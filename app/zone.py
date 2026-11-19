"""Zone text parsing, whole-version validation, immutable snapshots, and
single-version resolution for the svc.test. authoritative zone."""

import ipaddress
import re
import threading

ZONE = "svc.test."
# Reverse zone for the operator-facing 10.0.0.0/24 network.
# Per RFC 1035 the address octets are reversed:
# 10.0.0.<d>  ->  <d>.0.0.10.in-addr.arpa.
REVERSE_NETWORK = ipaddress.IPv4Network("10.0.0.0/24")
REVERSE_ZONE = "0.0.10.in-addr.arpa."
DEFAULT_TTL = 60
MAX_TTL = 2_147_483_647

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


class ZoneError(Exception):
    """Raised when a candidate zone version fails validation.

    Carries the full list of human-readable problems; the whole version
    is rejected, nothing is published.
    """

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def fqdn(name):
    """Normalize an operator-supplied name to an in-zone FQDN.

    Accepts relative names ("web"), zone FQDNs ("web.svc.test."), and the
    zone apex. Rejects anything outside the zone.
    """
    n = (name or "").strip().lower().rstrip(".")
    if not n:
        raise ValueError("empty name")
    if n == ZONE[:-1]:
        return ZONE
    if n.endswith("." + ZONE[:-1]):
        candidate = n + "."
    elif "." in n:
        raise ValueError(f"name '{name}' is outside zone {ZONE}")
    else:
        candidate = n + "." + ZONE
    _check_name(candidate)
    return candidate


def _check_name(name):
    if len(name) > 253:
        raise ValueError(f"name too long: {name}")
    for label in name.rstrip(".").split("."):
        if not _LABEL_RE.match(label):
            raise ValueError(f"bad label '{label}' in {name}")


def parse_zone_text(text):
    """Parse and validate a full zone version.

    Line format:  <name> <A|CNAME> <value> [ttl]     (# starts a comment)

    Returns {name: {"A": [ip, ...], "CNAME": target|None, "ttl": int}}.
    Raises ZoneError listing every problem found; nothing is half-accepted.
    """
    records = {}
    errors = []

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            errors.append(f"line {lineno}: expected '<name> <A|CNAME> <value> [ttl]'")
            continue
        if len(parts) > 4:
            errors.append(f"line {lineno}: too many fields")
            continue
        name_s, rtype, value = parts[0], parts[1].upper(), parts[2]
        ttl = DEFAULT_TTL
        if len(parts) == 4:
            try:
                ttl = int(parts[3])
                if not (0 < ttl <= MAX_TTL):
                    raise ValueError
            except ValueError:
                errors.append(f"line {lineno}: bad ttl '{parts[3]}'")
                continue
        try:
            name = fqdn(name_s)
        except ValueError as exc:
            errors.append(f"line {lineno}: {exc}")
            continue
        rec = records.setdefault(name, {"A": [], "CNAME": None, "ttl": ttl})

        if rtype == "A":
            try:
                ip = str(ipaddress.IPv4Address(value))
            except ValueError:
                errors.append(f"line {lineno}: invalid IPv4 address '{value}'")
                continue
            if ip not in rec["A"]:
                rec["A"].append(ip)
        elif rtype == "CNAME":
            try:
                target = fqdn(value)
            except ValueError:
                errors.append(
                    f"line {lineno}: CNAME target '{value}' is not a name inside {ZONE}"
                )
                continue
            if rec["CNAME"] is not None:
                errors.append(f"line {lineno}: duplicate CNAME for {name}")
                continue
            rec["CNAME"] = target
        else:
            errors.append(f"line {lineno}: unsupported record type '{parts[1]}' (A/CNAME only)")

    errors.extend(validate_records(records))
    if errors:
        raise ZoneError(errors)
    return records


def validate_records(records):
    """Cross-record rules for one candidate version.

    - a name cannot hold both A and CNAME
    - every CNAME target must exist in this same version (no dangling)
    - CNAME chains must be acyclic and terminate at a name with A record(s)
    """
    errors = []
    for name in sorted(records):
        rec = records[name]
        if rec["A"] and rec["CNAME"]:
            errors.append(f"{name}: cannot have both A and CNAME records")

    for name in sorted(records):
        rec = records[name]
        if not rec["CNAME"]:
            continue
        seen = {name}
        node = rec["CNAME"]
        while True:
            target = records.get(node)
            if target is None:
                errors.append(
                    f"{name}: CNAME target {node} is not defined in this version (dangling)"
                )
                break
            if node in seen:
                errors.append(f"{name}: CNAME chain loops back to {node} (cycle)")
                break
            seen.add(node)
            if target["CNAME"]:
                node = target["CNAME"]
                continue
            if target["A"]:
                break  # chain ends at address records: OK
            break  # pragma: no cover - a stored record always has A or CNAME
    return errors


def flatten_records(records):
    """parsed-dict -> list of (name, rtype, value, ttl) rows for storage."""
    rows = []
    for name in sorted(records):
        rec = records[name]
        for ip in rec["A"]:
            rows.append((name, "A", ip, rec["ttl"]))
        if rec["CNAME"]:
            rows.append((name, "CNAME", rec["CNAME"], rec["ttl"]))
    return rows


class Snapshot:
    """Immutable view of one published version. A query resolves its whole
    alias chain against the single Snapshot instance captured at query start,
    so the chain and the final A address always come from the same version.

    ptr_choices is the committed PTR ownership map {ip: owner_name} at the
    moment this snapshot was built; it is frozen here as well, so a PTR
    answer's name and its inherited TTL always come from the same state."""

    __slots__ = ("version_id", "created_at", "records", "ptr_choices")

    def __init__(self, version_id, created_at, records, ptr_choices=None):
        self.version_id = version_id
        self.created_at = created_at
        # freeze: A lists become tuples, structure is never mutated afterwards
        self.records = {
            name: {"A": tuple(rec["A"]), "CNAME": rec["CNAME"], "ttl": rec["ttl"]}
            for name, rec in records.items()
        }
        self.ptr_choices = dict(ptr_choices or {})

    def zone_text(self):
        lines = []
        for name in sorted(self.records):
            rec = self.records[name]
            for ip in rec["A"]:
                lines.append(f"{name} A {ip} {rec['ttl']}")
            if rec["CNAME"]:
                lines.append(f"{name} CNAME {rec['CNAME']} {rec['ttl']}")
        return "\n".join(lines)

    def owners_for_ip(self, ip):
        """All names whose A record points at ip in this version.

        Returns a sorted list of (name, ttl) — the TTL a PTR answer for that
        name would inherit (it must equal the corresponding A record's TTL).
        """
        out = []
        for name, rec in self.records.items():
            if ip in rec["A"]:
                out.append((name, rec["ttl"]))
        return sorted(out)


def snapshot_from_rows(version_id, created_at, rows, ptr_choices=None):
    """Rebuild a Snapshot from stored rows (name, rtype, value, ttl)."""
    records = {}
    for name, rtype, value, ttl in rows:
        rec = records.setdefault(name, {"A": [], "CNAME": None, "ttl": ttl})
        if rtype == "A":
            rec["A"].append(value)
        else:
            rec["CNAME"] = value
    return Snapshot(version_id, created_at, records, ptr_choices)


def parse_reverse_ip(ip_text):
    """Validate an operator-entered address inside 10.0.0.0/24.

    Returns the canonical dotted-quad string, or raises ValueError.
    """
    try:
        ip = ipaddress.IPv4Address((ip_text or "").strip())
    except ValueError:
        raise ValueError(f"invalid IPv4 address '{ip_text}'")
    if ip not in REVERSE_NETWORK:
        raise ValueError(f"{ip} is outside the reverse lookup network {REVERSE_NETWORK}")
    return str(ip)


def ptr_name(ip):
    """10.0.0.<d> -> <d>.0.0.10.in-addr.arpa.

    The 10.0.0.0/24 reverse zone already contains the first three (reversed)
    octets, so only the host octet becomes an extra label."""
    return ip.split(".")[3] + "." + REVERSE_ZONE


def ip_from_ptr_name(qname):
    """Parse a qname inside REVERSE_ZONE back to its dotted-quad IP.

    Returns the IP string for '<d>.0.0.10.in-addr.arpa.' style names,
    None for the reverse-zone apex, and False for a malformed in-zone name.
    """
    qname = qname.lower()
    if qname == REVERSE_ZONE:
        return None
    if not qname.endswith("." + REVERSE_ZONE):
        raise ValueError("not in reverse zone")
    label = qname[: -len(REVERSE_ZONE) - 1]
    if "." in label:
        return False  # deeper labels inside the reverse zone are not ours
    if not label.isdigit() or not (0 <= int(label) <= 255):
        return False
    return f"10.0.0.{int(label)}"


class SnapshotHolder:
    """Atomically-swapped reference to the current Snapshot.

    Publishing swaps the reference only after the SQLite transaction has
    committed; in-flight queries keep using the snapshot they captured, so
    service never pauses and never mixes versions."""

    def __init__(self):
        self._lock = threading.Lock()
        self._snap = None

    def get(self):
        with self._lock:
            return self._snap

    def set(self, snap):
        with self._lock:
            self._snap = snap


def resolve(snapshot, qname, qtype):
    """Resolve qname/qtype against one snapshot.

    Returns (rcode, answers) where answers is a list of
    (name, rtype, value, ttl). qtype is a mnemonic: A, CNAME, ANY, PTR, ...
    Forward names are answered from svc.test.; names inside the
    10.0.0.in-addr.arpa. reverse zone are answered by resolve_reverse().
    """
    qname = qname.lower().rstrip(".") + "."
    if qname.endswith("." + REVERSE_ZONE) or qname == REVERSE_ZONE:
        return resolve_reverse(snapshot, qname, qtype)
    if qname != ZONE and not qname.endswith("." + ZONE):
        return "REFUSED", []

    answers = []
    node = qname
    seen = set()
    while True:
        rec = snapshot.records.get(node)
        if rec is None:
            if answers:
                # A validated version never dangles; degrade gracefully.
                return "NOERROR", answers
            if node == ZONE:
                return "NOERROR", []  # zone apex exists but holds no such data
            return "NXDOMAIN", []
        if rec["CNAME"]:
            if node in seen:  # corrupt data safeguard; validated zones never loop
                return "NOERROR", answers
            seen.add(node)
            answers.append((node, "CNAME", rec["CNAME"], rec["ttl"]))
            if qtype == "CNAME":
                return "NOERROR", answers
            node = rec["CNAME"]
            continue
        if rec["A"]:
            if qtype in ("A", "ANY"):
                answers.extend((node, "A", ip, rec["ttl"]) for ip in rec["A"])
            return "NOERROR", answers
        return "NOERROR", answers  # pragma: no cover


def resolve_reverse(snapshot, qname, qtype):
    """PTR resolution inside the 10.0.0.0/24 reverse zone, one snapshot only.

    - reverse-zone apex: authoritative empty NOERROR (the zone exists)
    - malformed in-zone name: NXDOMAIN
    - no A record points at the address anywhere in this version: NXDOMAIN
    - exactly one owner name: its PTR directly (single-name auto reverse)
    - several names share the address: answer only when a committed PTR
      ownership choice exists; otherwise an authoritative empty NOERROR
      (NODATA) until the operator picks an owner on the web page
    The PTR TTL is the TTL of the chosen name's A record at this same
    committed state, so name and TTL always come from one snapshot.
    """
    ip = ip_from_ptr_name(qname)
    if ip is None:
        return "NOERROR", []  # reverse zone apex: exists, no such data
    if ip is False:
        return "NXDOMAIN", []  # malformed name inside the reverse zone

    owners = snapshot.owners_for_ip(ip)
    if not owners:
        return "NXDOMAIN", []  # no A record points at this address
    if qtype not in ("PTR", "ANY"):
        return "NOERROR", []  # the name exists, just not with this qtype

    if len(owners) == 1:
        name, ttl = owners[0]  # single owner: reverse directly, no choice needed
    else:
        name = snapshot.ptr_choices.get(ip)
        if name is None:
            return "NOERROR", []  # shared address, operator has not chosen yet
        owner_map = dict(owners)
        if name not in owner_map:
            # Defensive: a committed choice must reference a live A pair;
            # publish-time pruning makes this unreachable in normal operation.
            return "NOERROR", []
        ttl = owner_map[name]
    return "NOERROR", [(qname, "PTR", name, ttl)]
