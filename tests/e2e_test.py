#!/usr/bin/env python3
"""End-to-end verification for the svc.test. zone publisher.

Covers:
  0. store-level transaction atomicity (failed publish leaves no half version)
  1. cold start with empty DB (SERVFAIL), publish v1, real UDP DNS answers
  2. CNAME chain resolution, NXDOMAIN / REFUSED / NODATA behaviour
  3. whole-version rejection: dangling / cycle / external target / conflicts
  4. publish v2: new queries use the new version
  5. consistency: answers during concurrent publishes never mix versions
  6. write failure: old version keeps serving, DB untouched, recovery works
  7. PTR reverse lookup: single-name auto answer, shared-address choice,
     authoritative empty NOERROR, NXDOMAIN, TTL inheritance, stale-version
     rejection, choice invalidation on pair removal, re-selection needed
  8. restart: committed version (and PTR choices) is reloaded

Run with the project venv python:  /tmp/testvenv/bin/python tests/e2e_test.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import dnslib
import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.store import Store  # noqa: E402
from app.zone import ZoneError, parse_zone_text  # noqa: E402

WEB = "http://127.0.0.1:18000"
DNS_PORT = 15353
LOG = "/tmp/zonedns-e2e-server.log"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    line = f"[{mark}] {name}"
    if detail and not cond:
        line += f"  -- {detail}"
    print(line, flush=True)


def dns_query(name, qtype="A"):
    pkt = dnslib.DNSRecord.question(name, qtype).send("127.0.0.1", DNS_PORT, timeout=3)
    return dnslib.DNSRecord.parse(pkt)


def ptr_query(ip):
    """Real UDP PTR query for a 10.0.0.0/24 address."""
    last = ip.split(".")[3]
    return dns_query(f"{last}.0.0.10.in-addr.arpa.", "PTR")


def ptr_answers(resp):
    return sorted(
        (str(rr.rname), dnslib.QTYPE[rr.rtype], str(rr.rdata), rr.ttl)
        for rr in resp.rr
    )


def answers_of(resp):
    return sorted(
        (str(rr.rname), dnslib.QTYPE[rr.rtype], str(rr.rdata)) for rr in resp.rr
    )


def publish(text, note=""):
    return httpx.post(WEB + "/publish", data={"zone_text": text, "note": note}, timeout=10)


def wait_ready(proc, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"app exited early with {proc.returncode}; see {LOG}")
        try:
            if httpx.get(WEB + "/api/current", timeout=2).status_code == 200:
                dns_query("svc.test.", "A")  # UDP socket answers (any rcode)
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError("app did not become ready; see " + LOG)


def start_app(dbpath):
    env = dict(
        os.environ,
        ZONE_DB=dbpath,
        DNS_BIND="127.0.0.1",
        DNS_PORT=str(DNS_PORT),
        WEB_HOST="127.0.0.1",
        WEB_PORT="18000",
        REFRESH_INTERVAL="0.5",
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.main"],
        cwd=ROOT,
        env=env,
        stdout=open(LOG, "ab"),
        stderr=subprocess.STDOUT,
    )
    wait_ready(proc)
    return proc


def stop_app(proc):
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


# ---------------------------------------------------------------- unit: store
def test_store_atomicity(tmp):
    db = os.path.join(tmp, "unit.db")
    store = Store(db)
    store.init()
    vid, _ = store.publish([("web.svc.test.", "A", "10.0.0.1", 60)], note="v1")
    check("unit: first publish becomes current", store.current_version_id() == vid)
    try:
        store.publish(
            [("x.svc.test.", "A", "10.0.0.2", 60), ("x.svc.test.", "A", "10.0.0.2", 60)]
        )
        check("unit: duplicate rows violate UNIQUE -> publish raises", False)
    except Exception:
        check("unit: duplicate rows violate UNIQUE -> publish raises", True)
    check("unit: pointer unchanged after failed txn", store.current_version_id() == vid)
    check("unit: no orphan version row", store.load_version(vid + 1) is None)
    cur = store.load_current()
    check("unit: old records intact", len(cur["rows"]) == 1)


def test_ptr_choice_store(tmp):
    from app.store import PtrChoiceError, StaleVersionError  # noqa: PLC0415

    db = os.path.join(tmp, "ptr.db")
    store = Store(db)
    store.init()
    v1, _ = store.publish([
        ("web.svc.test.", "A", "10.0.0.10", 60),
        ("api.svc.test.", "A", "10.0.0.10", 90),
    ], note="v1")
    store.save_ptr_choice("10.0.0.10", "api.svc.test.", v1)
    check("unit: ptr choice stored", store.load_ptr_choices()
          == {"10.0.0.10": "api.svc.test."})
    try:
        store.save_ptr_choice("10.0.0.10", "web.svc.test.", v1 + 1)
        check("unit: stale version ptr save rejected", False)
    except StaleVersionError:
        check("unit: stale version ptr save rejected", True)
    try:
        store.save_ptr_choice("10.0.0.10", "ghost.svc.test.", v1)
        check("unit: ptr save without matching A pair rejected", False)
    except PtrChoiceError:
        check("unit: ptr save without matching A pair rejected", True)
    check("unit: failed ptr saves leave old choice",
          store.load_ptr_choices() == {"10.0.0.10": "api.svc.test."})
    # publish removes the (api, 10.0.0.10) pair: pruned in the same txn
    v2, _ = store.publish([("web.svc.test.", "A", "10.0.0.10", 60)], note="v2")
    check("unit: ptr choice pruned when its A pair is removed",
          store.load_ptr_choices() == {})
    # re-add the pair: nothing resurrects, a fresh save needs the new version
    v3, _ = store.publish([
        ("web.svc.test.", "A", "10.0.0.10", 60),
        ("api.svc.test.", "A", "10.0.0.10", 90),
    ], note="v3")
    check("unit: re-added pair does not resurrect old choice",
          store.load_ptr_choices() == {})
    store.save_ptr_choice("10.0.0.10", "web.svc.test.", v3)
    check("unit: re-selection on new version works",
          store.load_ptr_choices() == {"10.0.0.10": "web.svc.test."})


def test_validation():
    bad = {
        "dangling": "app CNAME missing\n",
        "cycle": "a CNAME b\nb CNAME a\n",
        "self cycle": "loop CNAME loop\n",
        "external target": "app CNAME www.example.com.\n",
        "A+CNAME conflict": "web A 10.0.0.1\napp A 10.0.0.2\napp CNAME web\n",
        "bad ipv4": "web A 999.1.1.1\n",
        "out-of-zone name": "evil.other.com. A 10.0.0.1\n",
        "dangling chain end": "a CNAME b\nb CNAME c\n",
    }
    for name, text in bad.items():
        try:
            parse_zone_text(text)
            check(f"unit: reject {name}", False, "parsed without error")
        except ZoneError:
            check(f"unit: reject {name}", True)
    ok = parse_zone_text("web A 10.0.0.1\napp CNAME web\n# comment\n\n")
    check("unit: valid zone parses", set(ok) == {"web.svc.test.", "app.svc.test."})


# ------------------------------------------------------------------ e2e flow
def main():
    tmp = tempfile.mkdtemp(prefix="zonedns-e2e-")
    db = os.path.join(tmp, "zone.db")
    open(LOG, "w").close()

    test_store_atomicity(tmp)
    test_ptr_choice_store(tmp)
    test_validation()

    proc = start_app(db)
    try:
        # 1. empty DB: nothing published yet
        r = httpx.get(WEB + "/api/current", timeout=5)
        check("e2e: empty DB -> no current version", r.json()["version"] is None)
        resp = dns_query("web.svc.test.", "A")
        check("e2e: empty DB -> SERVFAIL", dnslib.RCODE[resp.header.rcode] == "SERVFAIL")

        # 2. publish v1
        v1 = "web A 10.0.0.10 60\nweb A 10.0.0.11 60\napi CNAME web\napp CNAME api\ndb A 10.0.1.5 120\n"
        r = publish(v1, note="v1")
        check("e2e: publish v1 -> 303", r.status_code == 303, f"got {r.status_code}: {r.text[:200]}")
        cur = httpx.get(WEB + "/api/current", timeout=5).json()
        check("e2e: current is v1 with 5 records",
              cur["version"] == 1 and len(cur["records"]) == 5, str(cur)[:200])

        # 3. real DNS answers from v1
        resp = dns_query("app.svc.test.", "A")
        want = sorted([
            ("app.svc.test.", "CNAME", "api.svc.test."),
            ("api.svc.test.", "CNAME", "web.svc.test."),
            ("web.svc.test.", "A", "10.0.0.10"),
            ("web.svc.test.", "A", "10.0.0.11"),
        ])
        check("e2e: chain app->api->web + A addresses",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and answers_of(resp) == want,
              str(answers_of(resp)))
        check("e2e: authoritative bit set", resp.header.aa == 1)

        resp = dns_query("api.svc.test.", "CNAME")
        check("e2e: CNAME qtype returns the alias only",
              answers_of(resp) == [("api.svc.test.", "CNAME", "web.svc.test.")],
              str(answers_of(resp)))

        resp = dns_query("db.svc.test.", "CNAME")
        check("e2e: CNAME qtype on A-only name -> NODATA",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and not resp.rr)

        resp = dns_query("nope.svc.test.", "A")
        check("e2e: unknown name -> NXDOMAIN",
              dnslib.RCODE[resp.header.rcode] == "NXDOMAIN")

        resp = dns_query("other.com.", "A")
        check("e2e: out-of-zone -> REFUSED",
              dnslib.RCODE[resp.header.rcode] == "REFUSED")

        resp = dns_query("svc.test.", "A")
        check("e2e: zone apex -> NOERROR/NODATA",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and not resp.rr)

        r = httpx.get(WEB + "/query", params={"name": "app", "qtype": "A"}, timeout=5)
        check("e2e: web query page issues real query",
              r.status_code == 200 and "10.0.0.10" in r.text and "NOERROR" in r.text)

        # 4. invalid versions rejected wholesale; v1 keeps serving
        bad_zones = {
            "dangling": "app CNAME missing\nweb A 10.0.0.1\n",
            "cycle": "a CNAME b\nb CNAME a\n",
            "external": "app CNAME www.example.com.\n",
            "conflict": "web A 10.0.0.1\napp A 10.0.0.2\napp CNAME web\n",
        }
        for name, text in bad_zones.items():
            r = publish(text)
            check(f"e2e: invalid zone ({name}) -> 400", r.status_code == 400,
                  f"got {r.status_code}")
        cur = httpx.get(WEB + "/api/current", timeout=5).json()
        check("e2e: current still v1 after rejections", cur["version"] == 1)
        resp = dns_query("app.svc.test.", "A")
        check("e2e: DNS still serves v1 after rejections", answers_of(resp) == want)

        # 5. publish v2: new queries use the new version
        v2 = "web2 A 10.0.0.2 60\napp CNAME web2\n"
        r = publish(v2, note="v2")
        check("e2e: publish v2 -> 303", r.status_code == 303)
        resp = dns_query("app.svc.test.", "A")
        want2 = sorted([
            ("app.svc.test.", "CNAME", "web2.svc.test."),
            ("web2.svc.test.", "A", "10.0.0.2"),
        ])
        check("e2e: new queries use v2", answers_of(resp) == want2, str(answers_of(resp)))
        resp = dns_query("web.svc.test.", "A")
        check("e2e: names dropped in v2 -> NXDOMAIN",
              dnslib.RCODE[resp.header.rcode] == "NXDOMAIN")

        # 6. consistency: hammer queries while flipping between two versions
        zone_a = "app CNAME web1\nweb1 A 10.0.0.1 30\n"
        zone_b = "app CNAME web2\nweb2 A 10.0.0.2 30\n"
        consistent = {("web1.svc.test.", "10.0.0.1"), ("web2.svc.test.", "10.0.0.2")}
        errors, samples = [], [0]
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                try:
                    r2 = dns_query("app.svc.test.", "A")
                    rc = dnslib.RCODE[r2.header.rcode]
                    cn = [str(rr.rdata) for rr in r2.rr if dnslib.QTYPE[rr.rtype] == "CNAME"]
                    ip = [str(rr.rdata) for rr in r2.rr if dnslib.QTYPE[rr.rtype] == "A"]
                    samples[0] += 1
                    if rc != "NOERROR" or len(cn) != 1 or len(ip) != 1 \
                            or (cn[0], ip[0]) not in consistent:
                        errors.append((rc, cn, ip))
                except Exception as exc:  # noqa: BLE001
                    errors.append(("EXC", repr(exc)))

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for i in range(8):
            r = publish(zone_a if i % 2 == 0 else zone_b, note=f"flip{i}")
            if r.status_code != 303:
                errors.append(("publish", r.status_code))
            time.sleep(0.1)
        stop.set()
        for t in threads:
            t.join()
        check("e2e: answers during publishes never mix versions",
              not errors and samples[0] > 50,
              f"errors={errors[:3]} samples={samples[0]}")

        # 7. write failure: DB path replaced by a directory -> publish must fail
        versions_before = httpx.get(WEB + "/api/versions", timeout=5).json()
        current_before = httpx.get(WEB + "/api/current", timeout=5).json()
        os.rename(db, db + ".real")
        os.mkdir(db)  # sqlite can no longer open the database file
        try:
            r = publish(zone_a, note="must fail")
            check("e2e: write failure -> 500", r.status_code == 500,
                  f"got {r.status_code}: {r.text[:120]}")
            check("e2e: write failure page says old version stays",
                  "写入失败" in r.text)
            resp = dns_query("app.svc.test.", "A")
            cn = [str(rr.rdata) for rr in resp.rr if dnslib.QTYPE[rr.rtype] == "CNAME"]
            ip = [str(rr.rdata) for rr in resp.rr if dnslib.QTYPE[rr.rtype] == "A"]
            check("e2e: DNS keeps serving during write failure",
                  (cn[0], ip[0]) in consistent, f"{cn} {ip}")
        finally:
            os.rmdir(db)
            os.rename(db + ".real", db)
        time.sleep(1.2)  # let the refresh loop re-read the restored DB
        check("e2e: current version unchanged by failed write",
              httpx.get(WEB + "/api/current", timeout=5).json()["version"]
              == current_before["version"])
        check("e2e: no half-written version in DB",
              httpx.get(WEB + "/api/versions", timeout=5).json() == versions_before)
        r = publish(zone_b, note="recovered")
        check("e2e: publish works again after recovery", r.status_code == 303,
              f"got {r.status_code}")

        # 8. PTR reverse lookup for 10.0.0.0/24
        shared_zone = (
            "web A 10.0.0.10 60\n"
            "api A 10.0.0.10 120\n"
            "solo A 10.0.0.20 45\n"
        )
        r = publish(shared_zone, note="ptr base")
        check("e2e: publish PTR base version", r.status_code == 303)
        base_version = httpx.get(WEB + "/api/current", timeout=5).json()["version"]

        # reverse API lists owners with their A-record TTLs
        r = httpx.get(WEB + "/api/reverse", params={"ip": "10.0.0.10"}, timeout=5)
        data = r.json()
        check("e2e: reverse API lists two owners",
              r.status_code == 200 and data["shared"] is True
              and {o["name"] for o in data["owners"]}
              == {"web.svc.test.", "api.svc.test."}
              and data["chosen"] is None
              and data["reverse_name"] == "10.0.0.10.in-addr.arpa.", str(data))
        r = httpx.get(WEB + "/api/reverse", params={"ip": "10.0.0.20"}, timeout=5)
        check("e2e: reverse API marks single owner as not shared",
              r.json()["shared"] is False and len(r.json()["owners"]) == 1)
        r = httpx.get(WEB + "/api/reverse", params={"ip": "8.8.8.8"}, timeout=5)
        check("e2e: reverse API rejects address outside 10.0.0.0/24",
              r.status_code == 400)

        # single name pointing at an address: direct PTR, inherits A TTL
        resp = ptr_query("10.0.0.20")
        check("e2e: single owner -> direct PTR with A TTL",
              dnslib.RCODE[resp.header.rcode] == "NOERROR"
              and ptr_answers(resp)
              == [("20.0.0.10.in-addr.arpa.", "PTR", "solo.svc.test.", 45)]
              and resp.header.aa == 1, str(ptr_answers(resp)))

        # shared address with no choice: authoritative empty NOERROR
        resp = ptr_query("10.0.0.10")
        check("e2e: shared address, no choice -> empty NOERROR",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and not resp.rr
              and resp.header.aa == 1, str(dnslib.RCODE[resp.header.rcode]))

        # no A record for the address: NXDOMAIN
        resp = ptr_query("10.0.0.99")
        check("e2e: no A record -> NXDOMAIN",
              dnslib.RCODE[resp.header.rcode] == "NXDOMAIN" and not resp.rr)

        # reverse zone outside our /24 and forward names stay REFUSED/NXDOMAIN
        resp = dns_query("8.8.8.8.in-addr.arpa.", "PTR")
        check("e2e: other reverse zone -> REFUSED",
              dnslib.RCODE[resp.header.rcode] == "REFUSED")
        resp = dns_query("0.0.10.in-addr.arpa.", "PTR")
        check("e2e: reverse zone apex -> empty NOERROR",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and not resp.rr)

        # stale version save rejected (version field from an old render)
        r = httpx.post(WEB + "/ptr-choice",
                       data={"ip": "10.0.0.10", "name": "web.svc.test.",
                             "version": base_version - 1}, timeout=5)
        check("e2e: PTR choice on stale version -> 409 rejected",
              r.status_code == 409 and "过期" in r.text, f"got {r.status_code}")
        resp = ptr_query("10.0.0.10")
        check("e2e: rejected save keeps empty NOERROR answer",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and not resp.rr)

        # valid save against the current version: PTR now answered, TTL from
        # the chosen name's A record (api has TTL 120, web has 60)
        r = httpx.post(WEB + "/ptr-choice",
                       data={"ip": "10.0.0.10", "name": "api.svc.test.",
                             "version": base_version}, timeout=5,
                       follow_redirects=False)
        check("e2e: valid PTR choice save -> 303", r.status_code == 303)
        resp = ptr_query("10.0.0.10")
        check("e2e: chosen PTR answered with chosen name and its A TTL",
              ptr_answers(resp)
              == [("10.0.0.10.in-addr.arpa.", "PTR", "api.svc.test.", 120)],
              str(ptr_answers(resp)))
        r = httpx.get(WEB + "/api/reverse", params={"ip": "10.0.0.10"}, timeout=5)
        check("e2e: reverse API shows chosen owner",
              r.json()["chosen"] == "api.svc.test.")

        # web page can itself fire the real UDP PTR query (plain IP accepted)
        r = httpx.get(WEB + "/query", params={"name": "10.0.0.10", "qtype": "PTR"},
                      timeout=5)
        check("e2e: web /query issues real UDP PTR from a plain IP",
              r.status_code == 200 and "api.svc.test." in r.text
              and "PTR" in r.text and "NOERROR" in r.text)
        r = httpx.get(WEB + "/reverse", params={"ip": "10.0.0.10"}, timeout=5)
        check("e2e: reverse page lists both owners and current choice",
              r.status_code == 200 and "api.svc.test." in r.text
              and "web.svc.test." in r.text and "当前 PTR 归属" in r.text)

        # publish removing the chosen (api, 10.0.0.10) pair: choice invalidates
        # immediately; the address is now single-owned -> direct PTR to web
        one_left = "web A 10.0.0.10 60\nsolo A 10.0.0.20 45\n"
        r = publish(one_left, note="drop api pair")
        check("e2e: publish pruning version", r.status_code == 303)
        resp = ptr_query("10.0.0.10")
        check("e2e: removed pair invalidates choice; single owner answers",
              ptr_answers(resp)
              == [("10.0.0.10.in-addr.arpa.", "PTR", "web.svc.test.", 60)],
              str(ptr_answers(resp)))

        # re-add api pair so the address is shared again: no auto resurrection,
        # operator must choose anew -> empty NOERROR until they do
        r = publish(shared_zone, note="reshared")
        check("e2e: re-publish reshared version", r.status_code == 303)
        resp = ptr_query("10.0.0.10")
        check("e2e: re-added pair requires re-selection -> empty NOERROR",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and not resp.rr)
        new_version = httpx.get(WEB + "/api/current", timeout=5).json()["version"]
        r = httpx.post(WEB + "/ptr-choice",
                       data={"ip": "10.0.0.10", "name": "web.svc.test.",
                             "version": new_version}, timeout=5,
                       follow_redirects=False)
        check("e2e: re-selection after resharing accepted", r.status_code == 303)
        resp = ptr_query("10.0.0.10")
        check("e2e: re-selected PTR uses web and its TTL 60",
              ptr_answers(resp)
              == [("10.0.0.10.in-addr.arpa.", "PTR", "web.svc.test.", 60)],
              str(ptr_answers(resp)))

        # saving a choice while the DB cannot be written: 500, old answer kept
        versions_before = httpx.get(WEB + "/api/versions", timeout=5).json()
        os.rename(db, db + ".real")
        os.mkdir(db)
        try:
            r = httpx.post(WEB + "/ptr-choice",
                           data={"ip": "10.0.0.10", "name": "api.svc.test.",
                                 "version": new_version}, timeout=8)
            check("e2e: PTR choice write failure -> 500", r.status_code == 500,
                  f"got {r.status_code}")
            resp = ptr_query("10.0.0.10")
            check("e2e: write failure keeps old PTR answer",
                  ptr_answers(resp)
                  == [("10.0.0.10.in-addr.arpa.", "PTR", "web.svc.test.", 60)])
        finally:
            os.rmdir(db)
            os.rename(db + ".real", db)
        time.sleep(1.2)  # refresh loop re-reads the restored DB
        check("e2e: failed PTR choice leaves DB unchanged",
              httpx.get(WEB + "/api/versions", timeout=5).json() == versions_before)
        resp = ptr_query("10.0.0.10")
        check("e2e: PTR answer still the committed one after recovery",
              ptr_answers(resp)
              == [("10.0.0.10.in-addr.arpa.", "PTR", "web.svc.test.", 60)])

        # 9. restart: committed version is reloaded; nothing partial appears
        last = httpx.get(WEB + "/api/current", timeout=5).json()
        n_versions = len(httpx.get(WEB + "/api/versions", timeout=5).json())
    finally:
        stop_app(proc)

    proc = start_app(db)  # same DB file
    try:
        cur = httpx.get(WEB + "/api/current", timeout=5).json()
        check("e2e: restart reloads last committed version",
              cur["version"] == last["version"], f"{cur['version']} != {last['version']}")
        # final published zone is shared_zone: web + api both at 10.0.0.10
        resp = dns_query("web.svc.test.", "A")
        ip = sorted(str(rr.rdata) for rr in resp.rr if dnslib.QTYPE[rr.rtype] == "A")
        check("e2e: restart serves reloaded version", ip == ["10.0.0.10"], str(ip))
        check("e2e: restart leaves no partial versions",
              len(httpx.get(WEB + "/api/versions", timeout=5).json()) == n_versions)
        r = httpx.get(WEB + "/", timeout=5)
        check("e2e: UI renders after restart", r.status_code == 200 and "当前版本" in r.text)
        resp = ptr_query("10.0.0.10")
        check("e2e: PTR choice survives restart (rebuilt from committed state)",
              ptr_answers(resp)
              == [("10.0.0.10.in-addr.arpa.", "PTR", "web.svc.test.", 60)],
              str(ptr_answers(resp)))
        resp = ptr_query("10.0.0.20")
        check("e2e: single-owner PTR still works after restart",
              ptr_answers(resp)
              == [("20.0.0.10.in-addr.arpa.", "PTR", "solo.svc.test.", 45)])
        resp = ptr_query("10.0.0.99")
        check("e2e: NXDOMAIN still returned after restart",
              dnslib.RCODE[resp.header.rcode] == "NXDOMAIN")
    finally:
        stop_app(proc)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed checks:")
        for name in FAIL:
            print("  -", name)
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
