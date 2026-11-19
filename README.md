# svc.test. 区域发布系统

面向运维的内网 `svc.test.` 区域发布平台：FastAPI 操作网页 + dnslib UDP 权威 DNS + SQLite 版本存储。
网页整版提交 A/CNAME 记录、查看当前版本、发起真实 UDP 查询；发布原子生效，查询永不被发布打断。

## 快速开始

```bash
docker compose up --build
# 网页:  http://localhost:8000
# DNS:   dig @127.0.0.1 -p 5353 app.svc.test. A
# PTR:   dig @127.0.0.1 -p 5353 10.0.0.10.in-addr.arpa. PTR
```

单容器同时运行网页（8000/tcp）与权威 DNS（5353/udp），SQLite 落在命名卷 `zone-data` 里，重启不丢版本。

本地直跑（Python 3.11+）：

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
ZONE_DB=data/zone.db DNS_BIND=127.0.0.1 DNS_PORT=5353 WEB_PORT=8000 .venv/bin/python -m app.main
```

## 区域文本格式

每行一条记录，`#` 起为注释，名称可写相对名或 FQDN：

```
web A 10.0.0.10 60
web A 10.0.0.11 60        # 同名多 A 轮询
api CNAME web             # 别名只能指向本区域已定义的名称
app CNAME api             # 允许多级链，必须终结于 A 记录
```

每次提交即一个**完整新版本**（不是增量）。规则：

- CNAME 目标必须是本版本内已定义的 `svc.test.` 区域内名称；悬空、循环（含自环）、指向区域外，整版拒绝；
- 同一名称不能同时有 A 与 CNAME；A 值必须是合法 IPv4；
- 校验或写入任一失败，整版不生效，当前版本继续服务。

## 一致性与原子性设计

- **整版原子发布**：版本行 + 全部记录行 + `current_version` 指针在同一个 SQLite 事务
  （`BEGIN IMMEDIATE … COMMIT`）中落库；任何写入失败整体回滚，库中不会留下半版，
  重启后按指针恢复的只会是完整版本。
- **发布期间照常解析**：DNS 线程只读内存中的不可变 `Snapshot`；发布提交成功后一次性
  原子换引用，查询不等待、不阻塞。
- **单次查询同一版本**：每个查询在开始时捕获一次快照引用，整条 CNAME 链与最终 A
  地址都来自这同一个版本，绝不跨版本拼接。
- **重启恢复**：启动时从 SQLite 读取 `current_version` 指向的版本重建快照；另有每
  2 秒（`REFRESH_INTERVAL`）的对账线程兜底，DB 指针与内存快照不一致时以库为准。

## PTR 反查（10.0.0.0/24）

值班员只拿到连接日志里的 IP 时，可在网页输入 `10.0.0.0/24` 内的地址，查看当前已提交
版本里哪些名称的 A 记录指向它，并对本机权威 DNS 发起**真实 UDP PTR 查询**
（反向区域 `0.0.10.in-addr.arpa.`，如 `10.0.0.10 → 10.0.0.10.in-addr.arpa.`）。应答规则：

| 场景 | 应答 |
| --- | --- |
| 只有一个名称的 A 记录指向该地址 | 直接 `NOERROR` 返回该名称的 PTR，无需人工选择 |
| 多个名称共用该地址、未选归属 | `NOERROR` 权威空答复（NODATA，AA=1，无 answer） |
| 多个名称共用、已在网页选定归属 | `NOERROR` 返回所选名称的 PTR |
| 当前版本没有任何 A 记录指向该地址 | `NXDOMAIN` |
| 反向区域之外（如 `8.8.8.8.in-addr.arpa.`） | `REFUSED` |

- **TTL 继承**：PTR 的 TTL 取所选名称对应 A 记录的 TTL；名称与 TTL 来自查询开始时捕获的
  同一个已提交快照，绝不跨版本拼接。
- **选择立即失效、重新共享需重选**：PTR 归属以 `(名称, IP)` A 记录配对为前提。正向发布
  在**同一个事务**里删除已失去配对的选择行——配对一旦移除，原选择立即失效；日后该配对
  重新加回且地址再次被多个名称共用时，库里没有任何残留可恢复，必须重新选择。
- **过期版本拒绝保存**：网页表单带渲染时的版本号；提交时若区域已发布新版本，保存被拒绝
  （HTTP 409），原应答保持不变。写入失败（如磁盘错误，HTTP 500）同样保留原应答。
- 重启后从 SQLite 重建快照与 PTR 归属，按已提交状态继续反查。

## 网页与 API

| 入口 | 说明 |
| --- | --- |
| `GET /` | 当前版本记录、发布表单（预填当前版）、查询表单、地址反查表单、版本历史 |
| `POST /publish` | 表单 `zone_text` + `note`；校验失败 400、写入失败 500、成功 303 |
| `GET /query?name=&qtype=` | 网页发起真实 UDP 查询（A/CNAME/PTR/ANY；PTR 时 `name` 可直接填 `10.0.0.10`） |
| `GET /reverse?ip=10.0.0.10` | 列出指向该地址的全部名称与 TTL、当前 PTR 归属；共用地址时在此选择归属 |
| `POST /ptr-choice` | 表单 `ip` + `name` + `version`；过期版本/无效选择 409、写入失败 500、成功 303 |
| `GET /api/current` | 当前版本 JSON |
| `GET /api/reverse?ip=` | 反查 JSON：`owners`（名称+TTL）、`shared`、`chosen`、`reverse_name` |
| `GET /api/versions` | 版本历史 JSON |

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ZONE_DB` | `./data/zone.db`（镜像内 `/data/zone.db`） | SQLite 路径 |
| `DNS_BIND` / `DNS_PORT` | `0.0.0.0` / `5353` | UDP 权威 DNS 监听 |
| `WEB_HOST` / `WEB_PORT` | `0.0.0.0` / `8000` | 网页监听 |
| `DNS_QUERY_HOST` | `127.0.0.1` | 网页发起查询的目标地址 |
| `REFRESH_INTERVAL` | `2.0` | 内存快照与 DB 对账周期（秒） |

## 验证

```bash
.venv/bin/python tests/e2e_test.py
```

覆盖：事务原子性（唯一约束触发半途失败 → 无半版）、整版校验拒绝（悬空/循环/外部目标/
类型冲突/非法地址/区域外名称）、链式解析与 NXDOMAIN/REFUSED/NODATA、发布期间并发查询的
单版本一致性、写入失败（DB 路径被替换为目录 → 500、旧版照常应答、恢复后可继续发布）、
PTR 反查（单名称直答、共用地址未选空答复/选定后应答、NXDOMAIN/REFUSED、TTL 继承、
过期版本拒绝、配对移除即失效、重新共享需重选、写入失败保留原应答）、
重启后版本、记录与 PTR 归属完整恢复。
