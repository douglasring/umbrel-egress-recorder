# Umbrel Egress Recorder

Unofficial, lightweight rolling network-metadata recorder for Umbrel nodes.

It is designed for a specific incident-response question:

> A firewall or security product says this Umbrel contacted a suspicious IP. What network source on the Umbrel was talking to it around that time?

The recorder runs continuously, keeps a rolling history of outbound TCP/UDP flow metadata, and lets you look backward by IP address and optional port after an alert arrives.

It is **not** a malware detector and it does not automatically block anything.

## Before you investigate: is it Tor?

Check this **first**, before treating a reputation alert as a compromise.

A firewall outside the Umbrel sees the connection that actually leaves the machine. If an Umbrel app uses Tor — many do, and several use it by default — that public connection is a Tor **relay** connection, not a connection to the application's ultimate destination.

This matters because it is the most likely explanation for a "malware" verdict on an Umbrel:

- Tor relays commonly run on inexpensive hosting providers whose address space carries poor IP reputation.
- Guards rotate, so a previously unseen hosting IP appearing in your egress is normal, not anomalous.
- Reputation feeds routinely flag relay addresses.

Check the flagged address against the Tor consensus your node **already has locally**:

```bash
./tools/check-tor-relay.sh 203.0.113.42
```

Use the local consensus rather than an online lookup service. Querying a third-party API tells that service which address you are investigating, which is exactly the information you are trying to keep private during an incident.

If the address is a relay, the recorder can usually still tell you which Umbrel source spoke to it — but that source will be the **Tor container**, not the application behind it. The recorder cannot decrypt Tor and cannot prove which higher-level destination caused a particular relay connection. This is intentional.

## Security model

The container is intentionally narrow:

- no Docker socket
- no host `/proc` mount
- no wallet or LND data mounts
- no exposed TCP/UDP service ports
- no packet payloads written to disk
- no application logs
- no process command lines
- no environment-variable collection
- no automatic remediation
- read-only root filesystem
- all Linux capabilities dropped except `NET_RAW`
- `no-new-privileges` enabled
- bounded local retention

The only persistent data is a small SQLite database containing timestamps, protocol, interface, direction, and source/destination IP and port.

### Residual risk — read this part

Two properties of this design are not mitigated by the list above, and you should accept them deliberately:

**`network_mode: host` is the larger grant, not `NET_RAW`.** Sharing the host network namespace gives the container full TCP/UDP reachability to everything bound to `127.0.0.1` on the Umbrel — bitcoind RPC, LND gRPC/REST, Electrs, the dashboard. That is a path to node control that exists even with every capability dropped, and it cannot be constrained by Docker network policy.

**`NET_RAW` in the host namespace is not passive.** It permits packet *injection*, not just observation: ARP/ND spoofing, RST injection, and DHCP/DNS spoofing against the whole LAN. "Passive capture" describes what this software does, not what the capability allows.

Because neither can be fenced off at runtime, the controls that actually matter are **image provenance and code minimality**. Pin the image by digest, keep the runtime image free of HTTP clients and package managers, and treat the recorder as security-sensitive software.

## How it works

The recorder uses `tcpdump` only as a packet source. It does not create PCAP files. A small Python process reads tcpdump's binary pcap stream on stdout and stores flow metadata.

The capture invocation matters as much as the parsing:

```sh
tcpdump -i any -w - -U -nn -p -s 128 -Z nobody \
  '(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)
   or (ip6 and tcp and ip6[53] & 0x12 == 0x02)
   or udp'
```

Every flag is load-bearing:

| Flag | Why |
| --- | --- |
| `-w -` | Emits raw pcap records. tcpdump's protocol dissectors — historically its most CVE-prone code, and the part that parses attacker-influenced bytes — are not run at all. |
| `-nn` | Disables reverse DNS and service-name translation. Without it, the node emits a PTR query **for the suspicious address you are investigating**, tipping off the operator and polluting the capture. |
| `-p` | Stays out of promiscuous mode, so the recorder does not capture other LAN devices' traffic. |
| `-s 128` | The default snapshot length is 262144 bytes. Without this, full payloads — including cleartext credentials on loopback — are copied into the recorder's address space. |
| `-Z nobody` | Debian/Ubuntu tcpdump is built `--with-user=tcpdump` and **always** drops privileges at startup. `droproot()` runs even when the target user is root, so the drop cannot be disabled with `-Z root` — it still calls `setgid`/`setuid` and fails with `EPERM` unless `CAP_SETUID` and `CAP_SETGID` are granted. Since those capabilities are required either way, drop to `nobody` and get real privilege separation for the same cost. See [Capabilities](#capabilities). |
| SYN-only filter | Restricting TCP capture to connection initiations makes payload bytes essentially unreachable and cuts volume by orders of magnitude. |

The IPv6 clause is not redundant. `tcp[tcpflags]` compiles to an IPv4-only BPF program — it branches on ethertype `0x800` with no `0x86dd` path — so without the explicit `ip6` term, every IPv6 SYN is silently missed.

**Trade-off:** SYN-only capture cannot see connections that were already established when the recorder started. Long-lived flows that predate a restart are invisible until they reconnect. `status` reports the current session start time so you can tell.

### Interface and direction

Capturing with `-i any` yields Linux "cooked v2" (`LINUX_SLL2`) headers, which carry the capture interface and the packet direction. Both are recorded, and both are load-bearing:

- The **interface** is what makes pre-NAT attribution work (see below). On a Docker host the same flow is observed on the veth, on the bridge, and on the uplink — three times. Without an interface column those rows are indistinguishable and the duplication silently inflates the database.
- The **direction** distinguishes a connection the node *made* from one it *received*. Without it, an inbound connection from a flagged host is recorded as though the node initiated it, which inverts the conclusion.

Older libpcap (1.9 and earlier) emits `LINUX_SLL` instead, which has a different header length and no interface index. The parser reads the link type from the pcap stream header and handles both, but pin the image digest so this cannot change under you.

### What is recorded

All non-loopback flows are recorded, with filtering applied at **query** time rather than capture time. Recording only "local to public" traffic would miss LAN-to-LAN lateral movement and inbound connections, and would discard the app-to-Tor leg that is often the only thing narrowing attribution below "tor".

Loopback is excluded in the kernel BPF filter, not in Python, so credential-bearing loopback payloads are never copied to userspace at all.

## Attributing an internal Docker address

This is the one thing the recorder provides that a network firewall cannot: the **pre-NAT** source.

The same flow is observed on the Docker bridge with the container's address, and on the uplink with the host's address, with the source port preserved:

```text
UTC                   IFACE            DIR  PROTO  SOURCE                DESTINATION
2026-09-01T20:33:14Z  br-a1b2c3d4e5f6  out  TCP    10.21.21.12:51514     203.0.113.42:34567
2026-09-01T20:33:14Z  eth0             out  TCP    192.168.1.50:51514    203.0.113.42:34567
```

The first row is the attribution. Seeing both a container-side private source and the host-side address is normal on a bridged/NATed Docker host.

Source-port preservation under `MASQUERADE` is usual but **not guaranteed** — the kernel rewrites the port on collision. Treat the correlation as strong evidence, not proof.

### Confirming the mapping with conntrack

Where the flow is still in the connection-tracking table, the mapping can be read authoritatively rather than inferred. Because `/proc/net` is per-network-namespace, a host-networked container reads the host's conntrack table through its own `/proc` — no host mount, no Docker socket, and no capabilities required:

```text
ipv4 2 tcp 6 13 TIME_WAIT
  src=10.21.21.12   dst=203.0.113.42  sport=51514 dport=34567   <- original (pre-NAT)
  src=203.0.113.42  dst=192.168.1.50  sport=34567 dport=51514   <- reply (post-NAT)
```

Limitations: it requires `nf_conntrack` to be loaded, polling misses very short flows, and refused connections (SYN answered with RST) never enter the table at all. It supplements packet capture; it does not replace it.

## Mapping an internal IP to a container

The recorder deliberately has no Docker API access. Run the included helper manually on the Umbrel host:

```bash
./tools/map-container-ip.sh 10.21.21.12
```

The helper requests only container names, images, and assigned IP addresses. It deliberately does not dump full container configuration — a bare `docker inspect` of an Umbrel app prints its environment, which for several apps includes the bitcoind RPC password.

**This answers a question about the present, not the past.** If an app was updated, restarted, or reinstalled between the observation and your investigation, the address may now belong to a different app — or to nothing — and you will get a confident, wrong answer with no warning.

To make historical lookups trustworthy, install the ledger timer, which appends a timestamped IP-to-container record on the host:

```bash
sudo ./tools/install-ip-ledger.sh
```

The ledger is written outside the container and outside this repository. Never commit it.

## Portainer deployment

The intended deployment is a Portainer stack on the Umbrel host.

Use [`compose.yml`](./compose.yml). It does **not** expose a web interface.

Pin the image by digest. A mutable `:latest` tag, auto-pulled by a container holding `NET_RAW` in the host network namespace, is the highest-leverage compromise path in this design:

```text
ghcr.io/douglasring/umbrel-egress-recorder@sha256:<digest>
```

### Capabilities

The required set is `cap_drop: ALL` plus `cap_add: [NET_RAW, SETUID, SETGID]`.

`NET_RAW` is the floor for packet capture. `SETUID` and `SETGID` are **not optional**, which is easy to get wrong: Debian/Ubuntu tcpdump is built `--with-user=tcpdump` and always drops privileges at startup, and that drop needs both. It cannot be turned off — `droproot()` runs even when the target user is root, so `-Z root` still fails:

```text
tcpdump: Couldn't change to 'root' uid=0 gid=0: Operation not permitted
```

With `cap_add: [NET_RAW]` alone, tcpdump exits before capturing a single packet and the container simply stops. Because the two capabilities are required regardless, the recorder passes `-Z nobody` so tcpdump genuinely ends up unprivileged once the capture socket is open.

Two approaches that do **not** work, and are worth recording so they are not retried:

- Adding `user:` to run the container as non-root. Docker does not place `--cap-add` capabilities in the **ambient** set, so a non-root process gets `CapPrm=CapEff=0` and `AF_PACKET` fails with `EPERM`.
- Granting the binary file capabilities (`setcap cap_net_raw+ep`). `no-new-privileges` blocks capability elevation on `execve`, so the permitted set is zeroed. Keeping `no-new-privileges` is the right call; drop privileges after opening the socket instead.

## After a firewall alert

If the suspicious destination is `203.0.113.42`:

```bash
docker exec umbrel-egress-recorder lookup 203.0.113.42
```

If the firewall also reports destination port `34567`:

```bash
docker exec umbrel-egress-recorder lookup 203.0.113.42 34567
```

Example output:

```text
COVERAGE  continuous 2026-09-01T19:41:02Z .. 2026-09-01T20:41:03Z
          (59m58s of the requested 60m, 0 kernel drops, 0 gaps)

UTC                   IFACE            DIR  PROTO  SOURCE                DESTINATION
2026-09-01T20:33:14Z  br-a1b2c3d4e5f6  out  TCP    10.21.21.12:51514     203.0.113.42:34567
2026-09-01T20:33:14Z  eth0             out  TCP    192.168.1.50:51514    203.0.113.42:34567
```

All addresses in this README are examples. `203.0.113.0/24` is RFC 5737 documentation space and `10.21.21.12` is an illustrative address in Umbrel's default app network — neither refers to a real host.

### A negative result is only as good as the coverage

`lookup` always prints a coverage banner, including — especially — when it finds nothing. Without it, "no rows" is ambiguous across at least six causes, five of which mean *we do not know*:

- genuinely not observed
- the kernel dropped the packets under load
- the capture process died
- the recorder restarted
- the flow fell outside the retention window
- eviction reclaimed it early

An unqualified negative during an incident reads as exoneration, so the tool refuses to print one:

```text
NO MATCH for 203.0.113.42
COVERAGE  INCOMPLETE — 12m41s of the last 60m observed, 1 gap, 4,218 kernel drops
          Treat this as "unknown", not "did not happen".
```

Check recorder health with:

```bash
docker exec umbrel-egress-recorder status
```

`status` reports the current session, the oldest retained observation, kernel drop counters, and the container's current UTC time. Compare that last value against your firewall's clock before correlating: firewalls typically report local time, and a one-hour DST offset is enough to miss the window entirely.

Show recent egress observations:

```bash
docker exec umbrel-egress-recorder recent 5
```

## Storage and retention

Defaults:

- history: 1440 minutes (24 hours)
- database cap: 64 MB
- repeat-flow sampling: one row per flow, updated in place

Retention is 24 hours because the workflow this serves is a phone notification followed by human triage — realistically hours later, or after a weekend. A 60-minute window fails the exact scenario the tool exists for, and Firewalla's own on-box flow history is 24 hours, so a shorter window here retains less than the system that raised the alert.

This is affordable only because the store keeps **one row per flow**, not one row per sample. Each flow carries `first_seen`, `last_seen`, and an observation count, updated by upsert. At roughly 48 bytes per row, 24 hours of flow records on a home node is a few megabytes.

The size cap is enforced on **live bytes** — `(page_count - freelist_count) * page_size` — never on the file size. `DELETE` does not shrink a SQLite file; freed pages go on the freelist and are reused. A prune loop that waits for the file to shrink never sees it happen and deletes rows until the table is empty.

`auto_vacuum=INCREMENTAL` is set at database creation. It is silently ignored if set after any table exists, so it cannot be retrofitted to an existing database without a full `VACUUM`.

Session and coverage tables are **never evicted**. They are small, and they are what makes a negative result meaningful.

No captured packet payload is persisted.

## Schema

```sql
CREATE TABLE flow(                      -- one row per flow, not per sample
  session_id INTEGER NOT NULL,
  iface      TEXT    NOT NULL,          -- from SLL2; the pre-NAT row is the attribution
  dir        TEXT    NOT NULL,          -- 'out' | 'in' | '?'
  proto      INTEGER NOT NULL,
  src        TEXT    NOT NULL, sport INTEGER NOT NULL,
  dst        TEXT    NOT NULL, dport INTEGER NOT NULL,
  first_utc  INTEGER NOT NULL,
  last_utc   INTEGER NOT NULL,
  pkts       INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (iface, proto, src, sport, dst, dport)
) WITHOUT ROWID;

CREATE INDEX flow_dst ON flow(dst, dport, last_utc);
CREATE INDEX flow_age ON flow(last_utc);

CREATE TABLE session(                   -- never evicted: when were we actually recording?
  id            INTEGER PRIMARY KEY,
  started_utc   INTEGER NOT NULL,
  heartbeat_utc INTEGER,
  stopped_utc   INTEGER,
  stop_reason   TEXT,
  bpf           TEXT,
  cfg_json      TEXT);

CREATE TABLE capstat(                   -- never evicted: what did we miss?
  session_id INTEGER NOT NULL,
  utc        INTEGER NOT NULL,
  recv       INTEGER NOT NULL,
  dropped    INTEGER NOT NULL);
```

Kernel drop counters come from tcpdump itself: sending `SIGUSR1` to a running tcpdump prints capture statistics to stderr and the process continues. The recorder samples this periodically into `capstat`. This costs no additional privilege.

## What this can and cannot prove

A matching record can show that an IP/port tuple was observed leaving the Umbrel, and can often preserve the pre-NAT source address that helps with attribution.

It does **not** prove that a destination is malicious. Reputation systems produce false positives, hosting addresses serve many unrelated users, and Tor relay addresses are especially easy to misinterpret — see the first section.

Use the result as incident evidence, not as an automatic verdict.

## Handling captured data

The recorder stores metadata, but metadata about *this* node is not low-sensitivity. An hour of egress from an Umbrel can reveal Lightning channel peers, Bitcoin P2P peers, Tor guard and bridge addresses, VPN endpoints, and your LAN topology. Publishing Tor bridge addresses in particular causes real harm — bridge enumeration is an active threat.

Never paste `lookup`, `recent`, or `status` output into a public issue, and never commit the database. See [SECURITY.md](./SECURITY.md).

## Development

The recorder uses Python's standard library plus the `tcpdump` executable in the runtime image.

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

Build locally:

```bash
docker build -t umbrel-egress-recorder .
```

CI rejects any commit introducing an IP literal outside documentation ranges (RFC 5737, RFC 3849) and private space. See [`tools/check-no-real-ips.py`](./tools/check-no-real-ips.py).

See [SECURITY.md](./SECURITY.md) before reporting a security issue or sharing incident evidence.

## Status

Early-stage incident-response utility. Review and test it before relying on it as your only source of network evidence.

## License

MIT. See [LICENSE](./LICENSE).
