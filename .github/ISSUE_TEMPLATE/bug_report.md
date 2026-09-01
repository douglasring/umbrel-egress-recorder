---
name: Bug report
about: Report a problem with the recorder
---

<!--
DO NOT ATTACH CAPTURED DATA.

Never paste `lookup`, `recent` or `status` output, and never attach egress.db or a
copy of the /data volume. That data can identify your Lightning channel peers, your
Bitcoin peers, Tor guard and bridge addresses, VPN endpoints and your LAN layout.

Redact to RFC 5737 documentation addresses (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) before sharing anything. See SECURITY.md.
-->

**What happened**

**What you expected**

**How to reproduce**

**Environment**
- Umbrel version:
- Host architecture (arm64 / x86_64):
- Recorder image digest (`docker inspect --format='{{.Image}}' umbrel-egress-recorder`):
- Output of `docker exec umbrel-egress-recorder status` **with all addresses redacted**:
