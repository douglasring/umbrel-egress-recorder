# Security policy

## Reporting a vulnerability

Report security issues privately through GitHub's [private vulnerability
reporting](https://github.com/douglasring/umbrel-egress-recorder/security/advisories/new)
rather than in a public issue.

Please do not include captured data in a report. See below.

## Never attach captured data

The recorder stores network metadata, not payloads. That does not make it safe to publish.

An hour of egress metadata from an Umbrel node can reveal:

- **Lightning channel peer addresses** — deanonymising your node's peer graph
- **Bitcoin P2P peers**
- **Tor guard relays, and Tor bridge addresses.** Publishing bridge addresses causes
  real harm to people who depend on them; bridge enumeration is an active threat, not
  a theoretical one.
- **VPN, WireGuard, or Tailscale endpoints**
- **Your remote-access source addresses**
- **Your LAN topology** — subnets, host addresses, and which internal address maps to
  which application

Concretely, when filing any issue:

- Do **not** paste `lookup`, `recent`, or `status` output.
- Do **not** attach `egress.db`, a copy of the `/data` volume, or a container-IP ledger.
- Do **not** include real addresses from your own network or from a firewall alert.

Redact to RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 3849
(`2001:db8::/32`) documentation ranges before sharing anything. Private (RFC 1918)
addresses are usually safe to share, but the pairing of a specific internal address with
"this contacted a suspicious host" can still identify which app was implicated on your
node — prefer a generic example there too.

Maintainers will not ask you for a capture. If reproducing an issue genuinely requires
one, we will work out a synthetic reproduction instead.

## Repository hygiene

CI rejects commits that introduce an IP literal outside the documentation and private
ranges (`tools/check-no-real-ips.py`). This is a backstop, not a substitute for care —
it cannot detect a real address that happens to fall inside an allowed range, and it
cannot un-publish anything already pushed.

`.gitignore` excludes `*.db`, `*.sqlite*`, `*.pcap`, and ledger files. Do not override it.

**If a real address is committed, editing the file is not remediation.** The value
remains reachable through the commit object, through forks, and through GitHub's cache.
Rewriting history and force-pushing — or deleting and recreating the repository — is
the only actual remedy, and it must happen before the value is treated as removed.

## Threat model for the recorder itself

The recorder runs with `network_mode: host` and `CAP_NET_RAW`. Two consequences are
inherent to the design and are not bugs:

1. **Host networking** gives the container reachability to every service bound to
   `127.0.0.1` on the Umbrel, including bitcoind RPC and LND. This holds even with all
   capabilities dropped.
2. **`CAP_NET_RAW` in the host network namespace permits packet injection**, not only
   observation — ARP/ND spoofing, RST injection, DHCP and DNS spoofing against the LAN.

Neither can be constrained by Docker network policy once host networking is in use.
The controls that actually reduce risk are therefore supply-chain controls:

- Pin the image by **digest**, never by the `:latest` tag.
- Pin the base image by digest in the `Dockerfile`.
- Verify build provenance attestations before deploying a new digest.
- Keep the runtime image free of HTTP clients (`curl`, `wget`) and package managers.

Treat this container as security-sensitive software on your node, and review any change
to it with that in mind.

## Scope

In scope: privilege escalation out of the container, capture of data the design says it
does not capture (payloads, environment variables, process arguments, application logs),
unbounded resource growth, and any path by which the recorder's own data could be
exfiltrated or exposed.

Out of scope: the fact that a reputation alert can be a false positive, and the fact that
Tor egress cannot be attributed past the Tor container. Both are documented, intended
limitations — see the README.
