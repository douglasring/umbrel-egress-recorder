#!/usr/bin/env python3
"""Fail if a tracked file contains an IP literal outside the allowed ranges.

Backstop against committing real addresses from an incident. See SECURITY.md.

Allowed:
  - RFC 5737 documentation   192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
  - RFC 3849 documentation   2001:db8::/32
  - RFC 1918 private         10/8, 172.16/12, 192.168/16
  - RFC 4193 unique-local    fc00::/7
  - loopback, link-local, multicast, unspecified, broadcast

This cannot detect a real address that happens to fall inside an allowed range,
and it cannot un-publish anything already pushed. It only stops the easy mistake.
"""

import ipaddress
import re
import subprocess
import sys

# Octet-boundary anchored so version strings like "1.10.4" and "4.99.4" do not match.
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
# Require at least two colons and a hex group, to avoid matching times/durations.
IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}(?::|[0-9A-Fa-f]{1,4})(?![\w:])")

DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".deb")
SKIP_PATHS = {"tools/check-no-real-ips.py"}  # this file names the allowed ranges


def allowed(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # not actually an address (e.g. "1.2.3.4.5" fragments)
    if any(ip in net for net in DOC_NETS):
        return True
    return bool(
        ip.is_private          # RFC 1918 / RFC 4193 / loopback / link-local
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [f for f in out.splitlines() if f]


def main() -> int:
    findings: list[tuple[str, int, str]] = []
    for path in tracked_files():
        if path in SKIP_PATHS or path.lower().endswith(SKIP_SUFFIXES):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for n, line in enumerate(lines, 1):
            for pattern in (IPV4, IPV6):
                for match in pattern.findall(line):
                    if not allowed(match):
                        findings.append((path, n, match))

    if not findings:
        print("check-no-real-ips: OK — no disallowed IP literals in tracked files")
        return 0

    print("check-no-real-ips: FAILED\n", file=sys.stderr)
    for path, n, addr in findings:
        print(f"  {path}:{n}: {addr}", file=sys.stderr)
    print(
        "\nUse RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or\n"
        "RFC 3849 (2001:db8::/32) documentation addresses instead.\n"
        "\nIf a real address was already committed, editing the file is NOT enough —\n"
        "see SECURITY.md, 'Repository hygiene'.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
