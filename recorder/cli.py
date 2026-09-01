"""Query commands: lookup, status, recent.

The governing rule here is that `lookup` must never print an unqualified negative.
"No rows" is ambiguous across at least six causes - genuinely not observed, kernel
drops, a dead capture process, a restart gap, retention expiry, and early eviction -
and five of those mean "we do not know". During an incident an unqualified empty
result reads as exoneration, so every result carries a coverage banner.
"""

import datetime
import ipaddress
import sys
import time

PROTO = {6: "TCP", 17: "UDP"}

WARNING = (
    "This output can identify Lightning/Bitcoin peers, Tor guards and bridges, VPN\n"
    "endpoints and your LAN layout. Do not paste it into a public issue. See SECURITY.md."
)


def _utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _dur(seconds):
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return ("%dh%02dm%02ds" % (h, m, s)) if h else ("%dm%02ds" % (m, s))


def _normalise(addr):
    """Accept any textual form of an address and return the canonical one.

    Without this, '::ffff:203.0.113.42' or an uncompressed IPv6 literal silently
    fails to match a stored row.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        sys.stderr.write("error: %r is not an IP address\n" % addr)
        raise SystemExit(2)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _banner(cov):
    lines = []
    if cov["degraded_since"]:
        lines.append(
            "DEGRADED  writes have been failing since %s: %s"
            % (_utc(cov["degraded_since"]), cov["last_write_error"])
        )
    if cov["complete"]:
        lines.append(
            "COVERAGE  continuous %s .. %s"
            % (_utc(cov["window_start_utc"]), _utc(cov["window_end_utc"]))
        )
        lines.append(
            "          (%s of the requested %s, 0 kernel drops, 0 gaps)"
            % (_dur(cov["covered_seconds"]), _dur(cov["requested_seconds"]))
        )
    else:
        lines.append(
            "COVERAGE  INCOMPLETE - %s of the last %s observed, %d gap(s), %s kernel drops"
            % (
                _dur(cov["covered_seconds"]),
                _dur(cov["requested_seconds"]),
                cov["gaps"],
                format(cov["kernel_drops"], ","),
            )
        )
        lines.append('          Treat a non-match as "unknown", not "did not happen".')
    return "\n".join(lines)


def _table(rows):
    out = [
        "%-22s %-16s %-5s %-5s %-24s %-24s %s"
        % ("FIRST SEEN (UTC)", "IFACE", "DIR", "PROTO", "SOURCE", "DESTINATION", "PKTS")
    ]
    for first, _last, iface, direction, proto, src, sport, dst, dport, pkts in rows:
        out.append(
            "%-22s %-16s %-5s %-5s %-24s %-24s %d"
            % (
                _utc(first),
                iface[:16],
                direction,
                PROTO.get(proto, str(proto)),
                "%s:%d" % (src, sport),
                "%s:%d" % (dst, dport),
                pkts,
            )
        )
    return "\n".join(out)


def cmd_lookup(store, args):
    if not args:
        sys.stderr.write("usage: lookup <ip> [port]\n")
        return 2
    target = _normalise(args[0])
    port = None
    if len(args) > 1:
        try:
            port = int(args[1])
        except ValueError:
            sys.stderr.write("error: %r is not a port\n" % args[1])
            return 2

    window = store.history_seconds
    cov = store.coverage(window)
    rows = store.lookup(target, port, since=int(time.time()) - window)

    if rows:
        print(_banner(cov))
        print()
        print(_table(rows))
        print()
        print(WARNING)
    else:
        print("NO MATCH for %s%s" % (target, (":%d" % port) if port else ""))
        print(_banner(cov))
    return 0


def cmd_recent(store, args):
    limit = 20
    if args:
        try:
            limit = max(1, int(args[0]))
        except ValueError:
            sys.stderr.write("error: %r is not a number\n" % args[0])
            return 2
    rows = store.recent(limit)
    if not rows:
        print("No flows recorded yet.")
        print(_banner(store.coverage(store.history_seconds)))
        return 0
    print(_table(rows))
    print()
    print(WARNING)
    return 0


def cmd_status(store, _args):
    cov = store.coverage(store.history_seconds)
    session = store.db.execute(
        "SELECT id, started_utc, heartbeat_utc, stopped_utc, stop_reason "
        "FROM session ORDER BY id DESC LIMIT 1"
    ).fetchone()
    count = store.db.execute("SELECT COUNT(*) FROM flow").fetchone()[0]
    stats = store.db.execute(
        "SELECT recv, dropped, utc FROM capstat ORDER BY utc DESC LIMIT 1"
    ).fetchone()

    print("umbrel-egress-recorder status")
    print("  container UTC now   : %s" % _utc(int(time.time())))
    print("    (compare against your firewall's clock - it likely reports LOCAL time)")
    if session:
        sid, started, beat, stopped, reason = session
        print("  session             : #%d started %s" % (sid, _utc(started)))
        print("  last heartbeat      : %s" % (_utc(beat) if beat else "never"))
        if stopped:
            print("  STOPPED             : %s - %s" % (_utc(stopped), reason))
    else:
        print("  session             : none recorded - capture has never started")
    print("  flows retained      : %s" % format(count, ","))
    print("  oldest observation  : %s" % (_utc(cov["oldest_row_utc"]) if cov["oldest_row_utc"] else "none"))
    print("  retention window    : %s" % _dur(store.history_seconds))
    print("  live bytes / cap    : %s / %s" % (format(store.live_bytes(), ","), format(store.max_db_bytes, ",")))
    if stats:
        recv, dropped, utc = stats
        print("  kernel drops        : %s dropped of %s received (as of %s)"
              % (format(dropped, ","), format(recv, ","), _utc(utc)))
    else:
        print("  kernel drops        : no capture statistics recorded yet")
    print()
    print(_banner(cov))
    return 0 if (session and not session[3] and not cov["degraded_since"]) else 1


COMMANDS = {"lookup": cmd_lookup, "recent": cmd_recent, "status": cmd_status}
