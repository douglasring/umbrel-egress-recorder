"""Capture supervisor: run tcpdump, parse its pcap stream, persist flow metadata."""

import os
import re
import signal
import subprocess
import sys
import threading
import time

from .pcap import PcapStream, PcapFormatError

# Loopback is excluded in the KERNEL, not in Python. On an Umbrel, loopback carries
# bitcoind RPC HTTP Basic auth and LND macaroons; filtering here means those bytes are
# never copied into this process at all, rather than being read and then discarded.
#
# The IPv6 clause is not redundant with tcp[tcpflags]: that primitive compiles to an
# IPv4-only BPF program (it branches on ethertype 0x800 with no 0x86dd path), so
# without it every IPv6 SYN is silently missed.
BPF = (
    "not host 127.0.0.1 and not host ::1 and ("
    "(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
    " or (ip6 and tcp and ip6[53] & 0x12 == 0x02)"
    " or udp)"
)

TCPDUMP = [
    "tcpdump",
    "-i", "any",
    "-w", "-",          # binary pcap: no protocol dissectors run
    "-U",               # unbuffered - evidence is not stuck in a block buffer
    "-nn",              # no reverse DNS (would query the address under investigation)
    "-p",               # no promiscuous mode - do not capture other LAN devices
    "-s", "128",        # default snaplen is 262144; keep payloads out of the pipe
    # Debian/Ubuntu tcpdump ALWAYS drops privileges (built --with-user=tcpdump), and
    # droproot() runs even when the target user is root, so "-Z root" does not disable
    # it - it still calls setgid/setuid and fails with EPERM unless CAP_SETUID and
    # CAP_SETGID are present. Since the caps are required either way, drop to an
    # unprivileged user and get real privilege separation for the same cost.
    "-Z", "nobody",
    BPF,
]

# "123 packets captured, 456 packets received by filter, 78 packets dropped by kernel"
_STATS = re.compile(
    r"(\d+)\s+packets?\s+received by filter.*?(\d+)\s+packets?\s+dropped by kernel",
    re.S,
)
# Any single line belonging to a statistics report, so it is not mistaken for an error.
_STATS_LINE = re.compile(
    r"packets? (captured|received by filter|dropped by kernel)|^\s*\d+\s+packets"
)


class InterfaceMap:
    """ifindex -> name, refreshed on miss so bridges created later are named.

    /sys/class/net is network-namespace scoped, so a host-networked container sees the
    host's interfaces through its own sysfs with no extra mounts.
    """

    def __init__(self):
        self._map = {}
        self.refresh()

    def refresh(self):
        table = {}
        try:
            for name in os.listdir("/sys/class/net"):
                try:
                    with open("/sys/class/net/%s/ifindex" % name) as fh:
                        table[int(fh.read().strip())] = name
                except (OSError, ValueError):
                    continue
        except OSError:
            return
        self._map = table

    def name(self, ifindex):
        if ifindex == 0:
            return "any"
        name = self._map.get(ifindex)
        if name is None:
            self.refresh()
            name = self._map.get(ifindex, "if%d" % ifindex)
        return name


class Recorder:
    def __init__(self, store, capstat_interval=10, flush_interval=2.0):
        self.store = store
        self.capstat_interval = capstat_interval
        self.flush_interval = flush_interval
        self.proc = None
        self.ifaces = InterfaceMap()
        self.stop = threading.Event()
        self.last_stderr = ""

    # -- tcpdump lifecycle ---------------------------------------------------

    def _spawn(self):
        self.proc = subprocess.Popen(
            TCPDUMP,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        # A larger pipe buffer reduces the chance that a parser stall becomes kernel
        # drops. F_SETPIPE_SZ = 1031; needs no capability up to /proc/sys/fs/pipe-max-size.
        try:
            import fcntl

            fcntl.fcntl(self.proc.stdout.fileno(), 1031, 1024 * 1024)
        except (OSError, ImportError):
            pass
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        threading.Thread(target=self._poll_stats, daemon=True).start()

    def _drain_stderr(self):
        """Consume stderr and harvest SIGUSR1 statistics.

        tcpdump prints capture statistics on SIGUSR1 and CONTINUES RUNNING, which is
        how kernel drop counters are obtained without extra privilege.
        """
        buf = ""
        stream = self.proc.stderr
        while not self.stop.is_set():
            chunk = stream.readline()
            if not chunk:
                return
            text = chunk.decode("utf-8", "replace")
            stripped = text.strip()
            # SIGUSR1 statistics are routine output, not a diagnostic. Keeping them in
            # last_stderr would make every exit look like "0 packets captured".
            if stripped and not _STATS_LINE.search(stripped):
                self.last_stderr = stripped
            buf = (buf + text)[-4096:]
            match = _STATS.search(buf)
            if match:
                recv, dropped = int(match.group(1)), int(match.group(2))
                self.store.record_capstat(recv, dropped)
                buf = ""

    def _poll_stats(self):
        while not self.stop.wait(self.capstat_interval):
            proc = self.proc
            if proc and proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGUSR1)
                except OSError:
                    return

    # -- main loop -----------------------------------------------------------

    def run(self):
        cfg = {
            "history_seconds": self.store.history_seconds,
            "max_db_bytes": self.store.max_db_bytes,
            "argv": TCPDUMP,
        }
        self.store.start_session(BPF, cfg)
        self._spawn()

        try:
            stream = PcapStream(self.proc.stdout)
        except PcapFormatError as exc:
            # Most likely tcpdump failed to start. Its stderr says why - commonly the
            # privilege-drop failure caused by omitting CAP_SETUID/CAP_SETGID.
            self.store.stop_session("capture failed to start: %s" % exc)
            sys.stderr.write(
                "fatal: %s\ntcpdump said: %s\n" % (exc, self.last_stderr or "(nothing)")
            )
            return 1

        pending, last_flush, last_prune = [], time.time(), time.time()
        try:
            for flow in stream:
                iface = self.ifaces.name(flow.ifindex)
                pending.append(
                    (
                        iface,
                        flow.direction,
                        flow.proto,
                        flow.src,
                        flow.sport,
                        flow.dst,
                        flow.dport,
                        int(flow.utc),
                    )
                )
                now = time.time()
                if len(pending) >= 500 or now - last_flush >= self.flush_interval:
                    self.store.upsert_batch(pending)
                    pending.clear()
                    self.store.heartbeat()
                    last_flush = now
                if now - last_prune >= 60:
                    self.store.prune()
                    last_prune = now
                if self.stop.is_set():
                    break
        except (PcapFormatError, OSError) as exc:
            self.store.stop_session("capture error: %s" % exc)
            sys.stderr.write("capture error: %s\n" % exc)
            return 1
        finally:
            if pending:
                self.store.upsert_batch(pending)
            self.stop.set()

        reason = "tcpdump exited rc=%s: %s" % (self.proc.poll(), self.last_stderr)
        self.store.stop_session(reason)
        sys.stderr.write(reason + "\n")
        return 1  # capture ending is always abnormal; let the supervisor restart us

    def shutdown(self, *_args):
        self.stop.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
