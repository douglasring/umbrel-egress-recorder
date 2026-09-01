"""Entry point: `python3 -m recorder <capture|lookup|status|recent|healthcheck>`."""

import os
import signal
import sys

from .cli import COMMANDS
from .store import Store

DB_PATH = os.environ.get("DB_PATH", "/data/egress.db")


def _store():
    return Store(
        DB_PATH,
        history_minutes=int(os.environ.get("HISTORY_MINUTES", "1440")),
        max_db_mb=int(os.environ.get("MAX_DB_MB", "64")),
    )


def _healthcheck(store):
    """Fail when capture has stopped, writes are failing, or rows are not advancing.

    The cgroup OOM killer can kill tcpdump while the container stays "running" and the
    parser waits forever on an empty pipe, so liveness must be asserted on progress,
    not on the presence of a PID.
    """
    import time

    row = store.db.execute(
        "SELECT heartbeat_utc, stopped_utc FROM session ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        print("unhealthy: capture has never started")
        return 1
    heartbeat, stopped = row
    if stopped:
        print("unhealthy: capture session stopped")
        return 1
    if store.degraded_since:
        print("unhealthy: writes failing - %s" % store.last_write_error)
        return 1
    age = int(time.time()) - (heartbeat or 0)
    if age > 300:
        print("unhealthy: no heartbeat for %ds" % age)
        return 1
    print("ok")
    return 0


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: recorder <capture|lookup|status|recent|healthcheck>\n")
        return 2
    command, args = argv[1], argv[2:]

    if command == "capture":
        from .capture import Recorder

        store = _store()
        rec = Recorder(store, capstat_interval=int(os.environ.get("CAPSTAT_INTERVAL_SECONDS", "10")))
        # Python as PID 1 ignores SIGTERM by default, so `docker stop` would hang for
        # the full grace period and then SIGKILL, losing buffered flow state.
        signal.signal(signal.SIGTERM, rec.shutdown)
        signal.signal(signal.SIGINT, rec.shutdown)
        try:
            return rec.run()
        finally:
            store.close()

    store = _store()
    try:
        if command == "healthcheck":
            return _healthcheck(store)
        handler = COMMANDS.get(command)
        if handler is None:
            sys.stderr.write("unknown command %r\n" % command)
            return 2
        return handler(store, args)
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
