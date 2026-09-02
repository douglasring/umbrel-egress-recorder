"""Poll Firewalla MSP for security alarms and attribute them with the recorder.

Runtime shape, and why:

  - The MSP API has no webhook, so this polls. `ts:>{last_seen}` makes that safe:
    each poll asks only for alarms newer than the last one processed, so an alarm
    cannot be missed by mistiming a poll. Polling is also outbound-only, so nothing
    on the node is reachable from the internet.
  - The recorder's database is opened READ-ONLY through a shared volume. There is no
    Docker socket, no local API and no listener between the two containers, so the
    recorder's security properties are unaffected by this process existing.
  - Only the redacted report is ever sent off the node, and only when analysis is
    explicitly enabled.
"""

import io
import json
import os
import signal
import sqlite3
import sys
import time
import contextlib

from recorder.store import Store
from recorder import cli

from . import analyze, notify
from .msp import Msp, MspError, extract

STATE_PATH = os.environ.get("STATE_PATH", "/state/agent.json")
DB_PATH = os.environ.get("DB_PATH", "/data/egress.db")


def log(msg):
    sys.stdout.write("%s %s\n" % (
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg))
    sys.stdout.flush()


CONFIG_FILE = os.environ.get("CONFIG_FILE", "/state/agent.env")


def cfg():
    """Environment, with /state/agent.env filling any gaps.

    Compose variable substitution is not always reliable in Portainer - with a
    Git-backed stack the .env it writes may not sit beside the compose file, and the
    values silently resolve to empty. Reading a file on the agent's own writable
    volume removes that dependency entirely, and keeps credentials out of the public
    repository. Real environment variables still win when they carry a value.
    """
    conf = dict(os.environ)
    try:
        with open(CONFIG_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip().strip('"').strip("'")
                if val and not (conf.get(key) or "").strip():
                    conf[key] = val
    except OSError:
        pass
    return conf


def load_state():
    try:
        with open(STATE_PATH) as fh:
            s = json.load(fh)
            s.setdefault("seen", [])
            return s
    except (OSError, ValueError):
        return {"last_ts": 0.0, "seen": []}


def save_state(state):
    # Keep the seen-list bounded; last_ts does the real work and this only guards
    # against re-notifying on the boundary timestamp.
    state["seen"] = state.get("seen", [])[-500:]
    tmp = STATE_PATH + ".tmp"
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(tmp, "w") as fh:
            json.dump(state, fh)
        os.replace(tmp, STATE_PATH)
    except OSError as exc:
        log("WARN cannot persist state to %s: %s" % (STATE_PATH, exc))


def open_recorder_readonly():
    """Read-only handle on the recorder's database.

    Opened via a file: URI with mode=ro so this process cannot modify the evidence
    it is reading, even if something here is wrong.
    """
    store = Store.__new__(Store)
    store.path = DB_PATH
    store.history_seconds = int(os.environ.get("HISTORY_MINUTES", "1440")) * 60
    store.max_db_bytes = 0
    store.session_id = None
    store.degraded_since = None
    store.last_write_error = None
    uri = "file:%s?mode=ro" % DB_PATH
    store.db = sqlite3.connect(uri, uri=True, timeout=10.0, check_same_thread=False)
    import threading
    store._lock = threading.Lock()
    return store


def report_for(store, ip, port):
    """The shareable report text, captured from the recorder's own formatter."""
    buf = io.StringIO()
    args = [ip] + ([str(port)] if port else [])
    with contextlib.redirect_stdout(buf):
        cli.cmd_report(store, args)
    return buf.getvalue()


def handle(alarm, store, conf):
    info = extract(alarm)
    if info is None:
        return False

    ports = info["remote_ports"] or [None]
    reports, matched = [], False
    for port in ports:
        text = report_for(store, info["remote_ip"], port)
        if "NO MATCH" not in text:
            matched = True
        reports.append(text)

    if conf.get("ONLY_WITH_MATCH", "").lower() in ("1", "true", "yes") and not matched:
        log("alarm aid=%s %s: no recorder match, suppressed by ONLY_WITH_MATCH"
            % (info["aid"], info["remote_ip"]))
        return False

    header = [
        "FIREWALLA ALARM  %s" % info["type_name"],
        info["message"],
        "",
        "endpoint  : %s%s" % (info["remote_ip"],
                              (" ports " + ",".join(str(p) for p in info["remote_ports"]))
                              if info["remote_ports"] else ""),
    ]
    for key, field in (("domain", "remote_domain"), ("category", "remote_category"),
                       ("region", "remote_region"), ("protocol", "protocol"),
                       ("direction", "direction")):
        if info.get(field):
            header.append("%-10s: %s" % (key, info[field]))
    header.append("alarm     : aid=%s gid=%s" % (info["aid"], info["gid"]))
    header.append("")

    body = "\n".join(header) + "\n\n".join(reports)

    analysis = analyze.analyse(conf, body)
    if analysis:
        body += "\n\nANALYSIS\n" + analysis

    title = "%s: %s" % (info["type_name"], info["remote_ip"])
    try:
        status = notify.send(conf, title, body)
    except Exception as exc:
        status = "notification FAILED: %s" % exc
    log("alarm aid=%s %s matched=%s -> %s"
        % (info["aid"], info["remote_ip"], matched, status))
    return True


def main():
    # Wait for configuration rather than exiting. Exiting made the container
    # crash-loop, which meant no console - and the console is where the operator can
    # write /state/agent.env when compose substitution is not delivering the values.
    while True:
        conf = cfg()
        domain, token = conf.get("MSP_DOMAIN"), conf.get("MSP_TOKEN")
        if (domain or "").strip() and (token or "").strip():
            break
        log("WAITING: missing configuration")
        for name in ("MSP_DOMAIN", "MSP_TOKEN"):
            val = conf.get(name)
            if val is None:
                state = "NOT SET (never reached the container)"
            elif not val.strip():
                state = "SET BUT EMPTY (compose substituted nothing)"
            elif name == "MSP_TOKEN":
                state = "ok (%d chars)" % len(val)
            else:
                state = "ok (%r)" % val
            log("  %-11s : %s" % (name, state))
        log("  Fix either way:")
        log("    A) Portainer -> Stacks -> Environment variables -> Update the stack")
        log("    B) this container's Console (/bin/sh), then:")
        log('       printf \'MSP_DOMAIN=your.msp.host\\nMSP_TOKEN=your-token\\n\' > %s'
            % CONFIG_FILE)
        log("  Re-checking every 30s; no restart needed once the file exists.")
        for _ in range(30):
            time.sleep(1)

    interval = int(conf.get("POLL_SECONDS", "60"))
    types = tuple(int(t) for t in (conf.get("ALARM_TYPES", "1")).split(",") if t.strip())

    msp = Msp(domain, token)
    state = load_state()
    stopping = {"now": False}
    signal.signal(signal.SIGTERM, lambda *_: stopping.__setitem__("now", True))
    signal.signal(signal.SIGINT, lambda *_: stopping.__setitem__("now", True))

    log("agent started: domain=%s types=%s interval=%ds notify=%s analysis=%s"
        % (domain, types, interval, conf.get("NOTIFY", "none"), conf.get("LLM", "none")))
    if state.get("last_ts"):
        log("resuming after ts=%s" % state["last_ts"])
    else:
        log("cold start: the API defaults to the last 30 days; existing alarms will "
            "be recorded as seen without notifying")

    cold_start = not state.get("last_ts")

    while not stopping["now"]:
        try:
            alarms = msp.new_security_alarms(state.get("last_ts") or None, types=types)
        except MspError as exc:
            log("poll failed: %s" % exc)
            alarms = None

        if alarms:
            try:
                store = open_recorder_readonly()
            except sqlite3.Error as exc:
                log("cannot read recorder db %s: %s" % (DB_PATH, exc))
                store = None

            seen = set(state.get("seen", []))
            for alarm in alarms:
                aid = alarm.get("aid")
                key = "%s:%s" % (alarm.get("gid"), aid)
                if key in seen:
                    continue
                seen.add(key)
                state["seen"] = list(seen)
                ts = float(alarm.get("ts") or 0)
                state["last_ts"] = max(state.get("last_ts") or 0.0, ts)
                if cold_start:
                    continue  # record position without alerting on history
                if store is not None:
                    try:
                        handle(alarm, store, conf)
                    except Exception as exc:
                        log("ERROR handling aid=%s: %s" % (aid, exc))

            if store is not None:
                store.db.close()
            save_state(state)
            if cold_start:
                log("cold start complete: %d existing alarm(s) marked seen" % len(alarms))

        cold_start = False

        for _ in range(interval):
            if stopping["now"]:
                break
            time.sleep(1)

    log("agent stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
