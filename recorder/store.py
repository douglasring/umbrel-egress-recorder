"""SQLite rolling store.

Three correctness rules this module exists to enforce:

1. Retention is capped on LIVE BYTES, never on file size. DELETE does not shrink a
   SQLite file - freed pages go on the freelist and are reused. A prune loop that
   waits for the file to shrink never sees it happen and deletes every row.
2. auto_vacuum=INCREMENTAL is set BEFORE any table exists. Set afterwards it is
   silently ignored (PRAGMA auto_vacuum returns 0).
3. session/capstat rows are never evicted. They are what makes a negative lookup
   result meaningful instead of merely empty.
"""

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS flow(
  session_id INTEGER NOT NULL,
  iface      TEXT    NOT NULL,
  dir        TEXT    NOT NULL,
  proto      INTEGER NOT NULL,
  src        TEXT    NOT NULL, sport INTEGER NOT NULL,
  dst        TEXT    NOT NULL, dport INTEGER NOT NULL,
  first_utc  INTEGER NOT NULL,
  last_utc   INTEGER NOT NULL,
  pkts       INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (iface, proto, src, sport, dst, dport)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS flow_dst ON flow(dst, dport, last_utc);
CREATE INDEX IF NOT EXISTS flow_age ON flow(last_utc);

CREATE TABLE IF NOT EXISTS session(
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  started_utc   INTEGER NOT NULL,
  heartbeat_utc INTEGER,
  stopped_utc   INTEGER,
  stop_reason   TEXT,
  bpf           TEXT,
  cfg_json      TEXT);

CREATE TABLE IF NOT EXISTS capstat(
  session_id INTEGER NOT NULL,
  utc        INTEGER NOT NULL,
  recv       INTEGER NOT NULL,
  dropped    INTEGER NOT NULL);

CREATE INDEX IF NOT EXISTS capstat_time ON capstat(utc);
"""


class Store:
    def __init__(self, path, history_minutes=1440, max_db_mb=64):
        self.path = path
        self.history_seconds = history_minutes * 60
        self.max_db_bytes = max_db_mb * 1024 * 1024
        self.session_id = None
        self.degraded_since = None
        self.last_write_error = None

        directory = os.path.dirname(os.path.abspath(path)) or "."
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            pass  # read-only rootfs; the check below reports it usefully

        fresh = not os.path.exists(path)
        # check_same_thread=False because the stderr/statistics reader thread writes
        # capstat rows; every write goes through self._lock.
        try:
            self.db = sqlite3.connect(
                path, timeout=10.0, isolation_level=None, check_same_thread=False
            )
        except sqlite3.OperationalError as exc:
            # "unable to open database file" says nothing about which of the several
            # possible causes applies. Name them, so a deployment problem is not
            # mistaken for a code problem.
            raise RuntimeError(
                "cannot open database %r: %s\n"
                "  directory   : %s\n"
                "  exists      : %s\n"
                "  is a dir    : %s\n"
                "  writable    : %s\n"
                "The container has a read-only root filesystem, so the directory holding "
                "the database must be a writable volume mounted at that path. Check the "
                "`volumes:` entry in compose.yml and that DB_PATH points inside it."
                % (
                    path,
                    exc,
                    directory,
                    os.path.exists(directory),
                    os.path.isdir(directory),
                    os.access(directory, os.W_OK),
                )
            ) from exc
        self._lock = threading.Lock()
        if fresh:
            # Must precede table creation or it is silently ignored.
            self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        # Bound the WAL, which is not counted by page_count.
        self.db.execute("PRAGMA wal_autocheckpoint=256")
        self.db.execute("PRAGMA temp_store=MEMORY")
        self.db.executescript(SCHEMA)

    # -- sessions -----------------------------------------------------------

    def start_session(self, bpf, cfg):
        cur = self.db.execute(
            "INSERT INTO session(started_utc, heartbeat_utc, bpf, cfg_json) "
            "VALUES(?,?,?,?)",
            (int(time.time()), int(time.time()), bpf, json.dumps(cfg, sort_keys=True)),
        )
        self.session_id = cur.lastrowid
        return self.session_id

    def heartbeat(self):
        with self._lock:
            self.db.execute(
                "UPDATE session SET heartbeat_utc=? WHERE id=?",
                (int(time.time()), self.session_id),
            )

    def stop_session(self, reason):
        if self.session_id is None:
            return
        with self._lock:
            self.db.execute(
                "UPDATE session SET stopped_utc=?, stop_reason=? WHERE id=?",
                (int(time.time()), reason, self.session_id),
            )

    def record_capstat(self, recv, dropped):
        with self._lock:
            self.db.execute(
                "INSERT INTO capstat(session_id, utc, recv, dropped) VALUES(?,?,?,?)",
                (self.session_id, int(time.time()), recv, dropped),
            )

    # -- flows --------------------------------------------------------------

    def upsert_batch(self, rows):
        """rows: iterable of (iface, dir, proto, src, sport, dst, dport, utc).

        One row per flow, updated in place - not one row per observation. This is
        what makes a 24h window affordable.
        """
        try:
            with self._lock:
                self._write_batch(rows)
            if self.degraded_since is not None:
                self.degraded_since = None
                self.last_write_error = None
        except sqlite3.Error as exc:
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            # A write failure is a STATE CHANGE, not a logged exception. On a full
            # disk, INSERT, DELETE and VACUUM all fail while SELECT keeps working -
            # so without this the recorder looks healthy while recording nothing.
            if self.degraded_since is None:
                self.degraded_since = int(time.time())
            self.last_write_error = str(exc)

    def _write_batch(self, rows):
            self.db.execute("BEGIN")
            self.db.executemany(
                "INSERT INTO flow(session_id, iface, dir, proto, src, sport, dst,"
                " dport, first_utc, last_utc, pkts) VALUES(?,?,?,?,?,?,?,?,?,?,1) "
                "ON CONFLICT(iface, proto, src, sport, dst, dport) DO UPDATE SET "
                "last_utc=excluded.last_utc, pkts=pkts+1, session_id=excluded.session_id",
                [
                    (self.session_id, i, d, p, s, sp, dt, dp, u, u)
                    for (i, d, p, s, sp, dt, dp, u) in rows
                ],
            )
            self.db.execute("COMMIT")

    # -- retention ----------------------------------------------------------

    def live_bytes(self):
        page_count = self.db.execute("PRAGMA page_count").fetchone()[0]
        freelist = self.db.execute("PRAGMA freelist_count").fetchone()[0]
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        return (page_count - freelist) * page_size

    def prune(self):
        """Age out, then size out. Returns True if size eviction fired."""
        evicted = False
        cutoff = int(time.time()) - self.history_seconds
        try:
          with self._lock:
            self.db.execute("DELETE FROM flow WHERE last_utc < ?", (cutoff,))
            # Size is measured on live bytes; the file itself will not shrink.
            guard = 0
            while self.live_bytes() > self.max_db_bytes and guard < 50:
                oldest = self.db.execute(
                    "SELECT last_utc FROM flow ORDER BY last_utc LIMIT 1 OFFSET ?",
                    (max(1, self._count() // 10),),
                ).fetchone()
                if oldest is None:
                    break
                self.db.execute("DELETE FROM flow WHERE last_utc <= ?", (oldest[0],))
                evicted = True
                guard += 1
            self.db.execute("PRAGMA incremental_vacuum(256)")
            if self.degraded_since is not None:
                self.degraded_since = None
                self.last_write_error = None
        except sqlite3.Error as exc:
            if self.degraded_since is None:
                self.degraded_since = int(time.time())
            self.last_write_error = str(exc)
        return evicted

    def _count(self):
        return self.db.execute("SELECT COUNT(*) FROM flow").fetchone()[0]

    # -- queries ------------------------------------------------------------

    def lookup(self, dst, dport=None, since=None):
        sql = "SELECT first_utc, last_utc, iface, dir, proto, src, sport, dst, dport," \
              " pkts FROM flow WHERE (dst = ? OR src = ?)"
        args = [dst, dst]
        if dport is not None:
            sql += " AND (dport = ? OR sport = ?)"
            args += [dport, dport]
        if since is not None:
            sql += " AND last_utc >= ?"
            args.append(since)
        sql += " ORDER BY first_utc"
        return self.db.execute(sql, args).fetchall()

    def recent(self, limit=20):
        return self.db.execute(
            "SELECT first_utc, last_utc, iface, dir, proto, src, sport, dst, dport,"
            " pkts FROM flow ORDER BY last_utc DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def coverage(self, window_seconds):
        """What do we actually know about the requested window?

        Returns a dict describing observed coverage, gaps and kernel drops, so that
        an empty lookup can be reported as "unknown" rather than "did not happen".
        """
        now = int(time.time())
        start = now - window_seconds
        sessions = self.db.execute(
            "SELECT started_utc, COALESCE(stopped_utc, heartbeat_utc, started_utc) "
            "FROM session WHERE COALESCE(stopped_utc, heartbeat_utc, started_utc) >= ? "
            "ORDER BY started_utc",
            (start,),
        ).fetchall()

        covered, gaps, cursor = 0, 0, start
        for s_start, s_end in sessions:
            s_start, s_end = max(s_start, start), min(s_end, now)
            if s_end <= s_start:
                continue
            if s_start > cursor + 2:
                gaps += 1
            covered += s_end - max(s_start, cursor)
            cursor = max(cursor, s_end)
        if cursor < now - 2:
            gaps += 1

        drops = self.db.execute(
            "SELECT COALESCE(SUM(d), 0) FROM ("
            "  SELECT MAX(dropped) - MIN(dropped) AS d FROM capstat"
            "  WHERE utc >= ? GROUP BY session_id)",
            (start,),
        ).fetchone()[0]

        oldest = self.db.execute("SELECT MIN(last_utc) FROM flow").fetchone()[0]
        return {
            "requested_seconds": window_seconds,
            "covered_seconds": max(0, covered),
            "gaps": gaps,
            "kernel_drops": drops or 0,
            "oldest_row_utc": oldest,
            "window_start_utc": start,
            "window_end_utc": now,
            "degraded_since": self.degraded_since,
            "last_write_error": self.last_write_error,
            "complete": gaps == 0 and covered >= window_seconds - 5 and not drops,
        }

    def close(self):
        try:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        self.db.close()
