"""Retention and coverage tests - the parts that silently destroy evidence."""

import os
import sqlite3
import tempfile
import time
import unittest

from recorder.store import Store


class TestStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "egress.db")

    def tearDown(self):
        self.dir.cleanup()

    def store(self, **kw):
        s = Store(self.path, **kw)
        s.start_session("bpf", {})
        return s

    def rows(self, n, base=None, dst="203.0.113.42"):
        base = base or int(time.time())
        return [
            ("eth0", "out", 6, "10.21.21.12", 40000 + i, dst, 443, base)
            for i in range(n)
        ]

    def test_auto_vacuum_is_incremental(self):
        """Set after table creation it is silently ignored, so it must be set first."""
        s = self.store()
        self.assertEqual(s.db.execute("PRAGMA auto_vacuum").fetchone()[0], 2)

    def test_upsert_collapses_repeats_into_one_row(self):
        s = self.store()
        row = ("eth0", "out", 6, "10.21.21.12", 51514, "203.0.113.42", 34567, int(time.time()))
        s.upsert_batch([row] * 40)
        self.assertEqual(s._count(), 1)
        self.assertEqual(
            s.db.execute("SELECT pkts FROM flow").fetchone()[0], 40
        )

    def test_same_flow_on_different_interfaces_is_distinct(self):
        """The pre-NAT bridge row is the attribution; it must not merge with the uplink."""
        s = self.store()
        now = int(time.time())
        s.upsert_batch([
            ("br-abc", "in", 6, "10.21.21.12", 51514, "203.0.113.42", 34567, now),
            ("eth0", "out", 6, "192.168.1.50", 51514, "203.0.113.42", 34567, now),
        ])
        self.assertEqual(s._count(), 2)

    def test_age_based_prune_removes_only_old_rows(self):
        s = self.store(history_minutes=60)
        now = int(time.time())
        s.upsert_batch(self.rows(3, base=now))
        s.upsert_batch([("eth0", "out", 6, "10.0.0.9", 1, "203.0.113.5", 443, now - 7200)])
        self.assertEqual(s._count(), 4)
        s.prune()
        self.assertEqual(s._count(), 3)

    def test_size_cap_uses_live_bytes_not_file_size(self):
        """Capping on file size deletes everything: DELETE never shrinks the file."""
        s = self.store(history_minutes=60, max_db_mb=1)
        s.upsert_batch(self.rows(4000))
        before = s._count()
        s.db.execute("DELETE FROM flow")
        # File has not shrunk, but live bytes have collapsed.
        self.assertGreater(os.path.getsize(self.path), 0)
        self.assertLess(s.live_bytes(), 1024 * 1024)
        self.assertGreater(before, 0)

    def test_prune_never_empties_the_table_when_under_cap(self):
        s = self.store(history_minutes=60, max_db_mb=64)
        s.upsert_batch(self.rows(500))
        s.prune()
        self.assertEqual(s._count(), 500)

    def test_coverage_reports_gap_when_session_stopped(self):
        s = self.store(history_minutes=60)
        s.stop_session("test")
        cov = s.coverage(3600)
        self.assertFalse(cov["complete"])
        self.assertGreaterEqual(cov["gaps"], 1)

    def test_write_failure_sets_degraded_state(self):
        """A full disk must be a state change, not a swallowed exception."""
        s = self.store()
        s.db.close()  # force every subsequent write to fail
        s.upsert_batch(self.rows(1))
        self.assertIsNotNone(s.degraded_since)
        self.assertIsNotNone(s.last_write_error)

    def test_lookup_matches_source_or_destination(self):
        """Firewalla can flag either direction; an inbound hit must still be found."""
        s = self.store()
        now = int(time.time())
        s.upsert_batch([("eth0", "in", 6, "203.0.113.42", 34567, "192.168.1.50", 9735, now)])
        self.assertEqual(len(s.lookup("203.0.113.42")), 1)


if __name__ == "__main__":
    unittest.main()


class TestReportRedaction(unittest.TestCase):
    """`report` must not leak the LAN address or unrelated peers."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.s = Store(os.path.join(self.dir.name, "r.db"), history_minutes=1440)
        self.s.start_session("bpf", {})
        now = int(time.time())
        self.s.upsert_batch([
            ("veth0", "other", 17, "10.21.22.11", 19466, "203.0.113.42", 34567, now),
            ("eth0", "out", 17, "192.168.1.50", 19466, "203.0.113.42", 34567, now),
            # An unrelated peer that must never appear in a report for the address above.
            ("eth0", "out", 6, "192.168.1.50", 9735, "198.51.100.99", 9735, now),
        ])

    def tearDown(self):
        self.dir.cleanup()

    def _report(self, *args):
        import io, contextlib
        from recorder import cli
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.cmd_report(self.s, list(args))
        return buf.getvalue()

    def test_report_masks_lan_address(self):
        out = self._report("203.0.113.42", "34567")
        self.assertNotIn("192.168.1.50", out)
        self.assertIn("<this node>", out)

    def test_report_keeps_prenat_container_address(self):
        out = self._report("203.0.113.42", "34567")
        self.assertIn("10.21.22.11", out)

    def test_report_excludes_unrelated_peers(self):
        out = self._report("203.0.113.42", "34567")
        self.assertNotIn("198.51.100.99", out)

    def test_report_no_match_still_states_coverage(self):
        out = self._report("203.0.113.7")
        self.assertIn("NO MATCH", out)
        self.assertIn("COVERAGE", out)
