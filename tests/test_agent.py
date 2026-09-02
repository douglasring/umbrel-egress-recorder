"""Agent tests: MSP contract handling, and the alarm -> attribution join."""

import json
import os
import tempfile
import time
import unittest
from io import BytesIO

from agent.msp import Msp, extract, ALARM_TYPES, TYPES_WITH_REMOTE
from recorder.store import Store


class FakeResponse(BytesIO):
    status = 200
    def __enter__(self): return self
    def __exit__(self, *a): return False


class TestExtract(unittest.TestCase):
    def test_remote_port_array_is_preserved(self):
        """data-models/alarm types remote.port as Number[]; a scalar drops ports."""
        info = extract({"aid": 1, "type": 1, "ts": 1.0,
                        "remote": {"ip": "203.0.113.42", "port": [34567, 443]}})
        self.assertEqual(info["remote_ports"], [34567, 443])

    def test_scalar_port_still_accepted(self):
        info = extract({"aid": 1, "type": 1, "ts": 1.0,
                        "remote": {"ip": "203.0.113.42", "port": 443}})
        self.assertEqual(info["remote_ports"], [443])

    def test_alarm_without_remote_is_skipped(self):
        """Types outside [1,2,8,9,10,16] carry no remote host to attribute."""
        self.assertIsNone(extract({"aid": 2, "type": 5, "ts": 1.0,
                                   "device": {"ip": "192.168.1.9"}}))

    def test_type_one_is_security_activity(self):
        self.assertEqual(ALARM_TYPES[1], "Security Activity")
        self.assertIn(1, TYPES_WITH_REMOTE)

    def test_fields_carried_through(self):
        info = extract({"aid": 7, "gid": "g", "type": 1, "ts": 12.5,
                        "message": "m", "protocol": "tcp", "direction": "outbound",
                        "remote": {"ip": "203.0.113.9", "port": [443],
                                   "domain": "x.example", "category": "intel",
                                   "region": "RO"},
                        "device": {"ip": "192.168.1.50", "name": "umbrel"}})
        self.assertEqual(info["remote_category"], "intel")
        self.assertEqual(info["direction"], "outbound")
        self.assertEqual(info["type_name"], "Security Activity")


class TestMspQuery(unittest.TestCase):
    def setUp(self):
        self.calls = []

    def opener(self, req, timeout=None):
        self.calls.append(req.full_url)
        self.assertEqual(req.get_header("Authorization"), "Token TKN")
        return FakeResponse(json.dumps(
            {"count": 0, "results": [], "next_cursor": None}).encode())

    def test_incremental_query_is_built_and_encoded(self):
        Msp("msp.example", "TKN", opener=self.opener).new_security_alarms(1699999999.5)
        url = self.calls[0]
        self.assertIn("query=", url)
        self.assertIn("type%3A1", url)          # type:1
        self.assertIn("status%3Aactive", url)   # status:active
        self.assertIn("ts%3A%3E", url)          # ts:>
        self.assertIn("sortBy=ts%3Aasc", url)

    def test_cold_start_omits_ts(self):
        """No ts qualifier on a cold start; the API then defaults to 30 days.

        Assert on the `query` parameter alone - sortBy=ts:asc also contains "ts:"
        and would mask a real regression here.
        """
        import urllib.parse
        Msp("msp.example", "TKN", opener=self.opener).new_security_alarms(None)
        q = urllib.parse.parse_qs(
            urllib.parse.urlparse(self.calls[0]).query)["query"][0]
        self.assertNotIn("ts:", q)
        self.assertIn("type:1", q)

    def test_pagination_follows_cursor(self):
        pages = [
            {"results": [{"aid": 1}], "next_cursor": "abc"},
            {"results": [{"aid": 2}], "next_cursor": None},
        ]
        seen = []
        def opener(req, timeout=None):
            seen.append(req.full_url)
            return FakeResponse(json.dumps(pages[len(seen) - 1]).encode())
        got = Msp("msp.example", "TKN", opener=opener).alarms("type:1")
        self.assertEqual([a["aid"] for a in got], [1, 2])
        self.assertIn("cursor=abc", seen[1])


class TestAttributionJoin(unittest.TestCase):
    """The point of the whole system: alarm IP -> pre-NAT container address."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        path = os.path.join(self.dir.name, "egress.db")
        s = Store(path, history_minutes=1440)
        s.start_session("bpf", {})
        now = int(time.time())
        s.upsert_batch([
            ("veth0", "other", 6, "10.21.22.11", 51514, "203.0.113.42", 34567, now),
            ("eth0", "out", 6, "192.168.1.50", 51514, "203.0.113.42", 34567, now),
        ])
        s.db.close()
        os.environ["DB_PATH"] = path
        self.path = path

    def tearDown(self):
        self.dir.cleanup()

    def test_alarm_ip_resolves_to_container_address(self):
        import agent.__main__ as m
        m.DB_PATH = self.path
        store = m.open_recorder_readonly()
        text = m.report_for(store, "203.0.113.42", 34567)
        store.db.close()
        self.assertIn("10.21.22.11", text)      # the attribution
        self.assertNotIn("192.168.1.50", text)  # LAN address masked
        self.assertIn("<this node>", text)

    def test_recorder_db_is_opened_read_only(self):
        import agent.__main__ as m, sqlite3
        m.DB_PATH = self.path
        store = m.open_recorder_readonly()
        with self.assertRaises(sqlite3.OperationalError):
            store.db.execute("DELETE FROM flow")
        store.db.close()


if __name__ == "__main__":
    unittest.main()


class TestConfigFallback(unittest.TestCase):
    """Config must not depend on compose substitution, which Portainer may not apply."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "agent.env")
        import agent.__main__ as m
        self.m = m
        self._orig = m.CONFIG_FILE
        m.CONFIG_FILE = self.path

    def tearDown(self):
        self.m.CONFIG_FILE = self._orig
        for k in ("MSP_DOMAIN", "MSP_TOKEN"):
            os.environ.pop(k, None)
        self.dir.cleanup()

    def test_file_fills_missing_values(self):
        open(self.path, "w").write("MSP_DOMAIN=a.example\nMSP_TOKEN=tok\n")
        c = self.m.cfg()
        self.assertEqual(c["MSP_DOMAIN"], "a.example")
        self.assertEqual(c["MSP_TOKEN"], "tok")

    def test_file_fills_empty_substitution(self):
        """The actual Portainer failure: the var exists but substituted to ''."""
        os.environ["MSP_DOMAIN"] = ""
        open(self.path, "w").write("MSP_DOMAIN=b.example\n")
        self.assertEqual(self.m.cfg()["MSP_DOMAIN"], "b.example")

    def test_real_env_value_wins_over_file(self):
        os.environ["MSP_DOMAIN"] = "env.example"
        open(self.path, "w").write("MSP_DOMAIN=file.example\n")
        self.assertEqual(self.m.cfg()["MSP_DOMAIN"], "env.example")

    def test_quotes_and_comments_tolerated(self):
        open(self.path, "w").write('# note\nMSP_TOKEN="quoted-tok"\n\n')
        self.assertEqual(self.m.cfg()["MSP_TOKEN"], "quoted-tok")

    def test_missing_file_is_not_an_error(self):
        self.m.CONFIG_FILE = os.path.join(self.dir.name, "absent.env")
        self.assertIsInstance(self.m.cfg(), dict)
