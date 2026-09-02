"""Structural checks on compose.yml.

yaml.safe_load is not enough. A bad edit produced the top-level key
"volumes:volumes", which YAML happily parses as one key and only Compose's own
schema rejects - so the stack failed to deploy while every local check passed.
"""

import os
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCompose(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "compose.yml")) as fh:
            self.doc = yaml.safe_load(fh)

    def test_top_level_keys_are_exactly_services_and_volumes(self):
        self.assertEqual(sorted(self.doc), ["services", "volumes"])

    def test_declared_volumes(self):
        self.assertEqual(sorted(self.doc["volumes"]), ["agent-state", "egress-data"])

    def test_services(self):
        self.assertEqual(sorted(self.doc["services"]), ["alarm-agent", "egress-recorder"])

    def test_every_image_is_digest_pinned(self):
        for name, svc in self.doc["services"].items():
            self.assertIn("@sha256:", svc["image"], name)

    def test_both_services_use_the_same_image(self):
        images = {s["image"] for s in self.doc["services"].values()}
        self.assertEqual(len(images), 1, images)

    def test_no_credentials_or_substitution_in_compose(self):
        raw = open(os.path.join(ROOT, "compose.yml")).read()
        for line in raw.splitlines():
            if line.strip().startswith("#"):
                continue
            self.assertNotIn("${", line)
            self.assertNotIn("MSP_TOKEN", line)

    def test_agent_reads_recorder_volume_read_only(self):
        vols = self.doc["services"]["alarm-agent"]["volumes"]
        self.assertIn("egress-data:/data:ro", vols)

    def test_agent_has_no_capabilities(self):
        self.assertNotIn("cap_add", self.doc["services"]["alarm-agent"])

    def test_recorder_capabilities_are_the_minimum_that_works(self):
        rec = self.doc["services"]["egress-recorder"]
        self.assertEqual(rec["cap_drop"], ["ALL"])
        self.assertEqual(sorted(rec["cap_add"]), ["NET_RAW", "SETGID", "SETUID"])
