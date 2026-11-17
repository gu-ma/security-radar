"""Collection health persistence tests using temporary directories."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_radar.engine import run
from security_radar.http import SourceSchemaError
from security_radar.model import make_advisory


class CollectionHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.config = self.root / "monitor.json"
        self.config.write_text(json.dumps({
            "watchlist": ["Docker"], "focus_topics": [],
            "collectors": {"fake": True},
            "retention_days": 180, "max_entries": 2500,
        }), encoding="utf-8")

    def read(self, name):
        return json.loads((self.data / name).read_text(encoding="utf-8"))

    def test_success_creates_history_and_status(self):
        collector = lambda now, *, days: [make_advisory(
            identifier="CVE-2026-12345", title="Docker vulnerability",
            published="2026-11-16", modified="2026-11-16", severity="critical",
            source="NIST NVD", url="https://nvd.nist.gov/vuln/detail/CVE-2026-12345")]
        with patch("security_radar.engine.discover_sources", return_value={"fake": collector}):
            self.assertEqual(run(self.config, self.data), 0)
            self.assertEqual(run(self.config, self.data), 0)
        entries = self.read("history.json")
        self.assertEqual(len(entries), 2)
        self.assertTrue(all(x["result"]=="healthy" for x in entries))
        self.assertEqual(entries[0]["sources"]["fake"]["state"], "ok")
        self.assertFalse(self.read("status.json")["failed"])

    def test_failure_retains_advisories_and_writes_failure_record(self):
        prior = [{"id": "CVE-2026-12345", "title": "Previously collected"}]
        self.data.joinpath("advisories.json").write_text(json.dumps(prior), encoding="utf-8")
        previous_alerts = {"alerts": [{"id": "CVE-2026-12345"}]}
        self.data.joinpath("alerts.json").write_text(json.dumps(previous_alerts), encoding="utf-8")
        self.data.joinpath("status.json").write_text(json.dumps({
            "last_successful_run": "2026-11-16T12:00:00Z",
            "sources": {"fake": {"state": "ok", "last_success": "2026-11-16T12:00:00Z"}}
        }), encoding="utf-8")
        def broken(now, *, days):
            raise SourceSchemaError("invalid required field")
        with patch("security_radar.engine.discover_sources", return_value={"fake": broken}):
            self.assertEqual(run(self.config, self.data), 1)
            self.assertEqual(run(self.config, self.data), 1)
        self.assertEqual(self.read("advisories.json"), prior)
        self.assertEqual(self.read("alerts.json"), previous_alerts)
        status = self.read("status.json")
        self.assertTrue(status["failed"])
        self.assertEqual(status["sources"]["fake"]["error_type"], "schema")
        self.assertEqual(status["sources"]["fake"]["consecutive_failures"], 2)
        self.assertEqual(status["last_successful_run"], "2026-11-16T12:00:00Z")
        self.assertGreaterEqual(len(self.read("history.json")), 1)
        self.assertEqual(self.read("history.json")[0]["result"], "failed")


if __name__ == "__main__":
    unittest.main()
