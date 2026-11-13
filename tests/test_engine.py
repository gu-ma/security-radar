import unittest
from datetime import datetime, timezone
from security_radar.engine import process
from security_radar.model import make_advisory, merge, enrich


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 13, tzinfo=timezone.utc)
        self.cve = make_advisory(
            identifier="CVE-2026-123", title="Docker Engine issue",
            severity="critical", source="NIST NVD",
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-123",
            published="2026-11-12", modified="2026-11-12")

    def test_exploited_plus_watchlist_is_investigate_not_confirmed(self):
        row = dict(self.cve, exploited=True)
        scored = enrich(row, ["Docker"])
        self.assertEqual(scored["priority"], "investigate")
        self.assertEqual(scored["exposure"], "not assessed")

    def test_merge_preserves_exploitation_and_sources(self):
        b = make_advisory(
            identifier="CVE-2026-123", title="Docker Engine issue",
            source="CISA KEV", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            exploited=True)
        row = merge(self.cve, b, "2026-11-13T10:00:00Z")
        self.assertTrue(row["exploited"])
        self.assertEqual(len(row["sources"]), 2)
        self.assertEqual(row["severity"], "critical")

    def test_first_observation_yields_review_alert(self):
        records, alerts = process(now=self.now, previous=[], fetched=[self.cve],
                                  watchlist=["Docker"])
        self.assertEqual(len(records), 1)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["priority"], "review")

    def test_existing_record_does_not_repeat(self):
        rows, alerts = process(now=self.now, previous=[self.cve], fetched=[self.cve],
                               watchlist=["Docker"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(alerts, [])

    def test_cross_source_alias_merges(self):
        ghsa = make_advisory(
            identifier="CVE-2026-123", aliases=["GHSA-aaaa-bbbb-cccc"],
            title="Docker Engine issue", source="GitHub Advisory Database",
            url="https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            modified="2026-11-12")
        rows, _ = process(now=self.now, previous=[], fetched=[self.cve, ghsa],
                          watchlist=["Docker"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["sources"]), 2)


if __name__ == "__main__":
    unittest.main()
