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

    def test_quay_highlight_and_no_confirmed_exposure(self):
        quay = make_advisory(
            identifier="CVE-2026-123710",
            title="Red Hat Quay signing-key takeover", severity="critical", cvss=9.8,
            affected=["Red Hat Quay"],
            source="Red Hat Security Data API",
            url="https://access.redhat.com/security/cve/CVE-2026-123710",
            published="2026-11-11")
        rows, alerts = process(now=self.now, previous=[], fetched=[quay],
                               watchlist=["Quay"])
        self.assertEqual(rows[0]["priority"], "review")
        self.assertGreater(rows[0]["attention_score"], 0)
        self.assertEqual(rows[0]["exposure"], "not assessed")
        self.assertEqual(alerts[0]["id"], "CVE-2026-123710")

    def test_first_seen_survives_repeated_collections(self):
        first = datetime(2026, 11, 13, 9, 48, tzinfo=timezone.utc)
        second = datetime(2026, 11, 13, 10, 25, tzinfo=timezone.utc)
        third = datetime(2026, 11, 13, 11, 26, tzinfo=timezone.utc)
        initial, _ = process(now=first, previous=[], fetched=[self.cve],
                             watchlist=["Docker"])
        self.assertEqual(initial[0]["first_seen"], "2026-11-13T09:48:00Z")
        revised, _ = process(now=second, previous=initial, fetched=[self.cve],
                             watchlist=["Docker"])
        self.assertEqual(revised[0]["first_seen"], "2026-11-13T09:48:00Z")
        self.assertEqual(revised[0]["last_seen"], "2026-11-13T10:25:00Z")
        latest, _ = process(now=third, previous=revised, fetched=[self.cve],
                            watchlist=["Docker"])
        self.assertEqual(latest[0]["first_seen"], "2026-11-13T09:48:00Z")
        self.assertEqual(latest[0]["last_seen"], "2026-11-13T11:26:00Z")

    def test_last_seen_only_updates_if_source_returns_record(self):
        first = datetime(2026, 11, 13, 9, 48, tzinfo=timezone.utc)
        later = datetime(2026, 11, 13, 11, 26, tzinfo=timezone.utc)
        initial, _ = process(now=first, previous=[], fetched=[self.cve],
                             watchlist=["Docker"])
        rows, _ = process(now=later, previous=initial, fetched=[],
                          watchlist=["Docker"])
        self.assertEqual(rows[0]["first_seen"], initial[0]["first_seen"])
        self.assertEqual(rows[0]["last_seen"], initial[0]["last_seen"])

    def test_alias_bridge_keeps_earliest_first_seen(self):
        a = make_advisory(identifier="GHSA-abcd-efgh-ijkl", title="Docker issue",
                          source="GitHub Advisory Database",
                          url="https://github.com/advisories/GHSA-abcd-efgh-ijkl")
        b = make_advisory(identifier="CVE-2026-123", title="Docker issue",
                          source="NIST NVD",
                          url="https://nvd.nist.gov/vuln/detail/CVE-2026-123")
        a["first_seen"] = "2026-11-13T09:48:00Z"
        a["last_seen"] = "2026-11-13T09:48:00Z"
        b["first_seen"] = "2026-11-13T10:25:00Z"
        b["last_seen"] = "2026-11-13T10:25:00Z"
        bridge = make_advisory(identifier="CVE-2026-123",
                               aliases=["GHSA-abcd-efgh-ijkl"],
                               title="Docker issue", source="GitHub Advisory Database",
                               url="https://github.com/advisories/GHSA-abcd-efgh-ijkl",
                               published="2026-11-11")
        observed_at = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
        rows, _ = process(now=observed_at, previous=[a, b], fetched=[bridge],
                          watchlist=["Docker"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["first_seen"], "2026-11-13T09:48:00Z")
        self.assertEqual(rows[0]["last_seen"], "2026-11-13T12:00:00Z")

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
