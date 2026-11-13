"""Offline validation of public RSS 2.0 and Atom 1.0 output."""
import unittest
from datetime import datetime
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET

from security_radar.feeds import ATOM_NS, advisory_link, render_feeds, select_entries

A = "{" + ATOM_NS + "}"


def sample(ident="CVE-2026-123710", **changes):
    row = {
        "id": ident, "title": 'Quay <signing> & registry "issue"',
        "summary": "Signing key exposure with an illegal XML control: \x01",
        "why_it_matters": "Signing key <access> & disclosure",
        "suggested_next_step": "Review affected versions.",
        "severity": "critical", "cvss": 9.8, "cvss_version": "3.1",
        "exploited": False, "matched_topics": ["Quay"],
        "categories": ["containers"], "security_topics": ["Supply chain"],
        "published": "2026-11-11T09:00:00Z", "modified": "2026-11-12T12:00:00Z",
        "sources": [{"name": "Red Hat", "url": "https://access.redhat.com/security/cve/" + ident}],
    }
    row.update(changes)
    return row


class FeedTests(unittest.TestCase):
    def test_feed_selection_is_curated_and_ordered(self):
        rows = [
            sample("CVE-2026-1111", modified="2026-11-11T00:00:00Z"),
            sample("CVE-2026-2222", modified="2026-11-13T00:00:00Z"),
            sample("CVE-2026-3333", matched_topics=[], modified="2026-11-14T00:00:00Z"),
            sample("CVE-2026-4444", severity="low", modified="2026-11-14T00:00:00Z"),
        ]
        self.assertEqual(
            [r["id"] for r in select_entries(rows)],
            ["CVE-2026-2222", "CVE-2026-1111"],
        )

    def test_kev_listed_low_severity_can_qualify(self):
        self.assertEqual(len(select_entries([sample(severity="low", exploited=True)])), 1)

    def test_deduplicates_ids_and_bounds_history(self):
        rows = [sample("CVE-2026-9999"), sample("CVE-2026-9999")]
        rows += [sample("CVE-2026-" + str(i), modified="2026-11-13T00:00:00Z")
                 for i in range(20)]
        selection = select_entries(rows, limit=5)
        self.assertEqual(len(selection), 5)
        self.assertEqual(len({r["id"] for r in selection}), 5)

    def test_feed_formats_parse_and_escape_source_text(self):
        artifacts = render_feeds([sample()])
        rss = ET.fromstring(artifacts["rss.xml"])
        atom = ET.fromstring(artifacts["atom.xml"])
        self.assertEqual(rss.tag, "rss")
        self.assertEqual(rss.attrib["version"], "2.0")
        self.assertEqual(atom.tag, A + "feed")
        item = rss.find("./channel/item")
        entry = atom.find(A + "entry")
        self.assertIsNotNone(item)
        self.assertIsNotNone(entry)
        self.assertEqual(item.findtext("title"), 'Quay <signing> & registry "issue"')
        self.assertEqual(entry.findtext(A + "title"), 'Quay <signing> & registry "issue"')
        self.assertIn("Signing key <access> & disclosure", item.findtext("description"))
        self.assertNotIn("\x01", artifacts["rss.xml"].decode())
        self.assertEqual(item.findtext("guid"), entry.findtext(A + "id"))
        self.assertEqual(item.find("guid").attrib["isPermaLink"], "true")
        self.assertEqual(item.findtext("link"),
                         "https://apps.massol.me/security-radar/?q=CVE-2026-123710#findings")
        self.assertEqual(parsedate_to_datetime(item.findtext("pubDate")).year, 2026)
        self.assertEqual(entry.findtext(A+"published"), "2026-11-11T09:00:00Z")
        self.assertEqual(entry.findtext(A+"updated"), "2026-11-12T12:00:00Z")
        self.assertEqual(entry.find(A+"link[@rel='related']").attrib["href"],
                         "https://access.redhat.com/security/cve/CVE-2026-123710")
        self.assertIn("Containers & registries",
                      [c.attrib["term"] for c in entry.findall(A+"category")])

    def test_deterministic_output_for_same_inputs(self):
        a = render_feeds([sample()])
        b = render_feeds([sample()])
        self.assertEqual(a, b)

    def test_missing_scores_and_dates_are_valid(self):
        artifacts = render_feeds([sample(cvss=None, cvss_version="", published="", modified="", first_seen="2026-11-10")])
        self.assertEqual(ET.fromstring(artifacts["atom.xml"]).findtext(A + "entry/" + A + "published"),
                         "2026-11-10T00:00:00Z")
        self.assertIn(b"Severity: CRITICAL", artifacts["rss.xml"])

    def test_disallow_non_https_source_link(self):
        artifacts = render_feeds([sample(sources=[{"name": "Bad", "url": "javascript:alert(1)"}])])
        self.assertNotIn(b"javascript:", artifacts["rss.xml"])
        self.assertNotIn(b"javascript:", artifacts["atom.xml"])

    def test_empty_feed_is_well_formed(self):
        artifacts = render_feeds([])
        self.assertEqual(len(ET.fromstring(artifacts["rss.xml"]).findall("./channel/item")), 0)
        self.assertEqual(len(ET.fromstring(artifacts["atom.xml"]).findall(A+"entry")), 0)

    def test_bad_input_and_base_rejected(self):
        with self.assertRaises(ValueError):
            select_entries({"wrong": "shape"})
        with self.assertRaises(ValueError):
            select_entries([], 0)
        with self.assertRaises(ValueError):
            render_feeds([sample()], base="http://localhost:8000/")

    def test_deep_link_encoding(self):
        self.assertIn("?q=GHSA-abcd-efgh-ijkl#findings",
                      advisory_link("https://apps.massol.me/security-radar/", {"id": "GHSA-abcd-efgh-ijkl"}))


if __name__ == "__main__":
    unittest.main()
