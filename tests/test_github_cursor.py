"""Cursor-based GitHub advisory pagination regression coverage."""
import unittest
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from security_radar.http import SourcePaginationError, SourceSchemaError
from security_radar.sources import collect_ghsa


def advisory(identifier: str):
    return {
        "ghsa_id": identifier,
        "summary": "A test vulnerability",
        "severity": "critical",
        "published_at": "2026-11-16T00:00:00Z",
        "updated_at": "2026-11-17T00:00:00Z",
    }


class GithubCursorTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 17, tzinfo=timezone.utc)

    def test_uses_cursor_and_collects_all_pages(self):
        calls = []
        def page(url):
            calls.append(url)
            if "after=cursor123" in url:
                return [advisory("GHSA-2222-2222-2222")], None
            if "type=reviewed" in url and "severity=critical" in url:
                return [advisory("GHSA-1111-1111-1111")], url + "&after=cursor123"
            return [], None
        with patch("security_radar.sources.get_github_page", side_effect=page):
            items = collect_ghsa(self.now)
        self.assertEqual(len(items), 2)
        self.assertEqual(len(calls), 4)
        self.assertIn("after=cursor123", calls[1])
        self.assertNotIn("page", parse_qs(urlsplit(calls[0]).query))

    def test_repeated_cursor_fails_closed(self):
        def page(url):
            return [advisory("GHSA-1111-1111-1111")], url
        with patch("security_radar.sources.get_github_page", side_effect=page):
            with self.assertRaises(SourcePaginationError):
                collect_ghsa(self.now)

    def test_duplicate_data_on_next_page_fails_closed(self):
        def page(url):
            return [advisory("GHSA-1111-1111-1111")], (
                None if "after=next" in url else url + "&after=next"
            )
        with patch("security_radar.sources.get_github_page", side_effect=page):
            with self.assertRaises(SourcePaginationError):
                collect_ghsa(self.now)

    def test_invalid_json_shape_fails_closed(self):
        with patch("security_radar.sources.get_github_page", side_effect=SourceSchemaError("changed")):
            with self.assertRaises(SourceSchemaError):
                collect_ghsa(self.now)

    def test_full_page_without_next_link_is_valid(self):
        rows = [advisory(f"GHSA-{n:04d}-1111-2222") for n in range(100)]
        def page(url):
            if "type=reviewed" in url and "severity=critical" in url:
                return rows, None
            return [], None
        with patch("security_radar.sources.get_github_page", side_effect=page):
            self.assertEqual(len(collect_ghsa(self.now)), 100)


if __name__ == "__main__":
    unittest.main()
