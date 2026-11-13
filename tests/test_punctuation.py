"""No em dash in public output or application-authored copy."""
import json
import tempfile
import unittest
from pathlib import Path

from security_radar.engine import write_json
from security_radar.model import make_advisory, normalize_punctuation


class PunctuationTests(unittest.TestCase):
    def test_nested_advisory_fields(self):
        original = {
            "title": "A\u2014B",
            "sources": [{"name": "Vendor\u2014feed", "url": "https://example.com"}],
            "affected": ["Package\u2014core"],
        }
        updated = normalize_punctuation(original)
        self.assertEqual(updated["title"], "A - B")
        self.assertEqual(updated["sources"][0]["name"], "Vendor - feed")
        self.assertNotIn("\u2014", str(updated))
        self.assertEqual(original["title"], "A\u2014B")

    def test_normalized_advisory(self):
        row = make_advisory(identifier="CVE-2026-0001",
            title="Vendor\u2014issue", summary="A\u2014B",
            source="Vendor\u2014source", url="https://example.com")
        self.assertNotIn("\u2014", json.dumps(row, ensure_ascii=False))

    def test_json_write_strips_em_dash(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "snapshot.json"
            write_json(path, [{"summary": "Upstream\u2014text"}])
            self.assertNotIn("\u2014", path.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(path.read_text())[0]["summary"], "Upstream - text")

    def test_site_and_documentation_no_em_dash(self):
        root = Path(__file__).resolve().parents[1]
        for folder in ("docs",):
            for path in (root / folder).glob("*.html"):
                self.assertNotIn("\u2014", path.read_text(encoding="utf-8"), str(path))
        for path in (root / "README.md", root / "SECURITY.md"):
            self.assertNotIn("\u2014", path.read_text(encoding="utf-8"), str(path))


if __name__ == "__main__":
    unittest.main()
