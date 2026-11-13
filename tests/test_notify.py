import io
import json
import unittest
from urllib.error import HTTPError
from urllib.request import Request

from security_radar.notify import (
    dashboard_link, render_text, select_alerts, send, validate_payload, workflow_payload
)


def example():
    return {
        "id": "CVE-2026-123710",
        "title": "Quay signing-key security vulnerability",
        "summary": "An attacker could modify affected container registry signing keys.",
        "severity": "critical",
        "cvss": 9.8,
        "categories": ["containers"],
        "security_topics": ["Supply chain"],
        "priority": "review",
        "attention_score": 125,
        "matched_topics": ["Quay"],
        "exposure": "not assessed",
        "suggested_next_step": "Consult the vendor advisory and verify affected versions.",
        "sources": [{"name": "Red Hat", "url": "https://access.redhat.com/security/cve/CVE-2026-123710"}],
    }


class Response:
    status = 202
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class NotificationTests(unittest.TestCase):
    def test_select_requires_watchlist(self):
        other = dict(example(), matched_topics=[], id="CVE-2026-123711")
        selected = select_alerts([other, example()])
        self.assertEqual([a["id"] for a in selected], ["CVE-2026-123710"])

    def test_filter_by_category(self):
        self.assertEqual(select_alerts([example()], categories=["ai-ml"]), [])
        self.assertEqual(len(select_alerts([example()], categories=["containers"])), 1)

    def test_json_contract_and_links(self):
        payload = workflow_payload([example()], "https://apps.massol.me/security-radar/")
        validate_payload(payload)
        self.assertEqual(set(payload), {"text"})
        self.assertIn("CVSS 9.8", payload["text"])
        self.assertIn("containers", payload["text"].lower())
        self.assertIn("Why it matters:", payload["text"])
        self.assertIn("Next step:", payload["text"])
        self.assertIn("CVE-2026-123710", payload["text"])
        self.assertIn("?q=CVE-2026-123710#findings", payload["text"])
        json.dumps(payload)

    def test_bad_url_never_enters_card(self):
        row = example()
        row["sources"] = [{"name": "Untrusted", "url": "javascript:alert(1)"}]
        self.assertNotIn("javascript:", render_text([row], "file:///tmp/foo"))

    def test_escaping_text_is_json_safe(self):
        row = example()
        row["title"] = 'A "quoted" title with newline\nvalue'
        payload = workflow_payload([row], "https://apps.massol.me/security-radar/")
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_send_http_mock(self):
        called = []
        def mock_opener(request: Request, timeout: int):
            called.append((request, timeout))
            return Response()
        code = send("https://example.org/workflow/secret", workflow_payload([example()], ""),
                    transport=mock_opener)
        self.assertEqual(code, 202)
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0][0].get_method(), "POST")
        self.assertEqual(called[0][0].get_header("Content-type"), "application/json")
        self.assertEqual(json.loads(called[0][0].data)["text"].splitlines()[0],
                         "Security Radar | New advisories")

    def test_reject_invalid_endpoint(self):
        with self.assertRaises(ValueError):
            send("http://example.org/unsafe", {"text": "hi"})
        with self.assertRaises(ValueError):
            validate_payload({"title": "hi"})

    def test_size_cap(self):
        with self.assertRaises(ValueError):
            validate_payload({"text": "x" * 9100})


if __name__ == "__main__":
    unittest.main()
