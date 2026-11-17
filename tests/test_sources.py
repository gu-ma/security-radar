import unittest
from security_radar.sources import parse_kev, parse_ghsa, parse_nvd, parse_redhat_quay


class ParserTests(unittest.TestCase):
    def test_kev(self):
        payload = {"vulnerabilities": [
            {"cveID": "CVE-2026-1", "dateAdded": "2026-11-10",
             "vendorProject": "Docker", "product": "Engine",
             "vulnerabilityName": "Example", "shortDescription": "Description"},
            {"cveID": "CVE-2025-2", "dateAdded": "2025-01-01"}
        ]}
        rows = parse_kev(payload, since="2026-11-01")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["exploited"])
        self.assertEqual(rows[0]["id"], "CVE-2026-1")

    def test_ghsa(self):
        rows = parse_ghsa([{
            "ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-123",
            "summary": "Example package", "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "some-package"}}]
        }])
        self.assertEqual(rows[0]["id"], "CVE-2026-123")
        self.assertIn("some-package", rows[0]["affected"])
        self.assertIn("GHSA-aaaa-bbbb-cccc", rows[0]["aliases"])

    def test_ghsa_retains_original_publication_when_updated_years_later(self):
        rows = parse_ghsa([{
            "ghsa_id": "GHSA-56xg-wfcc-g829",
            "cve_id": "CVE-2024-34359",
            "summary": "llama-cpp-python template injection",
            "severity": "critical",
            "published_at": "2024-05-13T14:10:18Z",
            "updated_at": "2026-11-16T15:19:28Z",
            "vulnerabilities": [{
                "package": {"ecosystem": "pip", "name": "llama-cpp-python"},
                "vulnerable_version_range": ">= 0.2.30, <= 0.2.71",
                "first_patched_version": "0.2.72"
            }],
        }])
        self.assertEqual(rows[0]["id"], "CVE-2024-34359")
        self.assertIn("GHSA-56xg-wfcc-g829", rows[0]["aliases"])
        self.assertEqual(rows[0]["published"], "2024-05-13T14:10:18Z")
        self.assertEqual(rows[0]["modified"], "2026-11-16T15:19:28Z")

    def test_redhat_quay_product_advisory(self):
        records = parse_redhat_quay([{
            "CVE": "CVE-2026-123710", "severity": "Critical", "cvss3_score": "9.8",
            "public_date": "2026-11-11",
            "bugzilla": {"description": "Quay signing-key takeover"}
        }])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["severity"], "critical")
        self.assertEqual(records[0]["cvss"], 9.8)
        self.assertIn("Red Hat Quay", records[0]["affected"])

    def test_nvd(self):
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2026-456", "published": "2026-11-11T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Docker example vulnerability"}],
            "metrics": {"cvssMetricV31": [{
                "type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
            }]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:example:docker_engine:*:*:*:*:*:*:*:*"}
            ]}]}]
        }}]}
        rows = parse_nvd(payload)
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertIn("example docker engine", rows[0]["affected"])


if __name__ == "__main__":
    unittest.main()
