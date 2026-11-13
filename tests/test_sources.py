import unittest
from security_radar.sources import parse_kev, parse_ghsa, parse_nvd


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
