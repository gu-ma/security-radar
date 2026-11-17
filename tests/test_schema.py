"""Corrupt nested JSON must fail, not silently discard advisories."""
import unittest

from security_radar.http import SourceSchemaError
from security_radar.sources import parse_ghsa, parse_kev, parse_nvd, parse_redhat_quay


class SchemaTests(unittest.TestCase):
    def test_valid_empty_batches(self):
        self.assertEqual(parse_ghsa([]), [])
        self.assertEqual(parse_nvd({"vulnerabilities": []}), [])
        self.assertEqual(parse_kev({"vulnerabilities": []}, since="2026-11-01"), [])
        self.assertEqual(parse_redhat_quay([]), [])

    def test_cisa_changed_required_fields(self):
        with self.assertRaises(SourceSchemaError):
            parse_kev({"vulnerabilities": [{"dateAdded": "2026-11-11"}]}, since="2026-11-01")
        with self.assertRaises(SourceSchemaError):
            parse_kev({"vulnerabilities": [None]}, since="2026-11-01")

    def test_github_bad_nested_structure(self):
        with self.assertRaises(SourceSchemaError):
            parse_ghsa([{"ghsa_id": "GHSA-abcd-efgh-ijkl", "vulnerabilities": "changed"}])
        with self.assertRaises(SourceSchemaError):
            parse_ghsa([{"ghsa_id": "GHSA-abcd-efgh-ijkl", "cvss": [9.8]}])
        with self.assertRaises(SourceSchemaError):
            parse_ghsa([{"ghsa_id": "GHSA-abcd-efgh-ijkl", "vulnerabilities": [{"package": "bad"}]}])

    def test_nvd_changed_cve_shape(self):
        with self.assertRaises(SourceSchemaError):
            parse_nvd({"vulnerabilities": [{"cve": {"newIdField": "CVE-2026-1234"}}]})
        with self.assertRaises(SourceSchemaError):
            parse_nvd({"vulnerabilities": [{"cve": {"id": "CVE-2026-1234",
                "metrics": {"cvssMetricV31": {"bad": "shape"}}}}]})

    def test_redhat_missing_cve(self):
        with self.assertRaises(SourceSchemaError):
            parse_redhat_quay([{"title": "changed"}])


if __name__ == "__main__":
    unittest.main()
