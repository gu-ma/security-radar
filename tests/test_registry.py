import unittest

from security_radar.registry import discover_sources


class RegistryTests(unittest.TestCase):
    def test_all_four_sources_auto_discovered(self):
        collected = discover_sources()
        self.assertEqual(set(collected), {
            "cisa_kev", "github_advisories", "nist_nvd", "redhat_quay"
        })
        self.assertTrue(all(callable(f) for f in collected.values()))


if __name__ == "__main__":
    unittest.main()
