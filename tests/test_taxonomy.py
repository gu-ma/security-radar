"""Tagging tests are offline: no text generation or outside model service."""
import unittest

from security_radar.taxonomy import CATEGORIES, categorize, explanation, next_step, topic_tags


class TaxonomyTests(unittest.TestCase):
    def test_six_categories(self):
        self.assertEqual(len(CATEGORIES), 6)
        self.assertEqual(len({slug for slug, _ in CATEGORIES}), 6)

    def test_quay_multiple_categories_and_supply_chain(self):
        row = {
            "title": "Red Hat Quay registry signing-key takeover",
            "summary": "Attackers may compromise image signing keys in a container registry.",
            "affected": ["Red Hat Quay"],
            "ecosystems": []
        }
        self.assertIn("containers", categorize(row))
        self.assertIn("Supply chain", topic_tags(row))
        self.assertNotIn("ai-ml", categorize(row))

    def test_python_package_category(self):
        row = {"title": "Malicious package published to PyPI",
               "summary": "A malicious package may be installed using pip."}
        self.assertIn("dependencies", categorize(row))
        self.assertIn("Supply chain", topic_tags(row))

    def test_multi_category(self):
        row = {"title": "Jupyter notebook web server remote code execution",
               "summary": "An attacker may achieve remote code execution."}
        self.assertIn("infrastructure", categorize(row))
        self.assertIn("ai-ml", categorize(row))
        self.assertIn("Remote code execution", topic_tags(row))

    def test_unknown_is_not_guess(self):
        self.assertEqual(categorize({"title": "Security issue", "summary": ""}),
                         ["unclassified"])

    def test_fixed_fallback_explanation(self):
        self.assertEqual(explanation({}),
                         "The source did not provide a description. Consult the original advisory.")

    def test_actions_do_not_claim_exposure(self):
        row = {"title": "Quay signing-key vulnerability", "exploited": False,
               "summary": "Container image registry signing-key issue"}
        msg = next_step(row)
        self.assertIn("upstream", msg.lower())
        self.assertNotIn("our servers", msg.lower())


if __name__ == "__main__":
    unittest.main()
