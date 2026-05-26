"""
=============================================================================
MODULE: 11_test_kg_engine.py
PURPOSE: Validates the KnowledgeEngine end-to-end graph evaluation.
HOW IT TESTS:
1. Known CVE behavior returns matched threats and is_zero_day=False.
2. Unknown behavior populates unmatched_behaviors and is_zero_day=True.
3. Mixed behaviors (one known, one unknown) correctly splits results:
   is_zero_day=False but unmatched_behaviors is non-empty.
4. Empty input returns safe empty payload without crashing.
5. systems_at_risk is non-empty for a known behavior.
COMMAND: python -m unittest tests.11_test_kg_engine
NOTE: Requires Neo4j running locally with the baseline graph built.
=============================================================================
"""
import unittest
from enrichment.kg_engine import KnowledgeEngine

KNOWN_BEHAVIOR    = "Attacker exploits JNDI injection vulnerability to achieve remote code execution"
UNKNOWN_BEHAVIOR  = "Attacker uses telepathic intrusion to bypass quantum firewall silently"

class TestKnowledgeEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = KnowledgeEngine()

    @classmethod
    def tearDownClass(cls):
        cls.engine.close()

    def test_01_known_behavior_matches(self):
        print("\n[*] Testing known CVE behavior...")
        payload = self.engine.evaluate_threat([KNOWN_BEHAVIOR])
        print(f"    matched_threats  : {payload['matched_threats']}")
        print(f"    techniques       : {payload['techniques']}")
        print(f"    systems_at_risk  : {payload['systems_at_risk']}")
        print(f"    is_zero_day      : {payload['is_zero_day']}")
        self.assertFalse(payload["is_zero_day"],
            "Known behavior should not be zero-day.")
        self.assertGreater(len(payload["matched_threats"]), 0,
            "Known behavior should match at least one CVE or TTP.")

    def test_02_known_behavior_has_blast_radius(self):
        print("\n[*] Testing blast radius for known behavior...")
        payload = self.engine.evaluate_threat([KNOWN_BEHAVIOR])
        print(f"    systems_at_risk  : {payload['systems_at_risk']}")
        self.assertGreater(len(payload["systems_at_risk"]), 0,
            "Known behavior should produce a non-empty blast radius.")

    def test_03_unknown_behavior_is_zero_day(self):
        print("\n[*] Testing unknown behavior zero-day detection...")
        payload = self.engine.evaluate_threat([UNKNOWN_BEHAVIOR])
        print(f"    is_zero_day        : {payload['is_zero_day']}")
        print(f"    unmatched_behaviors: {payload['unmatched_behaviors']}")
        self.assertTrue(payload["is_zero_day"],
            "Unknown behavior should be flagged as zero-day.")
        self.assertIn(UNKNOWN_BEHAVIOR, payload["unmatched_behaviors"],
            "Unknown behavior should appear in unmatched_behaviors.")

    def test_04_mixed_behaviors_partial_match(self):
        print("\n[*] Testing mixed known + unknown behaviors...")
        payload = self.engine.evaluate_threat([KNOWN_BEHAVIOR, UNKNOWN_BEHAVIOR])
        print(f"    is_zero_day        : {payload['is_zero_day']}")
        print(f"    matched_threats    : {payload['matched_threats']}")
        print(f"    techniques         : {payload['techniques']}")
        print(f"    unmatched_behaviors: {payload['unmatched_behaviors']}")
        # At least one matched — so not a full zero-day
        self.assertFalse(payload["is_zero_day"],
            "Mixed input: one known match means is_zero_day should be False.")
        # But the unknown one should still surface
        self.assertIn(UNKNOWN_BEHAVIOR, payload["unmatched_behaviors"],
            "Unknown behavior in mixed input should still appear in unmatched_behaviors.")

    def test_05_empty_input_safe(self):
        print("\n[*] Testing empty behaviors list...")
        payload = self.engine.evaluate_threat([])
        self.assertEqual(payload["matched_threats"],    [], "Should be empty.")
        self.assertEqual(payload["systems_at_risk"],    [], "Should be empty.")
        self.assertEqual(payload["techniques"],         [], "Should be empty.")
        self.assertEqual(payload["unmatched_behaviors"],[],  "Should be empty.")
        self.assertTrue(payload["is_zero_day"],
            "Empty input should default to is_zero_day=True.")
        print("[+] Empty input handled safely.")

if __name__ == "__main__":
    unittest.main(verbosity=2)