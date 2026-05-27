"""
=============================================================================
MODULE: 10_test_behavior_translator.py
PURPOSE: Validates the HyDE behavior translation via local LLM (Llama 3).
HOW IT TESTS:
1. Valid OSINT text produces a non-empty behaviors list.
2. Output JSON is well-formed with correct schema.
3. Each behavior is a non-empty single string.
4. Behaviors use formal technical language (MITRE-style vocabulary).
5. Malformed/empty input is handled gracefully without crashing.
COMMAND: python -m unittest tests.10_test_behavior_translator
NOTE: Requires Ollama running locally with llama3 pulled.
=============================================================================
"""
import unittest
from enrichment.behavior_translator import translate_to_behaviors

OSINT_SAMPLE = """
A new campaign attributed to APT28 has been observed exploiting CVE-2021-44228 
(Log4Shell) to gain initial access to corporate networks. After exploitation, 
the group deploys Cobalt Strike beacons for command and control, followed by 
lateral movement using stolen credentials. Data exfiltration was observed 
over HTTPS to external C2 infrastructure.
"""

MITRE_KEYWORDS = {
    "exploit", "execution", "access", "lateral", "credential",
    "exfiltration", "command", "control", "privilege", "persistence",
    "injection", "remote", "network", "deploy", "beacon"
}

class TestBehaviorTranslator(unittest.TestCase):

    def test_01_valid_input_returns_behaviors(self):
        print("\n[*] Testing valid OSINT input...")
        behaviors = translate_to_behaviors(OSINT_SAMPLE)
        print(f"[+] Extracted {len(behaviors)} behaviors:")
        for b in behaviors:
            print(f"    - {b}")
        self.assertIsInstance(behaviors, list, "Output should be a list.")
        self.assertGreater(len(behaviors), 0, "Should extract at least one behavior.")

    def test_02_each_behavior_is_a_string(self):
        print("\n[*] Testing behavior types...")
        behaviors = translate_to_behaviors(OSINT_SAMPLE)
        for i, b in enumerate(behaviors):
            self.assertIsInstance(b, str, f"Behavior {i} is not a string: {b}")
            self.assertGreater(len(b.strip()), 0, f"Behavior {i} is empty.")
        print(f"[+] All {len(behaviors)} behaviors are non-empty strings.")

    def test_03_behaviors_use_technical_language(self):
        print("\n[*] Testing for MITRE-style technical vocabulary...")
        behaviors = translate_to_behaviors(OSINT_SAMPLE)
        combined = " ".join(behaviors).lower()
        matched = [kw for kw in MITRE_KEYWORDS if kw in combined]
        print(f"[+] Matched MITRE keywords: {matched}")
        self.assertGreater(len(matched), 2,
            f"Behaviors lack technical MITRE vocabulary. Got: {behaviors}")

    def test_04_empty_input_returns_empty_list(self):
        print("\n[*] Testing empty input handling...")
        behaviors = translate_to_behaviors("")
        print(f"[+] Result for empty input: {behaviors}")
        self.assertIsInstance(behaviors, list,
            "Empty input should return a list.")
        self.assertEqual(len(behaviors), 0,
            "Empty input should return an EMPTY list — not call the LLM.")
        print("[PASS] Empty input correctly returns [] without calling LLM.")

    def test_05_garbage_input_does_not_crash(self):
        print("\n[*] Testing garbage input handling...")
        behaviors = translate_to_behaviors("!!!@@@### not a real threat $$$%%%^^^")
        print(f"[+] Result for garbage input: {behaviors}")
        self.assertIsInstance(behaviors, list,
            "Garbage input should return a list, not raise an exception.")
        # Garbage input may return [] or a list — both are acceptable
        # The critical assertion is that it does NOT crash
        for b in behaviors:
            self.assertIsInstance(b, str,
                f"Any returned behavior must be a string, got: {b}")
        print(f"[PASS] Garbage input handled gracefully — {len(behaviors)} behaviors returned.")

if __name__ == "__main__":
    unittest.main(verbosity=2)