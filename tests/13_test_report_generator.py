"""
=============================================================================
MODULE: 13_test_report_generator.py
PURPOSE: Validates the report_generator RAG pipeline.
HOW IT TESTS:
1. Valid full input produces a non-empty structured report.
2. Report contains all required section headers.
3. Report contains [source_id: X] citation.
4. Zero-day flag is reflected in the report.
5. Missing encapsulation raises ValueError immediately.
6. Empty entities and empty kg_payload are handled gracefully.
COMMAND: python -m unittest tests.13_test_report_generator
NOTE: Requires Ollama running locally with llama3 pulled.
=============================================================================
"""
import requests
import unittest
from preprocessor.encapsulator import encapsulate_threat_data
from reports.report_generator import generate_analyst_summary

REQUIRED_SECTIONS = [
    "## Threat Overview",
    "## Indicators of Compromise",
    "## MITRE ATT&CK Mapping",
    "## Matched Vulnerabilities",
    "## Blast Radius",
    "## Zero-Day Assessment",
    "## Recommended Actions",
]

SAMPLE_TEXT = encapsulate_threat_data(
    "APT28 has been observed exploiting CVE-2021-44228 (Log4Shell) to gain "
    "initial access to corporate networks. After exploitation, the group deploys "
    "Cobalt Strike beacons for command and control. C2 traffic was observed to "
    "192.168.100.50 and evil-c2.example.com. Dropped payload hash: "
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
)

SAMPLE_ENTITIES = [
    {"entity_type": "THREAT_ACTOR", "entity_value": "APT28"},
    {"entity_type": "MALWARE",      "entity_value": "Cobalt Strike"},
    {"entity_type": "CVE",          "entity_value": "CVE-2021-44228"},
    {"entity_type": "IPv4",         "entity_value": "192.168.100.50"},
    {"entity_type": "DOMAIN",       "entity_value": "evil-c2.example.com"},
    {"entity_type": "SHA256",       "entity_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
]

SAMPLE_KG_PAYLOAD = {
    "matched_cves":        ["CVE-2021-44228", "CVE-2021-26084"],
    "matched_ttps":        ["T1190", "T1059"],
    "systems_at_risk":     ["apache_log4j", "microsoft_windows"],
    "unmatched_behaviors": [],
    "is_zero_day":         False,
}

ZERO_DAY_KG_PAYLOAD = {
    "matched_cves":        [],
    "matched_ttps":        [],
    "systems_at_risk":     [],
    "unmatched_behaviors": ["Attacker uses novel memory corruption via heap spray"],
    "is_zero_day":         True,
}


def _ollama_available() -> bool:
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


class TestReportGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _ollama_available():
            raise unittest.SkipTest("Ollama not available — skipping report generator tests.")

    # ── Test 1 ────────────────────────────────────────────────────────────────

    def test_01_valid_input_produces_report(self):
        print("\n[*] Testing valid full input...")
        report = generate_analyst_summary(
            source_id=1,
            cleaned_text=SAMPLE_TEXT,
            entities_list=SAMPLE_ENTITIES,
            kg_payload=SAMPLE_KG_PAYLOAD,
        )
        print(f"\n[=] GENERATED REPORT:\n{'-'*60}\n{report}\n{'-'*60}")
        self.assertIsInstance(report, str)
        self.assertGreater(len(report.strip()), 100,
            "Report is too short — LLM may have failed silently.")

    # ── Test 2 ────────────────────────────────────────────────────────────────

    def test_02_report_contains_all_sections(self):
        print("\n[*] Testing report section headers...")
        report = generate_analyst_summary(
            source_id=2,
            cleaned_text=SAMPLE_TEXT,
            entities_list=SAMPLE_ENTITIES,
            kg_payload=SAMPLE_KG_PAYLOAD,
        )
        for section in REQUIRED_SECTIONS:
            self.assertIn(section, report,
                f"Missing section '{section}' in report.")
            print(f"    [PASS] Found: {section}")

    # ── Test 3 ────────────────────────────────────────────────────────────────

    def test_03_report_contains_citation(self):
        print("\n[*] Testing [source_id] citation...")
        report = generate_analyst_summary(
            source_id=42,
            cleaned_text=SAMPLE_TEXT,
            entities_list=SAMPLE_ENTITIES,
            kg_payload=SAMPLE_KG_PAYLOAD,
        )
        self.assertIn("[source_id: 42]", report,
            "Report is missing mandatory [source_id: 42] citation.")
        print("    [PASS] Citation found.")

    # ── Test 4 ────────────────────────────────────────────────────────────────

    def test_04_zero_day_flag_reflected_in_report(self):
        print("\n[*] Testing zero-day flag in report...")
        report = generate_analyst_summary(
            source_id=3,
            cleaned_text=SAMPLE_TEXT,
            entities_list=[],
            kg_payload=ZERO_DAY_KG_PAYLOAD,
        )
        print(f"\n[=] ZERO-DAY REPORT:\n{'-'*60}\n{report}\n{'-'*60}")
        report_lower = report.lower()
        self.assertTrue(
            "zero-day" in report_lower or "zero day" in report_lower or "novel" in report_lower,
            "Zero-day flag not reflected in report text."
        )
        print("    [PASS] Zero-day language found in report.")

    # ── Test 5 ────────────────────────────────────────────────────────────────

    def test_05_missing_encapsulation_raises(self):
        print("\n[*] Testing encapsulation guard...")
        with self.assertRaises(ValueError) as ctx:
            generate_analyst_summary(
                source_id=4,
                cleaned_text="Raw text without THREAT_DATA tags",
                entities_list=[],
                kg_payload=SAMPLE_KG_PAYLOAD,
            )
        print(f"    [PASS] ValueError raised: {ctx.exception}")

    # ── Test 6 ────────────────────────────────────────────────────────────────

    def test_06_empty_entities_and_empty_kg_handled(self):
        print("\n[*] Testing empty entities and empty kg_payload...")
        empty_kg = {
            "matched_cves":        [],
            "matched_ttps":        [],
            "systems_at_risk":     [],
            "unmatched_behaviors": [],
            "is_zero_day":         False,
        }
        report = generate_analyst_summary(
            source_id=5,
            cleaned_text=SAMPLE_TEXT,
            entities_list=[],
            kg_payload=empty_kg,
        )
        self.assertIsInstance(report, str)
        self.assertGreater(len(report.strip()), 0,
            "Report should not be empty even with no entities or graph context.")
        print("    [PASS] Handled gracefully.")

if __name__ == "__main__":
    unittest.main(verbosity=2)