"""
=============================================================================
MODULE: 12_test_ctid_mapping.py
PURPOSE: Validates the CTID CVE->ATT&CK mapping fetch and parse logic.
HOW IT TESTS:
1. fetch_ctid_mapping() returns a non-empty dict.
2. No TTP value contains a semicolon (validates semicolon split fix).
3. No TTP value contains a BOM character (validates utf-8-sig fix).
4. All TTP values start with "T" (valid technique IDs).
5. Known CVE maps to the correct individual TTP IDs.
COMMAND: python -m unittest tests.12_test_ctid_mapping
=============================================================================
"""
import unittest
from collectors.sync_nvd_baseline import fetch_ctid_mapping

class TestCTIDMapping(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n[*] Fetching CTID mapping (requires internet)...")
        cls.mapping = fetch_ctid_mapping()
        print(f"[+] Loaded {len(cls.mapping)} CVE mappings.")

    def test_01_mapping_not_empty(self):
        self.assertGreater(len(self.mapping), 0,
            "CTID mapping returned empty — check BOM fix and column names.")

    def test_02_no_semicolons_in_ttp_values(self):
        print("\n[*] Checking for semicolons in TTP values...")
        violations = [
            (cve, ttp)
            for cve, ttps in self.mapping.items()
            for ttp in ttps
            if ";" in ttp
        ]
        if violations:
            print(f"[!] Found {len(violations)} TTP values with semicolons:")
            for cve, ttp in violations[:5]:
                print(f"    {cve} -> '{ttp}'")
        self.assertEqual(len(violations), 0,
            "Semicolon split fix failed — some TTP values still contain ';'.")

    def test_03_no_bom_in_cve_ids(self):
        print("\n[*] Checking for BOM characters in CVE IDs...")
        violations = [cve for cve in self.mapping if "\ufeff" in cve]
        self.assertEqual(len(violations), 0,
            f"BOM fix failed — CVE IDs contain \\ufeff: {violations[:3]}")

    def test_04_all_ttps_start_with_T(self):
        print("\n[*] Checking all TTP values start with 'T'...")
        violations = [
            (cve, ttp)
            for cve, ttps in self.mapping.items()
            for ttp in ttps
            if not ttp.startswith("T")
        ]
        self.assertEqual(len(violations), 0,
            f"Invalid TTP IDs found (must start with 'T'): {violations[:5]}")

    def test_05_known_cve_maps_correctly(self):
        print("\n[*] Checking known CVE-2019-15243 mapping...")
        # From the CSV: CVE-2019-15243 -> T1059, T1190, T1078 as separate entries
        cve = "CVE-2019-15243"
        self.assertIn(cve, self.mapping,
            f"{cve} not found in CTID mapping.")
        ttps = self.mapping[cve]
        print(f"    {cve} -> {ttps}")
        self.assertIn("T1059", ttps, "T1059 should be mapped for CVE-2019-15243.")
        self.assertIn("T1190", ttps, "T1190 should be mapped for CVE-2019-15243.")
        self.assertIn("T1078", ttps, "T1078 should be mapped for CVE-2019-15243.")
        # Make sure they are individual entries, not combined
        for ttp in ttps:
            self.assertNotIn(" ", ttp.strip(),
                f"TTP '{ttp}' contains spaces — not properly split.")

if __name__ == "__main__":
    unittest.main(verbosity=2)