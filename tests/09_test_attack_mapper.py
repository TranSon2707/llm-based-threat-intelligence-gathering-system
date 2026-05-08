"""
=============================================================================
MODULE: test_attack_mapper.py
PURPOSE: Tests the MITRE ATT&CK anti-hallucination filter.
HOW IT TESTS:
1. Mocks the 'mitreattack-python' library responses.
2. Confirms that valid IDs (e.g., T1190) return True.
3. Confirms that fake/hallucinated IDs (e.g., T9999) return False.
COMMAND: python -m unittest tests.09_test_attack_mapper
=============================================================================
"""

import unittest
from unittest.mock import patch
from enrichment.attack_mapper import validate_ttp_id

class TestAttackMapper(unittest.TestCase):
    
    @patch('enrichment.attack_mapper.mitre_data')
    def test_validate_valid_ttp(self, mock_mitre_data):
        # Simulate the MITRE database successfully finding the TTP ID
        mock_mitre_data.get_object_by_attack_id.return_value = {"id": "T1190", "name": "Exploit Public-Facing Application"}
        
        is_valid = validate_ttp_id("T1190")
        print(f"\n[*] Validating T1190 (Real ID): {is_valid}")
        self.assertTrue(is_valid, "T1190 should be validated as True.")
        mock_mitre_data.get_object_by_attack_id.assert_called_with("T1190", 'attack-pattern')

    @patch('enrichment.attack_mapper.mitre_data')
    def test_validate_invalid_ttp_hallucination(self, mock_mitre_data):
        # Simulate the MITRE database NOT finding the TTP ID (Hallucination)
        mock_mitre_data.get_object_by_attack_id.return_value = None
        
        is_valid = validate_ttp_id("T9999")
        print(f"\n[*] Validating T9999 (Fake ID): {is_valid}")
        self.assertFalse(is_valid, "T9999 should be rejected as False (Hallucination blocked).")

if __name__ == '__main__':
    unittest.main()