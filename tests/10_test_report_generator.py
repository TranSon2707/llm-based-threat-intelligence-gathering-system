"""
=============================================================================
MODULE: test_report_generator.py
PURPOSE: Tests the final report generation chain.
HOW IT TESTS:
1. Mocks 'build_standard_chain' from chain_builder.
2. Simulates an AI response and prints the final generated RAG report.
COMMAND: python -m unittest tests.10_test_report_generator
=============================================================================
"""
import unittest
from unittest.mock import MagicMock, patch
from enrichment.report_generator import generate_analyst_summary

class TestReportGenerator(unittest.TestCase):
    @patch('enrichment.report_generator.build_standard_chain')
    def test_generate_report(self, mock_chain_builder):
        mock_chain = MagicMock()
        mock_chain_builder.return_value = mock_chain
        
        # Simulate AI Response
        fake_report = "The adversary exploited an Apache server via log4j. [source_id: 104]"
        mock_chain.invoke.return_value = fake_report
        
        print("\n[*] Simulating Closed-Domain RAG execution...")
        result = generate_analyst_summary(
            source_id=104, 
            cleaned_text="The adversary exploited an Apache server.", 
            entities_list=[{"type": "IPv4", "value": "192.168.1.1"}], 
            ttp_list=[{"id": "T1190", "name": "Exploit Public"}]
        )
        
        print("\n[*] GENERATED EXECUTIVE SUMMARY:")
        print("=" * 50)
        print(result)
        print("=" * 50)
        
        self.assertIn("[source_id: 104]", result)
        mock_chain.invoke.assert_called_once()

if __name__ == '__main__':
    unittest.main(verbosity=2)