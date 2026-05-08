""" 
=============================================================================
MODULE: 01_test_collectors.py
PURPOSE: Validates the data retrieval logic for NVD, OTX, and RSS collectors.
HOW IT TESTS: 
1. Instantiates each collector (RSS, NVD, OTX).
2. Executes time-based and keyword fetching.
3. Prints the raw JSON output of the first item to verify schema structure.
COMMAND: python -m unittest tests.01_test_collectors
=============================================================================
"""
import os
import unittest
import json
from collectors.nvd_collector import NVDCollector
from collectors.otx_collector import OTXCollector
from collectors.rss_collector import RSSCollector

from dotenv import load_dotenv, find_dotenv
# Force load .env to ensure API keys are available during testing, especially in CI environments
load_dotenv(find_dotenv())

# --- FOR DEBUGGING ---
print("\n" + "="*50)
print("[DEBUG] KIỂM TRA ĐỌC FILE .ENV")
print(f"NVD_API_KEY: {os.getenv('NVD_API_KEY')}")
print(f"OTX_API_KEY: {os.getenv('OTX_API_KEY')}")
print("="*50 + "\n")
# ---------------------------------------------------

class TestCollectors(unittest.TestCase):
    def setUp(self):
        self.collectors = [RSSCollector(), NVDCollector(), OTXCollector()]

    def test_collectors_fetch_logic(self):
        for col in self.collectors:
            with self.subTest(collector=col.source_name):
                # Test time-based fetching
                print(f"\n[{col.source_name}] Testing fetch_by_time...")
                time_results = col.fetch_by_time(days_back=7, max_results=1)
                self.assertIsInstance(time_results, list)
                if time_results:
                    print(f" -> Success! First item title: {time_results[0].get('title', 'N/A')}")
                
                # Test keyword-based fetching
                print(f"[{col.source_name}] Testing fetch_by_keyword ('ransomware')...")
                key_results = col.fetch_by_keyword(query="ransomware", max_results=1)
                self.assertIsInstance(key_results, list)
                if key_results:
                    print(f" -> Success! First item title: {key_results[0].get('title', 'N/A')}")

if __name__ == "__main__":
    unittest.main(verbosity=2) 