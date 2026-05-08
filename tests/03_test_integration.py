"""
=============================================================================
MODULE: 03_test_integration.py
PURPOSE: Tests the end-to-end flow from API collection to Database storage.
HOW IT TESTS:
1. Uses the RSSCollector to pull live data from a real feed.
2. Uses 'collect_and_store' to automate the fetch-verify-save cycle.
3. Asserts that new records are successfully written to the 'raw_items' table.
COMMAND: python -m unittest tests.03_test_integration
=============================================================================
"""

import os
import unittest
from pathlib import Path
from db.db import init_db, DB_PATH
from collectors.rss_collector import RSSCollector

class TestPipelineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up a fresh database for the integration test."""
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()

    def test_full_collection_pipeline(self):
        """
        Tests hitting a REAL API and saving it directly to the Database 
        using the orchestrator method.
        """
        print("\n[*] Starting End-to-End Pipeline Test (RSS -> Database)...")
        
        # We use RSS because it is fast and doesn't require an API key
        collector = RSSCollector()

        inserted, skipped = collector.collect_and_store(
            db_path=Path(DB_PATH), mode="time", days_back=30
        )
        print(f"[+] Pipeline Success: {inserted} inserted, {skipped} duplicates skipped.")
        self.assertGreater(inserted, 0, "No records inserted from live feed.")

if __name__ == "__main__":
    unittest.main(verbosity=2)