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
        
        # This single line replaces Linh's entire 'for' loop and try/except block
        inserted, skipped = collector.collect_and_store(
            db_path=Path(DB_PATH), 
            mode="time", 
            days_back=30
        )
        
        print(f"[+] Pipeline Success: {inserted} inserted, {skipped} duplicates.")
        
        # Assertions to prove the pipeline actually wrote to the DB
        self.assertGreater(inserted, 0, "Pipeline failed to insert any real records.")
        self.assertGreaterEqual(skipped, 0)

if __name__ == "__main__":
    unittest.main()