"""
=============================================================================
MODULE: 02_test_db.py
PURPOSE: Tests SQLite database operations including insertion and deduplication.
HOW IT TESTS:
1. Initializes a fresh test database.
2. Inserts a record, prints status.
3. Inserts duplicate, verifies it returns 0 (ignored).
COMMAND: python -m unittest tests.02_test_db
=============================================================================
"""
import os
import unittest
from db.db import init_db, DB_PATH
from db.queries import insert_raw_item, get_unprocessed_batch, mark_processed

class TestDatabaseLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()

    def test_db_operations(self):
        sample = {
            "source": "test", "title": "Test Threat", "description": "Desc",
            "source_url": "http://x.com", "published_date": "2026-01-01",
            "collected_at": "2026-01-01", "processed": 0, "raw": "{}",
            "dedup_key": "unique_hash_123"
        }
        
        print("\n[*] Inserting new record...")
        result1 = insert_raw_item(sample)
        print(f" -> Insert ID: {result1}")
        self.assertIsNotNone(result1)
        
        print("[*] Inserting duplicate record...")
        result2 = insert_raw_item(sample)
        print(f" -> Insert ID (Should be 0): {result2}")
        self.assertEqual(result2, 0)
        
        batch = get_unprocessed_batch(batch_size=1)
        print(f"[*] Unprocessed items in DB: {len(batch)}")
        mark_processed(batch[0]['id'])
        print("[*] Marked as processed. New unprocessed count: 0")
        self.assertEqual(len(get_unprocessed_batch(1)), 0)

if __name__ == "__main__": 
    unittest.main(verbosity=2)