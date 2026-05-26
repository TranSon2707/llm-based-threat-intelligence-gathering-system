"""
=============================================================================
MODULE: 02_test_db.py
PURPOSE: Tests SQLite database operations including insertion and deduplication.
HOW IT TESTS:
1. Initializes a fresh test database.
2. Inserts a record as a tuple (matching insert_raw_item signature), prints status.
3. Inserts duplicate — verifies it returns the EXISTING row ID (not 0),
   reflecting Fix 2 where insert_raw_item now returns the existing row's ID
   instead of 0 on a duplicate.
4. Verifies mark_processed correctly flags the record.
COMMAND: python -m unittest tests.02_test_db
=============================================================================
"""
import os
import unittest
from db.sqlite_manager import init_db, DB_PATH, insert_raw_item, get_unprocessed_batch, mark_processed

class TestDatabaseLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()

    def test_db_operations(self):
        # insert_raw_item expects a tuple:
        # (source, title, description, source_url, published_date, collected_at, raw, dedup_key)
        sample = (
            "test",
            "Test Threat",
            "Desc",
            "http://x.com",
            "2026-01-01",
            "2026-01-01T00:00:00+00:00",
            "{}",
            "unique_hash_123",
        )

        print("\n[*] Inserting new record...")
        result1 = insert_raw_item(sample)
        print(f" -> Insert ID: {result1}")
        self.assertIsNotNone(result1)
        self.assertGreater(result1, 0, "First insert should return a valid row ID.")

        print("[*] Inserting duplicate record...")
        result2 = insert_raw_item(sample)
        print(f" -> Insert ID (should equal result1 = {result1}): {result2}")
        # Fix 2: duplicate now returns the EXISTING row's ID, not 0
        self.assertEqual(result2, result1,
            "Duplicate insert should return the existing row ID, not 0.")

        # get_unprocessed_batch uses 'limit', not 'batch_size'
        batch = get_unprocessed_batch(limit=1)
        print(f"[*] Unprocessed items in DB: {len(batch)}")
        self.assertEqual(len(batch), 1, "Should have exactly 1 unprocessed record.")

        mark_processed(batch[0]['id'])
        print("[*] Marked as processed. New unprocessed count should be 0.")
        self.assertEqual(len(get_unprocessed_batch(limit=1)), 0,
            "No unprocessed records should remain after mark_processed.")

if __name__ == "__main__":
    unittest.main(verbosity=2)