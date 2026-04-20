import os
import unittest
from pathlib import Path
from db.db import init_db, DB_PATH, SCHEMA_PATH
from db.queries import insert_raw_item, get_unprocessed_batch, mark_processed

class TestDatabaseLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Initialize a fresh database for testing."""
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()

    def test_01_insert_and_deduplication(self):
        """Test that items are inserted and duplicates are ignored by the dedup_key."""
        sample_data = {
            "source": "test_source",
            "title": "Test Title",
            "description": "Test Description",
            "source_url": "http://example.com",
            "published_date": "2026-04-20",
            "collected_at": "2026-04-20T10:00:00Z",
            "processed": 0,
            "raw": {"key": "value"},
            "dedup_key": "unique_hash_123"
        }

        # First insert should succeed
        result1 = insert_raw_item(sample_data)
        self.assertIsNotNone(result1, "First insert failed")

        # Second insert with same dedup_key should be ignored
        result2 = insert_raw_item(sample_data)
        self.assertEqual(result2, 0, "Deduplication failed: Duplicate was not ignored")

    def test_02_processing_flow(self):
        """Test fetching unprocessed items and marking them as done."""
        # Check that we can fetch the item we just added
        batch = get_unprocessed_batch(batch_size=1)
        self.assertEqual(len(batch), 1)
        item_id = batch[0]['id']

        # Mark as processed
        mark_processed(item_id)

        # Batch should now be empty
        new_batch = get_unprocessed_batch(batch_size=1)
        self.assertEqual(len(new_batch), 0, "Item was still found after being marked processed")

if __name__ == "__main__":
    unittest.main()