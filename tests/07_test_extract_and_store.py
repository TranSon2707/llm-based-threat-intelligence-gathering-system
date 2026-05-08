"""
=============================================================================
MODULE: test_extract_and_store.py
PURPOSE: Tests the integration between enrichment modules and the Database.
HOW IT TESTS:
1. Initializes DB and extracts entities + NER from a complex text.
2. Directly queries the 'entities' table.
3. Prints the raw SQLite rows to prove data was actually persisted.
COMMAND: python -m unittest tests.07_test_extract_and_store
=============================================================================
"""
import unittest
import sqlite3
import os
from db.db import init_db, DB_PATH
from enrichment.entity_extractor import extract_and_store
from enrichment.ner_spacy import extract_and_store_ner

class TestStoreIntegration(unittest.TestCase):
    def test_database_storage_integration(self):
        init_db()
        text = """The Lazarus Group deployed WannaCry ransomware across hospital networks 
        last month. Simultaneously, APT28, also known as Fancy Bear, used 
        Emotet as a dropper to deliver Cobalt Strike beacons. 
        Researcher John Smith attributed the attack to a North Korean threat actor.
        Another group, LAPSUS$, was observed using RedLine Stealer to harvest credentials."""
        print(f"\n[*] Processing Text for DB: {text}")
        
        extract_and_store(source_id=1, cleaned_text=text)
        extract_and_store_ner(source_id=1, cleaned_text=text)
        
        print("\n[*] Connecting to SQLite DB to verify insertion...")
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute("SELECT entity_type, entity_value FROM entities;").fetchall()
        conn.close()
        
        print("[*] Raw SQLite Rows Found:")
        for row in rows:
            print(f"    -> {row}")
            
        self.assertGreater(len(rows), 0, "No records found in the entities table.")

if __name__ == "__main__":
    unittest.main(verbosity=2)