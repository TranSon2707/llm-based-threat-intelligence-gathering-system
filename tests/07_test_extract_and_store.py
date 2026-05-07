from db.db import init_db
from enrichment.entity_extractor import extract_and_store
from enrichment.ner_spacy import extract_and_store_ner

# This is a simple integration test for the NER extraction and storage logic.
# run by executing: python -m tests.07_test_extract_and_store
# then verify database by executing sqlite3 db/threat_intel.db "SELECT * FROM entities; # not running at the moment
# enrichment test



# Fresh DB
init_db()

# Pretend source_id=1 already exists in raw_items (or insert a dummy first)
text = "Lazarus Group exploited CVE-2021-44228 from 10.0.0.5. Payload: WannaCry."

entities   = extract_and_store(source_id=1, cleaned_text=text)
ner_hits   = extract_and_store_ner(source_id=1, cleaned_text=text)

print("Regex entities:", entities)
print("NER entities:  ", ner_hits)


# Verify the entities were stored in the DB (requires sqlite3 CLI tool but I no download)
import sqlite3
from db.db import DB_PATH

connect = sqlite3.connect(DB_PATH) # connect to DB file
rows = connect.execute("SELECT * FROM entities;").fetchall()
for row in rows:
    print(row)
connect.close()