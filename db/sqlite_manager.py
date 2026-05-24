import sqlite3
import logging
from pathlib import Path
from contextlib import contextmanager
from db.queries import (
    INSERT_RAW_ITEM, 
    GET_UNPROCESSED_BATCH, 
    MARK_PROCESSED, 
    INSERT_ENTITY, 
    INSERT_REPORT,
    GET_ENTITIES_BY_SOURCE,
    GET_REPORT
)

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "threat_intel.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

@contextmanager
def get_db_connection():
    """Provides a safe connection context for SQLite, yielding dictionary-like rows."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()

def init_db():
    """Reads schema.sql and initializes the database tables during system boot."""
    if not SCHEMA_PATH.exists():
        logger.error(f"Schema file not found at {SCHEMA_PATH}")
        return

    with open(SCHEMA_PATH, "r") as f:
        schema_script = f.read()

    with get_db_connection() as conn:
        conn.executescript(schema_script)
    logger.info("SQLite database initialized successfully.")

def insert_raw_item(data: tuple) -> int:
    """Inserts a scraped OSINT post. Returns the primary key ID."""
    with get_db_connection() as conn:
        cursor = conn.execute(INSERT_RAW_ITEM, data)
        return cursor.lastrowid

def get_unprocessed_batch(limit: int = 10) -> list:
    """Fetches raw records for the preprocessing pipeline to sanitize."""
    with get_db_connection() as conn:
        cursor = conn.execute(GET_UNPROCESSED_BATCH, (limit,))
        return [dict(row) for row in cursor.fetchall()]

def mark_processed(item_id: int):
    """Flags a raw item as securely sanitized and ready for enrichment."""
    with get_db_connection() as conn:
        conn.execute(MARK_PROCESSED, (item_id,))

def insert_entity(source_id: int, entity_type: str, entity_value: str):
    """Stores hard IOCs or soft entities extracted via regex/spaCy."""
    with get_db_connection() as conn:
        conn.execute(INSERT_ENTITY, (source_id, entity_type, entity_value))

def get_entities(source_id: int) -> list:
    """Retrieves all entities associated with a specific raw item."""
    with get_db_connection() as conn:
        cursor = conn.execute(GET_ENTITIES_BY_SOURCE, (source_id,))
        return [dict(row) for row in cursor.fetchall()]

def insert_report(data: tuple):
    """Saves the final generated LLM intelligence report."""
    with get_db_connection() as conn:
        conn.execute(INSERT_REPORT, data)

def get_report(source_id: int) -> dict:
    """Fetches a saved report by its source ID."""
    with get_db_connection() as conn:
        cursor = conn.execute(GET_REPORT, (source_id,))
        row = cursor.fetchone()
        return dict(row) if row else None