"""
=============================================================================
FILE: preprocessor/pipeline.py
ROLE: Data Sanitization Orchestrator
=============================================================================
PURPOSE:
Retrieves raw records from the database, sanitizes HTML, encapsulates the text 
for prompt injection defense, and marks items as processed. 
NO LLM INFERENCE OCCURS HERE. The sanitized data is passed to the Enrichment layer.
"""
import logging
import sys

from preprocessor.html_stripper import strip_html
from preprocessor.encapsulator import encapsulate_threat_data

try:
    from db.queries import get_unprocessed_batch, mark_processed
except ImportError as e:
    print(f"Database import failed: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def run_preprocessing_batch(batch_size: int = 10) -> list:
    """
    Executes the preprocessing pipeline for a specific batch size.
    Returns a list of dictionaries containing the sanitized items.
    """
    logger.info(f"[*] Waking up Preprocessor. Fetching batch of {batch_size}...")

    raw_items = get_unprocessed_batch(batch_size=batch_size)
    if not raw_items:
        logger.info("[+] Database is fully processed. No new items found.")
        return []

    processed_results = []
    
    for item in raw_items:
        item_id = item.get('id')
        title = item.get('title', 'Unknown')
        content = item.get('description', '')

        logger.info(f"[*] Sanitizing Item ID {item_id}: {title}...")

        # 1. Strip HTML tags
        clean_text = strip_html(content)

        # 2. Encapsulate with XML tags to prevent Prompt Injection
        secured_text = encapsulate_threat_data(clean_text)

        # 3. Mark as processed in the database
        mark_processed(item_id)

        # Store results for the next pipeline stage (Enrichment)
        processed_results.append({
            "source_id": item_id,
            "title": title,
            "raw_text": content,
            "cleaned_text": clean_text,
            "secured_text": secured_text
        })
        
    logger.info(f"[=] Preprocessing Complete. Sanitized {len(processed_results)} items.")
    return processed_results
