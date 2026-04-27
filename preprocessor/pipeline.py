import yaml
import logging
import argparse
import sys
import json
from preprocessor.html_stripper import strip_html
from preprocessor.encapsulator import build_langchain_prompt

# Ensure langchain_community is installed: pip install langchain-community
from langchain_community.chat_models import ChatOllama

try:
    from db.queries import get_unprocessed_batch, mark_processed, insert_report
except ImportError as e:
    logging.error(f"Database import failed: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def load_settings(config_path):
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logger.warning(f"Config file {config_path} not found. Using defaults.")
        return {}

def extract_cve_id(item: dict) -> str:
    """Extracts the CVE ID based on the source's specific schema."""
    source = item.get('source', '')
    
    if source == 'nvd':
        return item.get('title', '')
    
    if source == 'alienvault':
        try:
            raw_data = json.loads(item.get('raw', '{}'))
            return raw_data.get('linked_cve', '')
        except json.JSONDecodeError:
            return ''
            
    return ''

def run_pipeline():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='settings.yaml')
    args = parser.parse_args()

    settings = load_settings(args.config)
    batch_size = settings.get('preprocessing', {}).get('batch_size', 10)
    
    logger.info(f"[*] Waking up pipeline. Fetching batch of {batch_size}...")

    raw_items = get_unprocessed_batch(batch_size=batch_size)
    if not raw_items:
        logger.info("[+] Database is fully processed. No new items found.")
        return

    llm = ChatOllama(model="llama3", temperature=0.2)
    processed_count = 0

    for item in raw_items:
        item_id = item.get('id')
        title = item.get('title', 'Unknown Threat')
        content = item.get('description', '')
        
        cve_id = extract_cve_id(item)
        clean_text = strip_html(content)

        logger.info(f"[*] Analyzing: {title}...")

        messages = build_langchain_prompt(clean_text)
        
        try:
            response = llm.invoke(messages)
            report_summary = response.content
            
            insert_report(source_id=item_id, summary=report_summary)
            mark_processed(item_id)
            processed_count += 1
            
            logger.info(f"[+] Successfully generated and saved report for ID {item_id}")
            
        except Exception as e:
            logger.error(f"[!] LLM Execution failed for ID {item_id}: {e}")

    logger.info(f"\n[=] Pipeline Complete. Processed: {processed_count}")

if __name__ == '__main__':
    run_pipeline()