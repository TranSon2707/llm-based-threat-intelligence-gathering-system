import json
import os
from dotenv import load_dotenv

# Load environment variables (API keys)
load_dotenv()

from collectors.nvd_collector import NVDCollector
from collectors.otx_collector import OTXCollector
from collectors.rss_collector import RSSCollector

def test_collector(collector, test_keyword="wannacry"):
    print(f"\n{'='*60}")
    print(f"[*] Testing {collector.__class__.__name__} ({collector.source_name})")
    print(f"{'='*60}")

    # --- Test 1: Time-based fetching ---
    print("\n[+] Test 1: fetch_by_time (last 7 days, max 2 results)")
    time_results = collector.fetch_by_time(days_back=7, max_results=2)
    
    if time_results:
        print(f"  -> Successfully retrieved {len(time_results)} records.")
        print("  -> Sample Output (First Record):")
        print(json.dumps(time_results[0], indent=4))
    else:
        print("  -> [-] No records found or request failed.")

    # --- Test 2: Keyword fetching ---
    print(f"\n[+] Test 2: fetch_by_keyword (query: '{test_keyword}', max 2 results)")
    keyword_results = collector.fetch_by_keyword(query=test_keyword, max_results=2)
    
    if keyword_results:
        print(f"  -> Successfully retrieved {len(keyword_results)} records.")
        print("  -> Sample Output (First Record):")
        print(json.dumps(keyword_results[0], indent=4))
    else:
        print("  -> [-] No records found or request failed.")

if __name__ == "__main__":
    print("[*] Initializing test suite for all collectors...")
    
    # Instantiate all collectors. They will automatically look for API keys in the environment.
    # We test RSS first because it's the fastest and requires no keys.
    collectors = [
        RSSCollector(),
        NVDCollector(),
        OTXCollector()
    ]

    for col in collectors:
        test_collector(col, test_keyword="ransomware")