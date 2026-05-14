"""
=============================================================================
MODULE: 01_test_collectors.py
PURPOSE: Executes performance telemetry on Threat Intel Collectors.
METRICS: Execution time, peak RAM allocation, and payload structure.
COMMAND: python -m tests.01_test_collectors
=============================================================================
"""
import os
import time
import tracemalloc
import json
from dotenv import load_dotenv, find_dotenv

from collectors.nvd_collector import NVDCollector
from collectors.otx_collector import OTXCollector
from collectors.rss_collector import RSSCollector
from collectors.reddit_collector import RedditCollector

# Force load .env
load_dotenv(find_dotenv())

def run_profiler(collector, mode="time", **kwargs):
    print(f"\n{'-'*60}")
    print(f"[*] Profiling {collector.source_name.upper()} | Mode: {mode.upper()}")
    print(f"[-] Args: {kwargs}")
    
    # Start telemetry
    tracemalloc.start()
    start_time = time.perf_counter()
    
    try:
        if mode == "time":
            results = collector.fetch_by_time(**kwargs)
        elif mode == "keyword":
            results = collector.fetch_by_keyword(**kwargs)
        else:
            results = []
            
    except Exception as e:
        print(f"[!] Execution failed: {e}")
        results = []
        
    # Stop telemetry
    end_time = time.perf_counter()
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    # Calculate metrics
    total_time = end_time - start_time
    peak_ram_mb = peak_mem / (1024 * 1024)
    item_count = len(results)
    time_per_item = total_time / item_count if item_count > 0 else 0
    
    # Print Telemetry Report
    print(f"\n[+] TELEMETRY REPORT:")
    print(f"    Total Items Collected : {item_count}")
    print(f"    Total Execution Time  : {total_time:.4f} seconds")
    print(f"    Avg Time Per Item     : {time_per_item:.4f} seconds")
    print(f"    Peak RAM Allocated    : {peak_ram_mb:.4f} MB")
    
    # Print Data Structure Verification
    if item_count > 0:
        print("\n[+] DATA STRUCTURE (First Item Preview):")
        # Print a formatted JSON snippet of the first item to verify the schema
        sample = results[0]
        # Truncate description for terminal readability
        if len(sample.get("description", "")) > 150:
            sample["description"] = sample["description"][:150] + "... [TRUNCATED]"
            
        print(json.dumps(sample, indent=2))
    else:
        print("\n[!] No data collected to preview.")

if __name__ == "__main__":
    print("="*60)
    print("[DEBUG] ENVIRONMENT VERIFICATION")
    print(f"NVD_API_KEY: {'[SET]' if os.getenv('NVD_API_KEY') else '[MISSING]'}")
    print(f"OTX_API_KEY: {'[SET]' if os.getenv('OTX_API_KEY') else '[MISSING]'}")
    # <-- ADDED REDDIT ENV CHECKS -->
    print(f"REDDIT_CLIENT_ID: {'[SET]' if os.getenv('REDDIT_CLIENT_ID') else '[MISSING]'}")
    print(f"REDDIT_CLIENT_SECRET: {'[SET]' if os.getenv('REDDIT_CLIENT_SECRET') else '[MISSING]'}")
    print("="*60)

    # Instantiate collectors
    nvd = NVDCollector()
    otx = OTXCollector()
    rss = RSSCollector()
    reddit = RedditCollector()  # <-- ADDED

    # Define test parameters
    TEST_MAX_RESULTS = 5
    TEST_KEYWORD = "ransomware"

    # Profile RSS
    run_profiler(rss, mode="time", days_back=7, max_results=TEST_MAX_RESULTS)
    
    # Profile NVD
    run_profiler(nvd, mode="keyword", query=TEST_KEYWORD, max_results=TEST_MAX_RESULTS)
    
    # Profile OTX
    run_profiler(otx, mode="keyword", query=TEST_KEYWORD, max_results=TEST_MAX_RESULTS)
    
    # Profile Reddit
    run_profiler(reddit, mode="keyword", query=TEST_KEYWORD, max_results=TEST_MAX_RESULTS)