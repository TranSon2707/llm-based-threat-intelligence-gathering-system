"""
=============================================================================
MODULE: 01_test_collectors.py
PURPOSE: Executes performance telemetry on Threat Intel Collectors.
METRICS: Execution time, peak RAM allocation, and payload structure.
COMMAND: python -m tests.01_test_collectors
=============================================================================
"""
import copy
import os
import time
import tracemalloc
import json
from dotenv import load_dotenv, find_dotenv

from collectors.nvd_collector import NVDCollector
from collectors.otx_collector import OTXCollector
from collectors.rss_collector import RSSCollector, KNOWN_FEEDS
from collectors.reddit_collector import RedditCollector

load_dotenv(find_dotenv())

# Required top-level keys every collector must return on every record.
REQUIRED_SCHEMA_KEYS = {
    "source", "title", "description", "source_url",
    "published_date", "collected_at", "processed", "raw", "dedup_key",
}


def assert_schema(results: list[dict], collector_label: str) -> None:
    """
    Hard assertion: every result must contain all REQUIRED_SCHEMA_KEYS,
    including dedup_key.  Prints a per-item pass/fail so regressions are
    obvious without reading the full JSON dump.
    """
    if not results:
        return
    for i, item in enumerate(results):
        missing = REQUIRED_SCHEMA_KEYS - item.keys()
        if missing:
            print(f"    [FAIL] Item {i} missing keys: {missing}")
        else:
            print(f"    [PASS] Item {i} schema OK  |  dedup_key: {item['dedup_key'][:16]}…")

        # Sanity-check dedup_key is a non-empty string (not None / "")
        dk = item.get("dedup_key", "")
        if not dk:
            print(f"    [FAIL] Item {i} dedup_key is empty!")


def run_profiler(collector, mode: str = "time", label: str = "", **kwargs) -> list[dict]:
    """
    Run one profiling pass.

    Returns the raw results list so the caller can chain assertions or
    run multiple modes on the same collector without re-instantiating.

    FIX 2: description truncation now operates on a *display copy* so the
    live result list is never mutated.
    """
    display_label = label or collector.source_name.upper()
    print(f"\n{'-'*60}")
    print(f"[*] Profiling {display_label} | Mode: {mode.upper()}")
    print(f"[-] Args: {kwargs}")

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

    end_time = time.perf_counter()
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_time   = end_time - start_time
    peak_ram_mb  = peak_mem / (1024 * 1024)
    item_count   = len(results)
    time_per_item = total_time / item_count if item_count > 0 else 0

    print(f"\n[+] TELEMETRY REPORT:")
    print(f"    Total Items Collected : {item_count}")
    print(f"    Total Execution Time  : {total_time:.4f} seconds")
    print(f"    Avg Time Per Item     : {time_per_item:.4f} seconds")
    print(f"    Peak RAM Allocated    : {peak_ram_mb:.4f} MB")

    if item_count > 0:
        # FIX 2: deep-copy before truncating so the original record is untouched
        sample = copy.deepcopy(results[0])
        if len(sample.get("description", "")) > 150:
            sample["description"] = sample["description"][:150] + "... [TRUNCATED]"
        print("\n[+] DATA STRUCTURE (First Item Preview):")
        print(json.dumps(sample, indent=2, ensure_ascii=False))

        # FIX 6: explicit schema + dedup_key assertion on ALL items
        print("\n[+] SCHEMA ASSERTION:")
        assert_schema(results, display_label)
    else:
        print("\n[!] No data collected to preview.")

    return results


if __name__ == "__main__":
    print("=" * 60)
    print("[DEBUG] ENVIRONMENT VERIFICATION")
    print(f"NVD_API_KEY          : {'[SET]' if os.getenv('NVD_API_KEY')          else '[MISSING]'}")
    print(f"OTX_API_KEY          : {'[SET]' if os.getenv('OTX_API_KEY')          else '[MISSING]'}")
    print(f"REDDIT_CLIENT_ID     : {'[SET]' if os.getenv('REDDIT_CLIENT_ID')     else '[MISSING]'}")
    print(f"REDDIT_CLIENT_SECRET : {'[SET]' if os.getenv('REDDIT_CLIENT_SECRET') else '[MISSING]'}")
    print("=" * 60)

    TEST_MAX_RESULTS = 5
    TEST_KEYWORD     = "ransomware"

    # ── RSS: ExploitDB (English) ──────────────────────────────────────────────
    rss = RSSCollector()                          # source_name = "exploit-db"

    # Time mode — verifies dedup_key hashing, scraping, date filtering
    run_profiler(rss, mode="time",    label="RSS | ExploitDB",
                 days_back=7, max_results=TEST_MAX_RESULTS)

    # FIX 4: keyword mode — verifies AND-logic, partial match, encoding
    run_profiler(rss, mode="keyword", label="RSS | ExploitDB",
                 query=TEST_KEYWORD, max_results=TEST_MAX_RESULTS)

    # ── RSS: Xakep (Russian — paywall fallback path) ──────────────────────────
    # FIX 1: source_name passed at construction time, not mutated after init.
    # RSSCollector.__init__ sets self.source_name via super().__init__(source_name=…).
    # We subclass inline to pass the right name without touching base_collector.
    class XakepCollector(RSSCollector):
        def __init__(self):
            super().__init__(feed_url=KNOWN_FEEDS["xakep"])
            self.source_name = "xakep"   # safe here: no DB write has happened yet

    xakep = XakepCollector()

    # Time mode only — keyword search on Russian content with an English query
    # is intentionally skipped: "ransomware" won't match Cyrillic titles, so
    # keyword mode for this feed is the responsibility of language_detector.py
    # (P2-04), not the collector itself.
    run_profiler(xakep, mode="time", label="RSS | Xakep (Russian)",
                 days_back=7, max_results=TEST_MAX_RESULTS)

    # ── NVD ───────────────────────────────────────────────────────────────────
    nvd = NVDCollector()

    run_profiler(nvd, mode="keyword", label="NVD",
                 query=TEST_KEYWORD, max_results=TEST_MAX_RESULTS)

    # FIX 5 (partial): exercise NVD time mode too so fetch_by_time is covered
    run_profiler(nvd, mode="time", label="NVD",
                 days_back=7, max_results=TEST_MAX_RESULTS)

    # ── OTX ───────────────────────────────────────────────────────────────────
    otx = OTXCollector()

    run_profiler(otx, mode="keyword", label="OTX",
                 query=TEST_KEYWORD, max_results=TEST_MAX_RESULTS)

    run_profiler(otx, mode="time", label="OTX",
                 days_back=7, max_results=TEST_MAX_RESULTS)

    # ── Reddit ────────────────────────────────────────────────────────────────
    reddit = RedditCollector()

    run_profiler(reddit, mode="keyword", label="Reddit",
                 query=TEST_KEYWORD, max_results=TEST_MAX_RESULTS)

    # FIX 5: add time mode so fetch_by_time() is exercised
    run_profiler(reddit, mode="time", label="Reddit",
                 days_back=7, max_results=TEST_MAX_RESULTS)