from __future__ import annotations

import feedparser
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from typing import Any
import hashlib

from collectors.base_collector import BaseCollector

# Well-known security RSS feeds — extend as needed
KNOWN_FEEDS: dict[str, str] = {
    "exploitdb":         "https://www.exploit-db.com/rss.xml",
    "bleeping_computer": "https://www.bleepingcomputer.com/feed/",
    "sans_isc":          "https://isc.sans.edu/rssfeed_full.xml",
    "packet_storm":      "https://rss.packetstormsecurity.com/files/",
}

class RSSCollector(BaseCollector):
    """
    Fetches threat intelligence from public RSS feeds.
    Defaults to Exploit-DB. No API key required.

    Fixes applied:
        FIX 1 — dedup_key is now present in every record automatically
                 because format_record() in BaseCollector generates it.
                 No code changes needed in this file.

    Note: RSS feeds have no server-side filtering API.
    Both fetch_by_time() and fetch_by_keyword() pull the full feed
    and filter client-side. Acceptable given typical feed sizes (50–200).
    """

    DEFAULT_DELAY = 2.0

    def __init__(self, feed_url: str = KNOWN_FEEDS["exploitdb"]) -> None:
        super().__init__(source_name="exploit-db")
        self.feed_url = feed_url

    # ── Task 1: fetch by time window ──────────────────────────────────────────

    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 200,
    ) -> list[dict[str, Any]]:
        """
        Fetch RSS entries within a time window.

        Examples:
            col.fetch_by_time()           # entries from last 7 days
            col.fetch_by_time(year=2023)  # entries published in 2023

        Filtering is client-side — the full feed is pulled then filtered
        by the parsed published date of each entry.
        """
        raw_entries = self._fetch_raw()

        if year is not None:
            filtered = [
                e for e in raw_entries
                if self._entry_year(e.get("published")) == year
            ]
        else:
            cutoff = datetime.now(timezone.utc).timestamp() - (days_back or 7) * 86400
            filtered = [
                e for e in raw_entries
                if self._entry_timestamp(e.get("published")) >= cutoff
            ]

        limited_raw = filtered[:max_results]
        return self.normalize(limited_raw)

    # ── Task 2: fetch by keyword ──────────────────────────────────────────────

    def fetch_by_keyword(
        self,
        query: str, 
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Search RSS entries by keyword in title or description.

        Matching behavior:
            - 'WannaCry'   → matches any entry mentioning WannaCry
            - 'wanna'      → partial match, case-insensitive
            - 'apache rce' → ALL words must appear (AND logic)

        Filtering is client-side — full feed is pulled then filtered.
        """
        raw_entries = self._fetch_raw()
        terms = query.strip().lower().split()

        filtered = [
            e for e in raw_entries
            if all(
                term in str(e.get("title", "")).lower() or term in str(e.get("summary", "")).lower()
                for term in terms
            )
        ]
        
        # CẮT LẤY MAX_RESULTS TRƯỚC KHI NORMALIZE VÀ SCRAPING
        limited_raw = filtered[:max_results]
        return self.normalize(limited_raw)

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, raw_data: list[Any]) -> list[dict[str, Any]]:
        records = []
        for entry in raw_data:
            link = entry.get("link")
            # RSS entries usually have an explicit 'id' or 'guid', fallback to link
            entry_id = entry.get("id") or link

            # --- SCRAPING FULL TEXT ---
            full_description = entry.get("summary") or entry.get("description")
            if link:
                try:
                    print(f"    [Scraping] Fetching full text from: {link}")
                    # Fetch the actual web page content
                    resp = requests.get(link, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        # Extract all text, strip HTML tags
                        scraped_text = soup.get_text(separator=' ', strip=True)
                        # Only use if it actually scraped meaningful content (longer than summary)
                        if len(scraped_text) > 100: 
                            full_description = scraped_text
                except Exception as e:
                    print(f"    [!] Scraping failed for {link}: {e}")
            # --------------------------------
            
            records.append(self.format_record(
                title          = entry.get("title"),
                description    = full_description,
                url            = link,
                published_date = entry.get("published"),
                raw            = {
                    "entry_id": entry_id 
                }
            ))
        return records

    # ── Override _make_dedup_key ──────────────────────────────────────────────
    def _make_dedup_key(self, title: str, description: str, raw: dict) -> str:
        """
        Override: Hash the immutable RSS entry ID or URL.
        This prevents dynamic website changes (like navbars) from altering the 
        hash and flooding the database with duplicates.
        """
        entry_id = raw.get("entry_id")
        
        if entry_id:
            content = f"{self.source_name}:id:{entry_id}"
        else:
            # Absolute fallback if feed is completely malformed
            content = f"{self.source_name}:{title}"
            
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    
    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch_raw(self) -> list[Any]:
        """Pull and parse the RSS feed. Returns feedparser entry objects."""
        feed = feedparser.parse(self.feed_url)
        if feed.bozo:
            print(f"[!] RSS parse warning: {feed.bozo_exception}")
        return feed.entries

    @staticmethod
    def _entry_timestamp(date_str: str) -> float:
        """Parse an RSS date string to a UTC Unix timestamp. Returns 0 on failure."""
        if not date_str:
            return 0.0
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str).timestamp()
        except Exception:
            return 0.0

    @staticmethod
    def _entry_year(date_str: str) -> int | None:
        """Extract the year from an RSS date string. Returns None on failure."""
        if not date_str:
            return None
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str).year
        except Exception:
            return None