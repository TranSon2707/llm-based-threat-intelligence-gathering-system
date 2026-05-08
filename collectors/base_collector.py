from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class BaseCollector(ABC):
    """
    Abstract base class for all threat intelligence collectors.
    Every subclass must implement fetch_by_time(), fetch_by_keyword(),
    and normalize().
    """

    DEFAULT_DELAY: float = 1.0  # seconds between requests, overridden per subclass

    def __init__(self, source_name: str) -> None:
        self.source_name = source_name
        self._last_request: float = 0.0

    # ── Abstract interface ────────────────────────────────────────────────────

    @abstractmethod
    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 200,
    ) -> list[dict[str, Any]]:
        """
        Task 1 — Fetch records within a time window.

        Two modes (mutually exclusive, year takes priority if both given):
          - days_back : last N days rolling from now  (default 7)
          - year      : full calendar year, e.g. 2021

        Returns a list of normalized record dicts ready for DB insert.
        """
        pass

    @abstractmethod
    def fetch_by_keyword(
        self,
        query: str,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Task 2 — Search by keyword, phrase, or CVE ID.

          - Plain word   'wannacry'       → fuzzy full-text search
          - Phrase       'apache log4j'   → both words must appear
          - Partial      'wanna'          → still matches WannaCry
          - CVE ID       'CVE-2021-44228' → exact-ID endpoint (NVD) or
                                            full-text (OTX / RSS)
          - Multi-word   'log4shell rce'  → AND logic on RSS
        """
        pass

    @abstractmethod
    def normalize(self, raw_data: list[Any]) -> list[dict[str, Any]]:
        """
        Convert raw API response objects into standard record dicts.
        Must call self.format_record() for every item.
        """
        pass

    def collect_and_store(
        self,
        db_path: Path,     
        mode: str = "time", 
        **fetch_kwargs: Any,
    ) -> tuple[int, int]:
        """
        Chains fetch → DB insert in one call.

        Args:
            db_path      : path to the SQLite database file.
            mode         : 'time'    → calls fetch_by_time(**fetch_kwargs)
                           'keyword' → calls fetch_by_keyword(**fetch_kwargs)
            fetch_kwargs : forwarded directly to the chosen fetch method.

        Returns:
            (inserted, skipped)
                inserted — new records written to DB.
                skipped  — duplicates blocked by dedup_key UNIQUE constraint.

        Usage by preprocessor/pipeline.py:
            nvd.collect_and_store(DB_PATH, mode="time", days_back=7)
            nvd.collect_and_store(DB_PATH, mode="time", year=2021,
                                  cvss_severity="CRITICAL")
            otx.collect_and_store(DB_PATH, mode="keyword", query="WannaCry")
        """
        if mode == "keyword":
            records = self.fetch_by_keyword(**fetch_kwargs)
        else:
            records = self.fetch_by_time(**fetch_kwargs)

        inserted = skipped = 0

        with _db_connection(db_path) as conn:
            for record in records:
                try:
                    conn.execute(
                        """
                        INSERT INTO raw_items
                            (source, title, description, source_url,
                             published_date, collected_at, processed,
                             raw, dedup_key)
                        VALUES
                            (:source, :title, :description, :source_url,
                             :published_date, :collected_at, :processed,
                             :raw, :dedup_key)
                        """,
                        {**record, "raw": json.dumps(record.get("raw", {}))},
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    # UNIQUE constraint on dedup_key — genuine duplicate, skip
                    skipped += 1

        print(
            f"[{self.source_name}] stored {inserted} new record(s), "
            f"skipped {skipped} duplicate(s)."
        )
        return inserted, skipped

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _throttle(self) -> None:
        """Enforce minimum delay between HTTP requests."""
        elapsed = time.time() - self._last_request
        if elapsed < self.DEFAULT_DELAY:
            time.sleep(self.DEFAULT_DELAY - elapsed)
        self._last_request = time.time()

    def format_record(
        self,
        title: str | None,
        description: str | None,
        url: str | None,
        published_date: str | None,
        raw: dict | None = None,
    ) -> dict[str, Any]:
        """
        Produces the standard DB-ready dict every collector must output.

        dedup_key field:
            Computed as SHA-256(source + title + description[:300]).
            Truncating description to 300 chars keeps the hash stable even
            when a source appends trailing metadata on repeat fetches.

            Same CVE arriving from NVD and OTX → two distinct dedup_keys
            (source is part of the hash) → both records kept, which is correct
            because they carry different metadata (CVSS vs IOC counts).
        """
        clean_title = title.strip() if title else "No Title"
        clean_desc  = description.strip() if description else "No Description"

        return {
            "source":         self.source_name,
            "title":          clean_title,
            "description":    clean_desc,
            "source_url":     url or "",
            "published_date": published_date or "",
            "collected_at":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "processed":      0,
            "raw":            raw or {},
            "dedup_key":      self._make_dedup_key(clean_title, clean_desc),
        }

    def _make_dedup_key(self, title: str, description: str) -> str:
        """SHA-256 fingerprint."""
        content = f"{self.source_name}:{title}:{description[:300]}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ── Internal DB helper ────────────────────────────────────────────────────────

@contextmanager
def _db_connection(db_path: Path):
    """
    Minimal connection context used only by collect_and_store().
    The full query interface lives in db/queries.py.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close() 