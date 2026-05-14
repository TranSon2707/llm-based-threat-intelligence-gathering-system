from __future__ import annotations

import os
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from collectors.nvd_collector import NVDCollector
from db.graph_connector import GraphConnector

# In a real run, you would import the embedding service here
# from enrichment.embedding_service import EmbeddingService

class BaselineSyncManager:
    """
    Manages asynchronous temporal backfilling of NVD baseline data.
    Uses sync_state.json to checkpoint progress, preventing data loss 
    or redundant API calls upon script restart.
    """

    STATE_FILE = Path("data/sync_state.json")
    EARLIEST_YEAR = 1999

    def __init__(self):
        self.nvd = NVDCollector()
        self.graph_db = GraphConnector()
        # self.embedder = EmbeddingService()
        
        # Ensure data directory exists
        self.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        """Loads the backfill checkpoint state from disk."""
        if self.STATE_FILE.exists():
            try:
                with open(self.STATE_FILE, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print("[!] sync_state.json corrupted. Initializing fresh state.")
        
        # Default state if file doesn't exist
        return {
            "nvd_backfill": {
                "target_year": datetime.now(timezone.utc).year,
                "completed_years": [],
                "status": "pending" # pending | in_progress | complete
            },
            "last_daily_sync": None
        }

    def _save_state(self) -> None:
        """Commits the current state to disk."""
        with open(self.STATE_FILE, "w") as f:
            json.dump(self.state, f, indent=4)

    # ── Task 1: Daily Sliding Window Sync ─────────────────────────────────────

    def run_sync(self) -> tuple[list[dict], str]:
        """
        Executes a 30-day sliding window sync. Used for daily cron jobs 
        to keep the graph updated with newly published or modified CVEs.
        """
        print("\n[*] Starting Daily 30-Day NVD Sync...")
        
        # Fetch the last 30 days of data
        records = self.nvd.fetch_by_time(days_back=30, max_results=5000)
        
        inserted_count = 0
        for record in records:
            # 1. Generate 768-dim Vector Embedding for GraphRAG
            # vector = self.embedder.generate_embedding(record["description"])
            
            # 2. Inject into Neo4j Graph
            # Note: In production, you would extract entities first. 
            # For baseline CVEs, the entity is the CVE itself.
            mock_entities = {"CVE": [record["title"]], "Indicators": [], "ThreatActor": []}
            self.graph_db.insert_threat_intel(record, mock_entities)
            inserted_count += 1

        self.state["last_daily_sync"] = datetime.now(timezone.utc).isoformat()
        self._save_state()
        
        msg = f"Daily sync complete. Processed {inserted_count} records."
        print(f"[+] {msg}")
        return records, msg

    # ── Task 2: Historical Year-by-Year Backfill ──────────────────────────────

    def run_backfill(self) -> None:
        """
        Long-running worker that backfills CVEs year-by-year down to 1999.
        Safe to interrupt (Ctrl+C); state is saved after every successful chunk.
        """
        backfill_state = self.state["nvd_backfill"]
        
        if backfill_state["status"] == "complete":
            print("[*] NVD Historical Backfill is already complete.")
            return

        backfill_state["status"] = "in_progress"
        self._save_state()

        current_year = backfill_state["target_year"]
        
        print(f"\n[*] Starting NVD Historical Backfill (Targeting {current_year} -> {self.EARLIEST_YEAR})")

        while current_year >= self.EARLIEST_YEAR:
            if current_year in backfill_state["completed_years"]:
                current_year -= 1
                continue

            print(f"\n[-] Fetching baseline data for year: {current_year}")
            
            try:
                # NVD limits date ranges to 120 days per request. 
                # The NVDCollector.fetch_by_time handles this, but here we process the whole year.
                records = self.nvd.fetch_by_time(year=current_year, max_results=10000)
                
                print(f"[-] Processing {len(records)} CVEs for {current_year} into Knowledge Graph...")
                for record in records:
                    # Phase 2 GraphRAG Flow: 
                    # 1. Embed text
                    # 2. Extract Entities
                    # 3. MERGE to Neo4j
                    mock_entities = {"CVE": [record["title"]], "Indicators": [], "ThreatActor": []}
                    self.graph_db.insert_threat_intel(record, mock_entities)
                
                # Checkpoint Success
                backfill_state["completed_years"].append(current_year)
                backfill_state["target_year"] = current_year - 1
                self._save_state()
                print(f"[+] Year {current_year} safely checkpointed.")

                # Safety sleep to prevent aggressive rate limiting bans from NIST
                print("[-] Sleeping for 10 seconds before next year chunk...")
                time.sleep(10)

            except Exception as e:
                print(f"[!] Backfill interrupted during {current_year}: {e}")
                print("[!] Saving state and exiting gracefully. Run script again to resume.")
                break
                
            current_year -= 1

        # Check if we finished the entire historical run
        if backfill_state["target_year"] < self.EARLIEST_YEAR:
            backfill_state["status"] = "complete"
            self._save_state()
            print("\n[+] FULL HISTORICAL NVD BACKFILL COMPLETE (1999 - Present).")


if __name__ == "__main__":
    manager = BaselineSyncManager()
    
    # You can choose which operation to run here
    print("Select Operation:")
    print("1. Daily Sliding Window Sync (Last 30 Days)")
    print("2. Full Historical Backfill (Year-by-Year to 1999)")
    
    choice = input("Enter choice (1/2): ")
    if choice == "1":
        manager.run_sync()
    elif choice == "2":
        manager.run_backfill()
    else:
        print("Invalid choice.")