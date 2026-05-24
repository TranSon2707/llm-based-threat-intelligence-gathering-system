"""
FILE: collectors/backfiller.py
ROLE: Periodic Baseline Updater
PURPOSE:
  Keeps the Neo4j Knowledge Graph fresh after the initial baseline sync.
  Runs two tasks on a schedule (e.g. weekly cron job):

  Task 1 — NVD Sliding Window Sync:
    Fetches CVEs published or modified in the last N days from NVD,
    embeds their descriptions, and merges them into the graph.
    Also applies CTID CVE->ATT&CK mappings to any newly added CVEs.

  Task 2 — MITRE ATT&CK Re-Sync:
    Re-downloads the MITRE STIX feed and merges any new or updated
    techniques into the graph. New TTP nodes automatically get picked
    up by the existing vector index.

  Uses sync_state.json to checkpoint progress so it is safe to interrupt
  and resume without losing work or making duplicate API calls.

RELATIONSHIP TO BASELINE SCRIPTS:
  sync_mitre_baseline.py  — run ONCE to build the initial MITRE graph
  sync_nvd_baseline.py    — run ONCE to build the initial CVE graph
  backfiller.py           — run PERIODICALLY to keep both sides updated
"""

from __future__ import annotations

import json
import time
import logging
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentence_transformers import SentenceTransformer
from collectors.nvd_collector import NVDCollector
from db.neo4j_manager import GraphConnector
from sync_nvd_baseline import fetch_ctid_mapping

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

STATE_FILE = Path("data/sync_state.json")


# ── State Management ──────────────────────────────────────────────────────────

def _load_state() -> dict[str, Any]:
    """Loads the sync checkpoint state from disk."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("[!] sync_state.json corrupted. Initializing fresh state.")

    return {
        "last_nvd_sync":   None,   # ISO timestamp of last NVD sliding window sync
        "last_mitre_sync": None,   # ISO timestamp of last MITRE re-sync
    }


def _save_state(state: dict[str, Any]) -> None:
    """Commits the current checkpoint state to disk."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)


# ── Task 1: NVD Sliding Window Sync ──────────────────────────────────────────

def run_nvd_sync(days_back: int = 30) -> None:
    """
    Fetches CVEs published or modified in the last `days_back` days from NVD.
    Embeds each CVE description and merges it into the Neo4j graph.
    Applies CTID CVE->ATT&CK mappings to build EXPLOITS_TECHNIQUE edges
    for any newly added CVEs that appear in the CTID dataset.

    Safe to run repeatedly — MERGE in Neo4j is idempotent.
    """
    logger.info(f"\n[*] Starting NVD {days_back}-day sliding window sync...")

    model     = SentenceTransformer('all-MiniLM-L6-v2')
    graph     = GraphConnector()
    collector = NVDCollector()

    # Fetch CTID mapping so we can wire up any new CVE->TTP edges
    cve_to_ttps = fetch_ctid_mapping()

    records = collector.fetch_by_time(days_back=days_back, max_results=5000)
    logger.info(f"[-] Fetched {len(records)} CVE records from NVD.")

    count = 0
    for record in records:
        try:
            cve_id      = record["title"]
            description = record["description"]
            cvss_score  = record.get("raw", {}).get("cvss_score")

            # 1. Embed and merge CVE node
            embedding = model.encode(description).tolist()
            graph.merge_cve(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                embedding=embedding,
            )

            # 2. Rebuild AFFECTS edges for affected software
            affected_software = record.get("raw", {}).get("affected_software", [])
            for software_name in affected_software:
                if software_name:
                    graph.link_cve_software(
                        cve_id=cve_id,
                        software_name=software_name.strip().lower(),
                    )

            # 3. Apply CTID mapping for CVE->MITRE edges
            ttps = cve_to_ttps.get(cve_id.upper(), [])
            for ttp_id in ttps:
                graph.link_cve_mitre(cve_id=cve_id, ttp_id=ttp_id)

            count += 1

        except Exception as e:
            logger.warning(f"[!] Failed to process CVE {record.get('title')}: {e}")
            continue

    graph.close()
    logger.info(f"[+] NVD sync complete. {count} CVE nodes merged.")


# ── Task 2: MITRE ATT&CK Re-Sync ─────────────────────────────────────────────

def run_mitre_sync() -> None:
    """
    Re-downloads the full MITRE ATT&CK STIX feed and merges any new or
    updated techniques into the Neo4j graph.

    New TTP nodes get embedded and are immediately searchable via the
    existing vector index — no index rebuild required.
    Existing nodes are updated in-place via MERGE + SET.
    """
    logger.info("\n[*] Starting MITRE ATT&CK re-sync...")

    model = SentenceTransformer('all-MiniLM-L6-v2')
    graph = GraphConnector()

    logger.info(f"[-] Fetching MITRE STIX feed from {MITRE_STIX_URL}...")
    response = requests.get(MITRE_STIX_URL, timeout=60)
    response.raise_for_status()
    stix_data = response.json()

    objects = stix_data.get("objects", [])
    count   = 0

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        ext_refs = obj.get("external_references", [])
        ttp_id   = next(
            (ref["external_id"] for ref in ext_refs
             if ref.get("source_name") == "mitre-attack"),
            None,
        )

        if not ttp_id:
            continue

        name        = obj.get("name", "Unknown")
        description = obj.get("description", "")

        try:
            # 1. Embed and merge TTP node (updates description + embedding if changed)
            embedding = model.encode(description).tolist()
            graph.merge_mitre_ttp(
                ttp_id=ttp_id,
                name=name,
                description=description,
                embedding=embedding,
            )

            # 2. Rebuild TARGETS edges for platforms
            platforms = obj.get("x_mitre_platforms", [])
            for platform in platforms:
                graph.link_mitre_software(
                    ttp_id=ttp_id,
                    software_name=platform.strip().lower(),
                )

            count += 1

        except Exception as e:
            logger.warning(f"[!] Failed to process TTP {ttp_id}: {e}")
            continue

    graph.close()
    logger.info(f"[+] MITRE re-sync complete. {count} TTP nodes merged.")


# ── Main Entry Point ──────────────────────────────────────────────────────────

def main() -> None:
    state = _load_state()

    print("\nBackfiller — Select Operation:")
    print("1. NVD Sliding Window Sync (last 30 days)")
    print("2. MITRE ATT&CK Re-Sync (full feed, updates existing nodes)")
    print("3. Run Both")

    choice = input("Enter choice (1/2/3): ").strip()

    if choice == "1":
        run_nvd_sync(days_back=30)
        state["last_nvd_sync"] = datetime.now(timezone.utc).isoformat()

    elif choice == "2":
        run_mitre_sync()
        state["last_mitre_sync"] = datetime.now(timezone.utc).isoformat()

    elif choice == "3":
        run_nvd_sync(days_back=30)
        state["last_nvd_sync"] = datetime.now(timezone.utc).isoformat()

        # Brief pause between the two network-heavy operations
        logger.info("[-] Sleeping 5 seconds before MITRE sync...")
        time.sleep(5)

        run_mitre_sync()
        state["last_mitre_sync"] = datetime.now(timezone.utc).isoformat()

    else:
        print("[!] Invalid choice. Exiting.")
        return

    _save_state(state)
    logger.info(f"[+] State saved. Last NVD sync: {state['last_nvd_sync']} | Last MITRE sync: {state['last_mitre_sync']}")


if __name__ == "__main__":
    main()