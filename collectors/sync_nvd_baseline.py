"""
FILE: collectors/sync_nvd_baseline.py
ROLE: Graph Baseline Builder (Phase 0) — NVD Side
PURPOSE:
  1. Fetches CVE data from NVD year-by-year (1999 -> present) and pushes
     CVE nodes + AFFECTS edges into Neo4j.
  2. Downloads the CTID (Center for Threat-Informed Defense) public CVE->ATT&CK
     mapping file and builds hard CVE -[:EXPLOITS_TECHNIQUE]-> MITRE_TTP edges.

WHY CTID?
  The official NVD API maps CVEs to CWE weakness IDs, NOT to MITRE ATT&CK techniques.
  CTID publishes and maintains a curated, authoritative JSON mapping of CVE IDs directly
  to ATT&CK technique IDs (e.g. CVE-2021-44228 -> T1190). This is the most direct and
  reliable source for building these hard edges without guessing.

CHECKPOINT SYSTEM:
  Progress is saved to data/nvd_sync_state.json after every successfully completed year.
  Failed years are recorded separately so they can be retried without redoing
  everything. On any subsequent run the script automatically skips completed years
  and can optionally retry only the failed ones.

  State file structure:
  {
      "completed_years": [1999, 2000, ...],
      "failed_years":    { "2003": "NVD timeout", ... },
      "last_run":        "2026-05-24T10:00:00+00:00"
  }

RUN ORDER (first-time setup):
  1. sync_mitre_baseline.py   (builds MITRE_TTP nodes + vector index)
  2. sync_nvd_baseline.py     (builds CVE nodes + AFFECTS + EXPLOITS_TECHNIQUE edges)

USAGE:
  python sync_nvd_baseline.py          # normal run  (skips completed, skips failed)
  python sync_nvd_baseline.py --retry  # retry previously failed years only
  python sync_nvd_baseline.py --reset  # wipe state and start completely fresh
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import requests
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
from db.neo4j_manager import GraphConnector
from collectors.nvd_collector import NVDCollector

# Load .env so NVD_API_KEY is available to NVDCollector
load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

CTID_MAPPING_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "attack_to_cve/master/Att%26ckToCveMappings.csv"
)

START_YEAR = 1999
END_YEAR   = datetime.now(timezone.utc).year   # always syncs up to current year

STATE_FILE = Path("data/nvd_sync_state.json")


# ── Checkpoint Helpers ────────────────────────────────────────────────────────

def _load_state() -> dict:
    """Loads progress state from disk. Returns a fresh state if file missing or corrupted."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("[!] nvd_sync_state.json corrupted. Starting fresh.")

    return {
        "completed_years": [],
        "failed_years":    {},   # { "year": "error message" }
        "last_run":        None,
    }


def _save_state(state: dict) -> None:
    """Writes current progress state to disk immediately after each year."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)
    logger.info(f"[✓] Checkpoint saved → {STATE_FILE}")


def _reset_state() -> dict:
    """Wipes the state file and returns a blank state."""
    if STATE_FILE.exists():
        STATE_FILE.unlink()
        logger.info("[*] State file wiped. Starting from scratch.")
    return {
        "completed_years": [],
        "failed_years":    {},
        "last_run":        None,
    }


def _print_state_summary(state: dict) -> None:
    """Prints a human-readable summary of current progress."""
    completed = state.get("completed_years", [])
    failed    = state.get("failed_years", {})
    last_run  = state.get("last_run", "Never")

    logger.info("─" * 60)
    logger.info(f"  Last run       : {last_run}")
    logger.info(f"  Completed years: {len(completed)}  →  {sorted(completed)}")
    logger.info(f"  Failed years   : {len(failed)}   →  {list(failed.keys())}")
    logger.info("─" * 60)


# ── Phase A: CTID Mapping ─────────────────────────────────────────────────────

def fetch_ctid_mapping() -> dict[str, list[str]]:
    """
    Downloads the CTID CVE->ATT&CK mapping CSV and returns:
        { "CVE-2021-44228": ["T1190", "T1059"], ... }

    The CSV columns are:
        CVE ID | Primary Impact | Secondary Impact | Exploitation Technique | Uncategorized | Phase
    We collect all non-empty technique columns for each CVE row.
    """
    logger.info("[*] Fetching CTID CVE->ATT&CK mapping (CSV)...")
    response = requests.get(CTID_MAPPING_URL, timeout=30)
    response.raise_for_status()

    cve_to_ttps: dict[str, list[str]] = {}

    # Parse CSV from response text
    reader = csv.DictReader(io.StringIO(response.text))

    # Technique columns to check — covers all mapping types in the CSV
    technique_columns = [
        "Primary Impact",
        "Secondary Impact",
        "Exploitation Technique",
        "Uncategorized",
    ]

    for row in reader:
        cve_id = row.get("CVE ID", "").strip().upper()
        if not cve_id or not cve_id.startswith("CVE-"):
            continue

        ttps = []
        for col in technique_columns:
            val = row.get(col, "").strip().upper()
            if val and val.startswith("T") and val not in ttps:
                ttps.append(val)

        if ttps:
            if cve_id not in cve_to_ttps:
                cve_to_ttps[cve_id] = []
            for ttp in ttps:
                if ttp not in cve_to_ttps[cve_id]:
                    cve_to_ttps[cve_id].append(ttp)

    logger.info(f"[+] CTID mapping loaded: {len(cve_to_ttps)} CVEs have ATT&CK mappings.")
    return cve_to_ttps


# ── Phase B: Per-Year Sync ────────────────────────────────────────────────────

def sync_nvd_year(
    year: int,
    collector: NVDCollector,
    model: SentenceTransformer,
    graph: GraphConnector,
    cve_to_ttps: dict[str, list[str]],
) -> int:
    """
    Fetches all CVEs for a single year, embeds descriptions, merges CVE nodes,
    creates AFFECTS edges to software, and creates EXPLOITS_TECHNIQUE edges
    to MITRE TTPs via the CTID mapping.

    Raises an exception if the NVD fetch fails — the caller catches this
    and records it as a failed year in the checkpoint file.

    Returns the count of CVE nodes successfully processed.
    """
    logger.info(f"\n[*] Syncing year {year}...")
    records = collector.fetch_by_time(year=year, max_results=10000)

    if not records:
        logger.warning(f"[!] No CVE records returned for {year}. Marking as completed.")
        return 0

    logger.info(f"[-] Processing {len(records)} CVEs for {year}...")
    count = 0

    for record in records:
        cve_id      = record["title"]        # NVDCollector always sets title = CVE ID
        description = record["description"]
        cvss_score  = record.get("raw", {}).get("cvss_score")

        # 1. Embed description and merge CVE node
        embedding = model.encode(description).tolist()
        graph.merge_cve(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            embedding=embedding,
        )

        # 2. AFFECTS edges to known software (from CPE data in raw field)
        affected_software = record.get("raw", {}).get("affected_software", [])
        for software_name in affected_software:
            if software_name:
                graph.link_cve_software(
                    cve_id=cve_id,
                    software_name=software_name.strip().lower(),
                )

        # 3. EXPLOITS_TECHNIQUE edges via CTID mapping
        #    Silently skips if the TTP node doesn't exist yet in Neo4j
        #    (sync_mitre_baseline.py must have run first)
        ttps = cve_to_ttps.get(cve_id.upper(), [])
        for ttp_id in ttps:
            graph.link_cve_mitre(cve_id=cve_id, ttp_id=ttp_id)

        count += 1

    logger.info(f"[+] Year {year} done: {count} CVE nodes merged.")
    return count


# ── Main Orchestrator ─────────────────────────────────────────────────────────

def sync_nvd(retry_failed: bool = False) -> None:
    """
    Orchestrates the full year-by-year NVD sync with checkpoint support.

    Args:
        retry_failed : if True, only process years that previously failed.
                       if False, process all years that are not yet completed.
    """
    state = _load_state()
    _print_state_summary(state)

    completed = set(state["completed_years"])
    failed    = state["failed_years"]          # { "year_str": "error" }

    # Decide which years to process this run
    if retry_failed:
        years_to_process = [int(y) for y in failed.keys()]
        if not years_to_process:
            logger.info("[*] No failed years to retry. Exiting.")
            return
        logger.info(f"[*] Retry mode — targeting {len(years_to_process)} failed years: {sorted(years_to_process)}")
    else:
        all_years        = list(range(START_YEAR, END_YEAR + 1))
        years_to_process = [y for y in all_years if y not in completed]
        logger.info(f"[*] Normal mode — {len(years_to_process)} years remaining out of {len(all_years)} total.")

    if not years_to_process:
        logger.info("[+] All years already completed. Nothing to do.")
        return

    # Initialize shared resources once — reused across all years
    logger.info("[*] Initializing embedding model (all-MiniLM-L6-v2)...")
    model = SentenceTransformer('all-MiniLM-L6-v2')

    logger.info("[*] Connecting to Neo4j...")
    graph = GraphConnector()

    logger.info("[*] Initializing NVD collector...")
    collector = NVDCollector()

    # Fetch CTID mapping once — used for all years
    cve_to_ttps = fetch_ctid_mapping()

    state["last_run"] = datetime.now(timezone.utc).isoformat()
    total = 0

    for year in sorted(years_to_process):
        try:
            count = sync_nvd_year(
                year=year,
                collector=collector,
                model=model,
                graph=graph,
                cve_to_ttps=cve_to_ttps,
            )
            total += count

            # ── SUCCESS: mark completed, remove from failed if it was there ──
            if year not in state["completed_years"]:
                state["completed_years"].append(year)

            if str(year) in state["failed_years"]:
                del state["failed_years"][str(year)]
                logger.info(f"[+] Year {year} previously failed — now resolved.")

        except KeyboardInterrupt:
            # User pressed Ctrl+C — save state and exit cleanly
            logger.warning(f"\n[!] Interrupted during year {year}. Saving checkpoint...")
            _save_state(state)
            logger.info("[!] Progress saved. Re-run the script to continue from where you left off.")
            graph.close()
            return

        except Exception as e:
            # ── FAILURE: record the year and error, continue to next year ──
            error_msg = str(e)
            state["failed_years"][str(year)] = error_msg
            logger.error(f"[!] Year {year} FAILED: {error_msg}")
            logger.error(f"[!] Recorded in failed_years. Continuing to next year...")

        finally:
            # Save checkpoint after every year regardless of success or failure
            _save_state(state)

    graph.close()

    # ── Final summary ──────────────────────────────────────────────────────────
    logger.info("\n" + "=" * 60)
    logger.info(f"  NVD sync session complete.")
    logger.info(f"  CVE nodes processed this run : {total}")
    logger.info(f"  Total completed years        : {len(state['completed_years'])}")
    logger.info(f"  Years still failing          : {list(state['failed_years'].keys())}")
    if state["failed_years"]:
        logger.info("  → Re-run with --retry to attempt failed years again.")
    logger.info("=" * 60)


# ── CLI Entry Point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NVD Baseline Sync (1999 → present)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--retry",
        action="store_true",
        help="Retry only previously failed years",
    )
    group.add_argument(
        "--reset",
        action="store_true",
        help="Wipe all checkpoint state and start completely fresh",
    )
    args = parser.parse_args()

    if args.reset:
        state = _reset_state()

    sync_nvd(retry_failed=args.retry)