"""
FILE: enrichment/attack_mapper.py
ROLE: LLM-based TTP Extractor with JSON verification
PURPOSE:
  Uses the LLM to directly extract MITRE ATT&CK technique IDs from
  behavior sentences, then verifies each extracted ID against the
  enterprise-attack.json file to eliminate
  hallucinated TTP IDs.

  The JSON file is the ground truth — if a TTP ID is not in it, it is
  hallucinated and dropped. No Neo4j call needed for verification.

  Runs in parallel with kg_engine — results are merged into kg_payload
  before report generation so the final report has both vector-matched
  and LLM-extracted TTPs.
"""
import re
import json
import logging
from pathlib import Path
from langchain_core.prompts import PromptTemplate
from llm.ollama_client import get_llm

logger = logging.getLogger(__name__)

# ── Load valid TTP IDs from enterprise-attack.json once at module load ────────

_VALID_TTP_IDS: set[str] = set()

def _load_valid_ttps() -> set[str]:
    """
    Parses enterprise-attack.json from the project root and extracts
    all valid MITRE ATT&CK technique IDs (e.g. T1059, T1059.001).
    Called once at module load — result is cached in _VALID_TTP_IDS.
    """
    stix_path = Path("enterprise-attack.json")
    if not stix_path.exists():
        logger.warning(
            "[!] enterprise-attack.json not found at project root. "
            "TTP verification will be skipped."
        )
        return set()

    try:
        with open(stix_path, "r", encoding="utf-8") as f:
            stix_data = json.load(f)

        valid_ids: set[str] = set()
        for obj in stix_data.get("objects", []):
            # Only load actual techniques — not mitigations, matrices, or tactics
            if obj.get("type") != "attack-pattern":
                continue
            # Skip deprecated and revoked techniques
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ttp_id = ref.get("external_id", "").strip().upper()
                    # Only accept T-codes, not tactic IDs (which start with TA)
                    if ttp_id and ttp_id.startswith("T") and not ttp_id.startswith("TA"):
                        valid_ids.add(ttp_id)

        logger.info(f"[+] Loaded {len(valid_ids)} valid active MITRE TTP IDs from enterprise-attack.json")
        return valid_ids

    except Exception as e:
        logger.error(f"[!] Failed to load enterprise-attack.json: {e}")
        return set()


# Load once at import time
_VALID_TTP_IDS = _load_valid_ttps()

# ── Regex for basic TTP format validation ─────────────────────────────────────

_TTP_PATTERN = re.compile(r'^T\d{4}(\.\d{3})?$')

# ── Prompt ────────────────────────────────────────────────────────────────────

ATTACK_MAPPER_PROMPT = """
You are a MITRE ATT&CK expert. Given the following adversarial behavior descriptions,
identify which MITRE ATT&CK technique IDs (T-codes) best match each behavior.

CRITICAL RULES:
1. Only output REAL, VALID MITRE ATT&CK technique IDs (e.g. T1059, T1078, T1190).
2. Do NOT invent technique IDs. If unsure, omit rather than guess.
3. Output ONLY a JSON object — no preamble, no explanation, no markdown.
4. Include sub-techniques where relevant (e.g. T1059.001 for PowerShell).
5. Maximum 5 technique IDs total across all behaviors.

JSON Schema:
{{"ttps": ["T1059", "T1078", "T1190"]}}

Behaviors to analyze:
{behaviors}
"""

# ── Main function ─────────────────────────────────────────────────────────────

def extract_ttps_from_behaviors(behaviors: list[str]) -> list[str]:
    """
    Uses LLM to extract MITRE ATT&CK TTP IDs from behavior sentences,
    then verifies each against enterprise-attack.json to eliminate hallucinations.

    Two-step verification:
      1. Format check  — regex T\d{4}(\.\d{3})? filters malformed IDs
      2. JSON check    — verifies ID exists in enterprise-attack.json

    Returns a deduplicated list of verified TTP IDs like ["T1059", "T1078"].
    """
    if not behaviors:
        return []

    logger.info("[*] Running LLM-based TTP extraction (attack mapper)...")

    llm = get_llm()
    prompt = PromptTemplate(
        input_variables=["behaviors"],
        template=ATTACK_MAPPER_PROMPT,
    )
    chain = prompt | llm

    behaviors_text = "\n".join(f"- {b}" for b in behaviors)

    try:
        response = chain.invoke({"behaviors": behaviors_text})

        # ── Parse JSON response ───────────────────────────────────────────────
        clean = response.strip().strip("```json").strip("```").strip()
        brace_idx = clean.find("{")
        if brace_idx > 0:
            clean = clean[brace_idx:]
        last_brace = clean.rfind("}")
        if last_brace != -1:
            clean = clean[:last_brace + 1]

        data = json.loads(clean)
        raw_ttps = data if isinstance(data, list) else data.get("ttps", [])

        logger.info(f"[-] LLM returned raw TTPs: {raw_ttps}")

        # ── Step 1: Format validation ─────────────────────────────────────────
        format_valid = []
        for t in raw_ttps:
            if not isinstance(t, str):
                continue
            t = t.strip().upper()
            if _TTP_PATTERN.match(t):
                format_valid.append(t)
            else:
                logger.warning(f"    [✗] '{t}' — invalid format, dropped")

        # ── Step 2: Verify against enterprise-attack.json ─────────────────────
        verified = []
        seen = set()
        for t in format_valid:
            if t in seen:
                continue
            seen.add(t)
            if not _VALID_TTP_IDS:
                # JSON not loaded — skip verification, trust format check
                verified.append(t)
                logger.warning(f"    [?] {t} — JSON not loaded, skipping verification")
            elif t in _VALID_TTP_IDS:
                verified.append(t)
                logger.info(f"    [✓] {t} — verified in enterprise-attack.json")
            else:
                logger.warning(f"    [✗] {t} — NOT in enterprise-attack.json (hallucinated), dropped")

        logger.info(f"[+] Attack mapper final: {len(verified)} verified TTPs: {verified}")
        return verified

    except json.JSONDecodeError as e:
        logger.error(f"[-] Attack mapper failed to parse JSON: {e}\nRaw: {response}")
        return []
    except Exception as e:
        logger.error(f"[-] Attack mapper failed: {e}")
        return []