"""
FILE: enrichment/attack_mapper.py
ROLE: LLM-based TTP/CVE Extractor with graph database verification
PURPOSE:
  Uses the LLM to directly extract MITRE ATT&CK/CVE IDs from
  behavior sentences, then verifies each extracted ID against the
  graph database to eliminate hallucinated IDs.

  Runs in parallel with kg_engine — results are merged into kg_payload
  before report generation so the final report has both vector-matched
  and LLM-extracted TTPs, CVEs.
"""
import re
import json
import logging
from pathlib import Path
from langchain_core.prompts import PromptTemplate
from llm.ollama_client import get_llm
from db.neo4j_manager import GraphConnector
import warnings
warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
# Suppress INFO/DEBUG logs from noisy libraries
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("neo4j").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)   # if httpx is used under the hood


logger = logging.getLogger(__name__)

# ── Regex for basic TTP format validation ─────────────────────────────────────

_TTP_PATTERN = re.compile(r'^T\d{4}(\.\d{3})?$')
_CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')

# ── Prompt ────────────────────────────────────────────────────────────────────

TTP_MAPPER_PROMPT = """
You are a MITRE ATT&CK expert. Given this following adversarial behavior description,
identify which MITRE ATT&CK technique IDs (T-codes) best match for this behavior.

CRITICAL RULES:
1. Only output REAL, VALID MITRE ATT&CK (e.g. T10--, "--" is placeholders for digits).
2. Do NOT invent technique IDs. If UNSURE, OMIT RATHER THAN GUESS.
3. If can not find any valid techniques, return an EMPTY list: [].
4. Output ONLY a JSON object — no preamble, no explanation, no markdown.
5. Include sub-techniques where relevant (e.g. T10--.001).
6. Maximum 3 technique IDs.

JSON Schema:
{{"ttps": ["T----", "T----", "T----"]}}

Behavior to analyze:
{behavior}
"""

CVE_MAPPER_PROMPT = """
You are a cybersecurity expert. Given this following adversarial behaviors description,
identify which CVE ID best match.

CRITICAL RULES:
1. Only output 1 REAL, VALID CVE ID (e.g. CVE-20xy-1234).
2. Do NOT invent CVE IDs. If UNSURE, OMIT RATHER THAN GUESS.
3. If can not find any valid CVE, return an EMPTY list: [].
4. Output ONLY a JSON object — NO preamble, NO EXPLANATION, NO MARKDOWN, NO NOTES.
5, 1 CVE ONLY — the most relevant one.

JSON Schema:
{{"cves": ["CVE-20xy-1234"]}}

Behaviors to analyze:
{behaviors}
"""

# ── Main function ─────────────────────────────────────────────────────────────

def extract_ttps_from_behavior(behavior:  str) -> list[str]:
    """
    Uses LLM to extract MITRE ATT&CK TTP IDs from behavior sentence,
    then verifies each against enterprise-attack.json to eliminate hallucinations.

    Two-step verification:
      1. Format check  — regex T\d{4}(\.\d{3})? filters malformed IDs
      2. JSON check    — verifies ID exists in enterprise-attack.json

    Returns a deduplicated list of verified TTP IDs like ["T1059", "T1078"].
    """
    if not behavior:
        return []

    logger.info("[*] Running LLM-based TTP extraction (attack mapper)...")

    llm = get_llm(model="attack_mapper", num_ctx=4096, num_predict=2048)
    prompt = PromptTemplate(
        input_variables=["behavior"],
        template=TTP_MAPPER_PROMPT,
    )
    chain = prompt | llm

    behavior_text = f"- {behavior}"

    try:
        response = chain.invoke({"behavior": behavior_text})

        # ── Parse JSON response ───────────────────────────────────────────────
        clean = response.strip().strip("```json").strip("```").strip()
        brace_idx = clean.find("{")
        if brace_idx > 0:
            clean = clean[brace_idx:]
        last_brace = clean.rfind("}")
        if last_brace != -1:
            clean = clean[:last_brace + 1]
        print(f"[-] Cleaned JSON string: {clean}")

        data = json.loads(clean)
        raw_ttps = data.get("ttps", [])

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
            check = GraphConnector().get_ttp_by_id(t)
            if check:   
                verified.append(t)
                logger.info(f"    [+] '{t}' verified against graph database")

        logger.info(f"[+] Attack mapper final: {len(verified)} verified TTPs: {verified}")
        return verified

    except json.JSONDecodeError as e:
        logger.error(f"[-] Attack mapper failed to parse JSON: {e}\nRaw: {response}")
        return []
    except Exception as e:
        logger.error(f"[-] Attack mapper failed: {e}")
        return []
    
def extract_cve_from_behaviors(behaviors:  list[str]) -> list[str]:
    """
    Uses LLM to extract CVE ID from behavior descriptions,
    then verifies each against a CVE database to eliminate hallucinations.

    Two-step verification:
      1. Format check  — regex CVE-\d{4}-\d{4,} filters malformed ID
      2. JSON check    — verifies ID exists in CVE database

    Returns a deduplicated list of verified CVE IDs like ["CVE-2021-1234", "CVE-2022-5678"].
    """
    if not behaviors:
        return []

    logger.info("[*] Running LLM-based CVE extraction (attack mapper)...")

    llm = get_llm(model="attack_mapper", num_ctx=4096, num_predict=2048)
    prompt = PromptTemplate(
        input_variables=["behaviors"],
        template=CVE_MAPPER_PROMPT,
    )
    chain = prompt | llm

    behavior_text = "\n- " + "\n- ".join(behaviors)

    try:
        response = chain.invoke({"behaviors": behavior_text})
        if response:
            logger.info(f"[-] LLM returned raw response: {response}")
            # ── Parse JSON response ───────────────────────────────────────────────
            clean = response.strip().strip("```json").strip("```").strip()
            brace_idx = clean.find("{")
            if brace_idx > 0:
                clean = clean[brace_idx:]
            last_brace = clean.rfind("}")
            if last_brace != -1:
                clean = clean[:last_brace + 1]
            print(f"[-] Cleaned JSON string: {clean}")

            data = json.loads(clean)
            raw_cve = data.get("cve", [])
            print(f"[-] Extracted CVE from JSON: {raw_cve}")
            raw_cve = raw_cve[0] if isinstance(raw_cve, list) and raw_cve else ""

            logger.info(f"[-] LLM returned raw CVE: {raw_cve}")

            # ── Step 1: Format validation ────────────────────────────────────────
            format_valid = None
            raw_cve = raw_cve.strip().upper()
            if _CVE_PATTERN.match(raw_cve):
                format_valid = raw_cve
            else:
                logger.warning(f"    [✗] '{raw_cve}' — invalid format, dropped")

            # ── Step 2: Verify against enterprise-attack.json ─────────────────────
            verified = None
            check = GraphConnector().get_cve_by_id(format_valid)
            if check:   
                verified = format_valid
                logger.info(f"    [+] '{format_valid}' verified against graph database")

            logger.info(f"[+] Attack mapper final verified CVEs: {verified}")
            return verified
        else:
            logger.info("[+] Attack mapper found no CVE.")
            return ""
        
        

    except json.JSONDecodeError as e:
        logger.error(f"[-] Attack mapper failed to parse JSON: {e}\nRaw: {response}")
        return []
    except Exception as e:
        logger.error(f"[-] Attack mapper failed: {e}")
        return []