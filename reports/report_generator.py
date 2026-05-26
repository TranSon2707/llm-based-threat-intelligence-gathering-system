"""
FILE: reports/report_generator.py
ROLE: Analyst Synthesis & Proactive Reporting (Stage 5)
PURPOSE:
  Produces the final actionable executive intelligence report using
  Closed-Domain RAG (Retrieval-Augmented Generation).

  The LLM receives a fully structured prompt containing:
    1. The original OSINT text (encapsulated in <THREAT_DATA> tags for
       prompt injection defense — must be passed pre-encapsulated).
    2. Extracted entities from SQLite (Actors, Malware, Hard IOCs).
    3. Graph context from Neo4j (matched CVEs, TTPs, systems at risk,
       zero-day flag, unmatched behaviors).

  The LLM is strictly mandated to:
    - Cite every claim with [source_id: X].
    - Separate matched CVEs from matched TTPs clearly.
    - Flag zero-day behaviors explicitly.
    - Return "Insufficient data to determine" for any section where
      data is missing, rather than hallucinating.

FUNCTION:
  generate_analyst_summary(
      source_id        : int              — raw_items.id, used for citation and DB storage
      cleaned_text     : str              — pre-encapsulated text (<THREAT_DATA>...</THREAT_DATA>)
      entities_list    : list[dict]       — from sqlite_manager.get_entities()
      kg_payload       : dict             — from kg_engine.evaluate_threat()
  ) -> str
"""

import logging
import datetime
from langchain_core.prompts import PromptTemplate

from llm.ollama_client import get_llm
from db.sqlite_manager import insert_report

logger = logging.getLogger(__name__)

# ── RAG Prompt ────────────────────────────────────────────────────────────────

RAG_PROMPT = """
You are a senior Cyber Threat Intelligence analyst producing a formal intelligence report.
You will be given structured threat context. Your job is to synthesize it into a clear,
actionable executive summary for a security operations team.

STRICT RULES:
1. You MUST append [source_id: {source_id}] after EVERY factual claim you make.
2. You MUST use ONLY the data provided below. Do NOT invent CVEs, TTPs, actors, or software names.
3. If a section has no data, write exactly: "Insufficient data to determine."
4. Never reproduce the raw <THREAT_DATA> text verbatim — summarize it.
5. Keep the report under 400 words.

=== THREAT DATA (OSINT SOURCE) ===
{threat_data}

=== EXTRACTED ENTITIES ===
Threat Actors : {threat_actors}
Malware       : {malware}
Hard IOCs     : {hard_iocs}

=== KNOWLEDGE GRAPH CONTEXT ===
Matched CVEs         : {matched_cves}
Matched MITRE TTPs   : {matched_ttps}
Systems at Risk      : {systems_at_risk}
Unmatched Behaviors  : {unmatched_behaviors}
Zero-Day Flag        : {is_zero_day}

=== REPORT FORMAT (follow exactly) ===

## Threat Overview
[1-2 sentences summarizing what the threat is and who is behind it.]

## Indicators of Compromise
[List the hard IOCs: IPs, domains, hashes, CVE IDs found in the source.]

## MITRE ATT&CK Mapping
[List each matched TTP with its ID and what adversarial action it represents.]

## Matched Vulnerabilities
[List each matched CVE and what system it affects.]

## Blast Radius
[List all systems at risk based on graph traversal.]

## Zero-Day Assessment
[State whether any behaviors were unmatched in the knowledge graph.
If is_zero_day is True, flag this as a potential novel or zero-day technique.
List unmatched behaviors explicitly.]

## Recommended Actions
[3-5 concrete mitigation steps grounded in the matched CVEs and TTPs above.]
"""

# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_entities(entities_list: list[dict]) -> tuple[str, str, str]:
    """
    Splits the flat entities list from SQLite into three display strings:
    threat actors, malware families, and hard IOCs.
    """
    actors  = []
    malware = []
    iocs    = []

    for e in entities_list:
        etype = e.get("entity_type", "")
        eval_ = e.get("entity_value", "")

        if etype == "THREAT_ACTOR":
            actors.append(eval_)
        elif etype == "MALWARE":
            malware.append(eval_)
        else:
            # CVE, IPv4, IPv6, DOMAIN, MD5, SHA1, SHA256
            iocs.append(f"{etype}: {eval_}")

    return (
        ", ".join(actors)  or "None identified",
        ", ".join(malware) or "None identified",
        ", ".join(iocs)    or "None identified",
    )


def _format_list(items: list) -> str:
    """Formats a list for prompt injection — comma-joined or 'None' if empty."""
    return ", ".join(str(i) for i in items) if items else "None"


# ── Main Entry Point ──────────────────────────────────────────────────────────

def generate_analyst_summary(
    source_id:     int,
    cleaned_text:  str,
    entities_list: list[dict],
    kg_payload:    dict,
) -> str:
    """
    Generates a structured intelligence report using closed-domain RAG.

    Args:
        source_id     : raw_items.id — used for [source_id: X] citations
                        and for storing the report in the reports table.
        cleaned_text  : the pre-encapsulated OSINT text
                        (must already be wrapped in <THREAT_DATA> tags by
                        preprocessor/encapsulator.py).
        entities_list : list of entity dicts from sqlite_manager.get_entities().
                        Each dict has keys: entity_type, entity_value.
        kg_payload    : dict from kg_engine.evaluate_threat(). Expected keys:
                        matched_cves, matched_ttps, systems_at_risk,
                        unmatched_behaviors, is_zero_day.

    Returns:
        The generated report string. Also persists it to the reports table.
    """
    logger.info(f"[*] Generating analyst report for source_id={source_id}...")

    # ── 1. Validate input ─────────────────────────────────────────────────────
    if not cleaned_text or not cleaned_text.strip().startswith("<THREAT_DATA>"):
        logger.error("[!] cleaned_text must be pre-encapsulated with <THREAT_DATA> tags.")
        raise ValueError(
            "cleaned_text must be wrapped in <THREAT_DATA> tags. "
            "Pass item['processed_text'] from the pipeline, not item['description']."
        )

    # ── 2. Format entities ────────────────────────────────────────────────────
    threat_actors, malware, hard_iocs = _format_entities(entities_list)

    # ── 3. Format graph context ───────────────────────────────────────────────
    # Support both old payload shape (matched_threats) and new split shape
    matched_cves = _format_list(
        kg_payload.get("matched_cves") or
        [t for t in kg_payload.get("matched_threats", []) if t.startswith("CVE-")]
    )
    matched_ttps = _format_list(
        kg_payload.get("matched_ttps") or
        kg_payload.get("techniques", [])
    )
    systems_at_risk     = _format_list(kg_payload.get("systems_at_risk", []))
    unmatched_behaviors = _format_list(kg_payload.get("unmatched_behaviors", []))
    is_zero_day         = "YES — potential novel/zero-day technique detected" \
                          if kg_payload.get("is_zero_day") else "No"

    # ── 4. Build and invoke LLM chain ─────────────────────────────────────────
    llm    = get_llm()
    prompt = PromptTemplate(
        input_variables=[
            "source_id", "threat_data", "threat_actors", "malware",
            "hard_iocs", "matched_cves", "matched_ttps", "systems_at_risk",
            "unmatched_behaviors", "is_zero_day",
        ],
        template=RAG_PROMPT,
    )
    chain = prompt | llm

    try:
        report = chain.invoke({
            "source_id":           source_id,
            "threat_data":         cleaned_text,
            "threat_actors":       threat_actors,
            "malware":             malware,
            "hard_iocs":           hard_iocs,
            "matched_cves":        matched_cves,
            "matched_ttps":        matched_ttps,
            "systems_at_risk":     systems_at_risk,
            "unmatched_behaviors": unmatched_behaviors,
            "is_zero_day":         is_zero_day,
        })
        report = report.strip()
        logger.info(f"[+] Report generated successfully for source_id={source_id}.")

    except Exception as e:
        logger.error(f"[-] LLM report generation failed for source_id={source_id}: {e}")
        report = (
            f"## Report Generation Failed\n"
            f"source_id: {source_id}\n"
            f"Error: {e}\n"
            f"Insufficient data to determine."
        )

    # ── 5. Persist to reports table ───────────────────────────────────────────
    try:
        insert_report((
            source_id,
            report,
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ))
        logger.info(f"[+] Report saved to DB for source_id={source_id}.")
    except Exception as e:
        logger.warning(f"[!] Failed to save report to DB for source_id={source_id}: {e}")

    return report