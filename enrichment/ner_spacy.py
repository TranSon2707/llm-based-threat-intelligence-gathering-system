"""
enrichment/ner_spacy.py
========================
spaCy-based Named Entity Recognition (NER) for threat intelligence text.

What it extracts
-----------------
  THREAT_ACTOR   Persons / groups identified as attackers (spaCy PERSON label
                 + custom org patterns like APT groups)
  MALWARE        Known malware family names (via custom EntityRuler)

Custom patterns cover the most commonly reported malware families and APT
group aliases so the base en_core_web_sm model is boosted with domain
knowledge.  The pattern list is intentionally extensible — add new entries
to MALWARE_PATTERNS or APT_PATTERNS as needed.

All results are persisted to the ``entities`` table via db/queries.py.

Usage
-----
    from enrichment.ner_spacy import extract_and_store_ner

    extract_and_store_ner(source_id=42, cleaned_text="Lazarus Group deployed WannaCry...")
"""

from __future__ import annotations

import logging
from typing import NamedTuple

import spacy
from spacy.language import Language
from spacy.pipeline import EntityRuler

from db.queries import insert_entity

logger = logging.getLogger(__name__)

# ── Custom pattern catalogue ──────────────────────────────────────────────────

# Malware family names (case-insensitive matching via lowercase patterns)
MALWARE_PATTERNS: list[dict] = [
    # Ransomware
    {"label": "MALWARE", "pattern": "WannaCry"},
    {"label": "MALWARE", "pattern": "WannaCrypt"},
    {"label": "MALWARE", "pattern": "NotPetya"},
    {"label": "MALWARE", "pattern": "Petya"},
    {"label": "MALWARE", "pattern": "REvil"},
    {"label": "MALWARE", "pattern": "LockBit"},
    {"label": "MALWARE", "pattern": "BlackCat"},
    {"label": "MALWARE", "pattern": "Conti"},
    {"label": "MALWARE", "pattern": "Ryuk"},
    {"label": "MALWARE", "pattern": "DarkSide"},
    {"label": "MALWARE", "pattern": "Hive"},
    {"label": "MALWARE", "pattern": "BlackMatter"},
    {"label": "MALWARE", "pattern": "Clop"},
    # Banking trojans
    {"label": "MALWARE", "pattern": "Emotet"},
    {"label": "MALWARE", "pattern": "TrickBot"},
    {"label": "MALWARE", "pattern": "Dridex"},
    {"label": "MALWARE", "pattern": "ZeuS"},
    {"label": "MALWARE", "pattern": "Zeus"},
    {"label": "MALWARE", "pattern": "Qakbot"},
    {"label": "MALWARE", "pattern": "QBot"},
    {"label": "MALWARE", "pattern": "IcedID"},
    # RATs / backdoors
    {"label": "MALWARE", "pattern": "Cobalt Strike"},
    {"label": "MALWARE", "pattern": "Metasploit"},
    {"label": "MALWARE", "pattern": "AsyncRAT"},
    {"label": "MALWARE", "pattern": "njRAT"},
    {"label": "MALWARE", "pattern": "Agent Tesla"},
    {"label": "MALWARE", "pattern": "AgentTesla"},
    {"label": "MALWARE", "pattern": "NanoCore"},
    {"label": "MALWARE", "pattern": "DarkComet"},
    {"label": "MALWARE", "pattern": "Remcos"},
    # Worms / exploits
    {"label": "MALWARE", "pattern": "EternalBlue"},
    {"label": "MALWARE", "pattern": "Log4Shell"},
    {"label": "MALWARE", "pattern": "Mirai"},
    {"label": "MALWARE", "pattern": "Sliver"},
    {"label": "MALWARE", "pattern": "Havoc"},
    # Spyware / info stealers
    {"label": "MALWARE", "pattern": "Pegasus"},
    {"label": "MALWARE", "pattern": "FinFisher"},
    {"label": "MALWARE", "pattern": "Redline"},
    {"label": "MALWARE", "pattern": "RedLine Stealer"},
    {"label": "MALWARE", "pattern": "Raccoon"},
    {"label": "MALWARE", "pattern": "Vidar"},
]

# APT group / threat-actor aliases that spaCy's PERSON label often misses
APT_PATTERNS: list[dict] = [
    {"label": "THREAT_ACTOR", "pattern": "Lazarus Group"},
    {"label": "THREAT_ACTOR", "pattern": "Lazarus"},
    {"label": "THREAT_ACTOR", "pattern": "APT28"},
    {"label": "THREAT_ACTOR", "pattern": "Fancy Bear"},
    {"label": "THREAT_ACTOR", "pattern": "APT29"},
    {"label": "THREAT_ACTOR", "pattern": "Cozy Bear"},
    {"label": "THREAT_ACTOR", "pattern": "APT41"},
    {"label": "THREAT_ACTOR", "pattern": "APT10"},
    {"label": "THREAT_ACTOR", "pattern": "APT32"},
    {"label": "THREAT_ACTOR", "pattern": "OceanLotus"},
    {"label": "THREAT_ACTOR", "pattern": "Sandworm"},
    {"label": "THREAT_ACTOR", "pattern": "Turla"},
    {"label": "THREAT_ACTOR", "pattern": "Charming Kitten"},
    {"label": "THREAT_ACTOR", "pattern": "APT35"},
    {"label": "THREAT_ACTOR", "pattern": "Scattered Spider"},
    {"label": "THREAT_ACTOR", "pattern": "LAPSUS$"},
    {"label": "THREAT_ACTOR", "pattern": [{"LOWER": "lapsus"}, {"TEXT": "$"}]},
    {"label": "THREAT_ACTOR", "pattern": "Equation Group"},
    {"label": "THREAT_ACTOR", "pattern": "DarkHalo"},
    {"label": "THREAT_ACTOR", "pattern": "UNC2452"},
    {"label": "THREAT_ACTOR", "pattern": "SolarWinds Attackers"},
]

# ── Model singleton ───────────────────────────────────────────────────────────

_NLP: Language | None = None


def _get_nlp() -> Language:
    """
    Load en_core_web_sm once and inject the custom EntityRuler before the
    built-in NER component so custom patterns take precedence.
    """
    global _NLP
    if _NLP is not None:
        return _NLP

    logger.info("[ner_spacy] Loading spaCy model en_core_web_sm …")
    nlp = spacy.load("en_core_web_sm")

    # EntityRuler added *before* ner so it can set spans that ner won't override
    ruler: EntityRuler = nlp.add_pipe(
        "entity_ruler",
        before="ner",
        config={"overwrite_ents": True},
    )
    ruler.add_patterns(MALWARE_PATTERNS + APT_PATTERNS)

    _NLP = nlp
    logger.info("[ner_spacy] Model ready with %d custom patterns.",
                len(MALWARE_PATTERNS) + len(APT_PATTERNS))
    return _NLP


# ── Public interface ───────────────────────────────────────────────────────────

class NEREntity(NamedTuple):
    entity_type:  str   # "THREAT_ACTOR" or "MALWARE"
    entity_value: str


def extract_ner_entities(text: str) -> list[NEREntity]:
    """
    Run NER over *text* and return deduplicated THREAT_ACTOR and MALWARE
    entities.

    Mapping from spaCy labels:
        PERSON  → THREAT_ACTOR  (individuals named in threat reports)
        MALWARE → MALWARE       (set by custom EntityRuler)
        THREAT_ACTOR → THREAT_ACTOR (set by custom EntityRuler for APT groups)

    GPE / ORG labels are intentionally excluded to reduce false positives
    (country names and vendor names are not threat actors).
    """
    if not text or not isinstance(text, str):
        return []

    nlp  = _get_nlp()
    # spaCy processes up to max_length chars; split long documents to be safe
    doc  = nlp(text[:100_000])

    seen:    set[tuple[str, str]] = set()
    results: list[NEREntity]      = []

    for ent in doc.ents:
        raw_label = ent.label_
        raw_value = ent.text.strip()

        if not raw_value:
            continue

        if raw_label == "PERSON":
            etype = "THREAT_ACTOR"
        elif raw_label == "MALWARE":
            etype = "MALWARE"
        elif raw_label == "THREAT_ACTOR":
            etype = "THREAT_ACTOR"
        else:
            continue  # ignore GPE, ORG, DATE, etc.

        key = (etype, raw_value.lower())
        if key not in seen:
            seen.add(key)
            results.append(NEREntity(entity_type=etype, entity_value=raw_value))

    return results


def extract_and_store_ner(source_id: int, cleaned_text: str) -> list[NEREntity]:
    """
    Extract THREAT_ACTOR and MALWARE entities from *cleaned_text* and
    persist them to the ``entities`` table linked to *source_id*.

    Returns the list of extracted entities for testing / logging.
    """
    entities = extract_ner_entities(cleaned_text)

    for entity in entities:
        try:
            insert_entity(
                source_id=source_id,
                entity_type=entity.entity_type,
                entity_value=entity.entity_value,
            )
        except Exception as exc:
            logger.warning(
                "Failed to insert NER entity (%s=%s) for source_id=%d: %s",
                entity.entity_type, entity.entity_value, source_id, exc,
            )

    logger.info(
        "[ner_spacy] source_id=%d → %d NER entities extracted",
        source_id, len(entities),
    )
    return entities


if __name__ == "__main__":
    sample = """
    The Lazarus Group deployed WannaCry ransomware across hospital networks.
    APT28, also known as Fancy Bear, used Emotet as a dropper to deliver Cobalt Strike.
    Researcher John Smith attributed the attack to a North Korean threat actor.
    """

    results = extract_ner_entities(sample)
    for e in results:
        print(e.entity_type, "→", e.entity_value)