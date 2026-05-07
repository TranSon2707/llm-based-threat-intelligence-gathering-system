"""
enrichment/entity_extractor.py
================================
Regex-based extraction of hard technical indicators (IOCs) from cleaned
threat-intelligence text.

Extracted entity types
-----------------------
  CVE        CVE-YYYY-NNNNN identifiers
  IPv4       Standard dotted-decimal addresses (e.g. 192.168.1.1)
  IPv6       Full and compressed IPv6 addresses (e.g. 2001:db8::1)
  DOMAIN     Hostnames / FQDNs (e.g. evil.example.com)
  MD5        32 hex-char hashes
  SHA1       40 hex-char hashes
  SHA256     64 hex-char hashes

All results are written to the `entities` table via db/queries.py.

Usage
-----
    from enrichment.entity_extractor import extract_and_store

    # cleaned_text  : output of preprocessor/html_stripper.strip_html()
    # source_id     : raw_items.id that produced this text
    extract_and_store(source_id=42, cleaned_text="CVE-2021-44228 triggered by 192.0.2.1")
"""

from __future__ import annotations

import re
import logging
from typing import NamedTuple

from db.queries import insert_entity

logger = logging.getLogger(__name__)

# ── Compiled regex patterns ────────────────────────────────────────────────────

# CVE-YYYY-NNNNN  (year 1999-2099, 4+ digit sequence number)
_RE_CVE = re.compile(
    r"\bCVE-(?:19|20)\d{2}-\d{4,}\b",
    re.IGNORECASE,
)

# IPv4: four octets 0-255, word-boundary anchored
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
)

# IPv6: simplified pattern covering full, compressed, and mixed notations
_RE_IPV6 = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"          # full
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:\b"                         # trailing ::
    r"|\b::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b"      # leading ::
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b"        # middle ::
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}\b"
    r"|\b[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}\b",
)

# DOMAIN: hostname.tld or sub.hostname.tld
# Excludes pure numbers (already caught by IPv4), requires a known-style TLD.
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b",
)

# Cryptographic hashes — distinguished by length, all hex characters
_RE_MD5    = re.compile(r"\b[0-9A-Fa-f]{32}\b")
_RE_SHA1   = re.compile(r"\b[0-9A-Fa-f]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9A-Fa-f]{64}\b")

# ── False-positive suppression ─────────────────────────────────────────────────

# Common tokens that match the domain regex but are not IOCs
_DOMAIN_STOPWORDS: frozenset[str] = frozenset({
    "example.com", "localhost.localdomain", "test.local",
    "schema.org", "w3.org", "xmlns.com",
})


# ── Public interface ───────────────────────────────────────────────────────────

class ExtractedEntity(NamedTuple):
    entity_type:  str
    entity_value: str


def extract_entities(text: str) -> list[ExtractedEntity]:
    """
    Run all regex patterns over *text* and return a deduplicated list of
    ``ExtractedEntity`` named tuples.

    Deduplication is (type, value) so the same IP appearing twice in one
    report is stored only once.
    """
    if not text or not isinstance(text, str):
        return []

    seen: set[tuple[str, str]] = set()
    results: list[ExtractedEntity] = []

    def _add(etype: str, evalue: str) -> None:
        key = (etype, evalue.upper() if etype == "CVE" else evalue)
        if key not in seen:
            seen.add(key)
            results.append(ExtractedEntity(entity_type=etype, entity_value=evalue))

    # Hashes first so long hex strings are claimed before domain regex runs
    for match in _RE_SHA256.finditer(text):
        _add("SHA256", match.group())

    for match in _RE_SHA1.finditer(text):
        val = match.group()
        # Skip if already captured as part of a SHA-256
        if not any(val in e.entity_value for e in results if e.entity_type == "SHA256"):
            _add("SHA1", val)

    for match in _RE_MD5.finditer(text):
        val = match.group()
        already_longer = any(
            val in e.entity_value
            for e in results
            if e.entity_type in ("SHA1", "SHA256")
        )
        if not already_longer:
            _add("MD5", val)

    # CVEs
    for match in _RE_CVE.finditer(text):
        _add("CVE", match.group().upper())

    # IPv6 before IPv4 to avoid partial matches
    for match in _RE_IPV6.finditer(text):
        _add("IPv6", match.group())

    for match in _RE_IPV4.finditer(text):
        _add("IPv4", match.group())

    # Domains — skip values that look like plain IPv4 or are in the stoplist
    for match in _RE_DOMAIN.finditer(text):
        val = match.group().lower()
        if val in _DOMAIN_STOPWORDS:
            continue
        # Avoid re-capturing things already tagged as IPv4
        if any(e.entity_value == match.group() and e.entity_type == "IPv4"
               for e in results):
            continue
        _add("DOMAIN", val)

    return results


def extract_and_store(source_id: int, cleaned_text: str) -> list[ExtractedEntity]:
    """
    Extract all IOCs from *cleaned_text* and persist each one to the
    ``entities`` table linked to *source_id* (raw_items.id).

    Returns the list of extracted entities for optional downstream use
    (e.g. logging, testing).
    """
    entities = extract_entities(cleaned_text)

    for entity in entities:
        try:
            insert_entity(
                source_id=source_id,
                entity_type=entity.entity_type,
                entity_value=entity.entity_value,
            )
        except Exception as exc:
            logger.warning(
                "Failed to insert entity (%s=%s) for source_id=%d: %s",
                entity.entity_type, entity.entity_value, source_id, exc,
            )

    logger.info(
        "[entity_extractor] source_id=%d → %d entities extracted",
        source_id, len(entities),
    )
    return entities
