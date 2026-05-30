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

from db.sqlite_manager import insert_entity

logger = logging.getLogger(__name__)

# ── Compiled regex patterns ────────────────────────────────────────────────────

# CVE-YYYY-NNNNN  (year 1999-2099, 4+ digit sequence number)
_RE_CVE = re.compile(
    r"\bCVE-(?:19|20)\d{2}-\d{4,}\b",
    re.IGNORECASE,
)

_RE_TTP = re.compile(r'^T\d{4}(\.\d{3})?$')

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

# DOMAIN: stricter regex requiring valid TLDs or common domain structures
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|org|net|edu|gov|mil|int|io|co|me|xyz|biz|info|dev|tech|app|ru|cn|uk|de|jp|us|uk|vn|us)\b",
)

# Cryptographic hashes — distinguished by length, all hex characters
_RE_MD5    = re.compile(r"\b[0-9A-Fa-f]{32}\b")
_RE_SHA1   = re.compile(r"\b[0-9A-Fa-f]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9A-Fa-f]{64}\b")


# ── System / Software patterns ─────────────────────────────────────────────────

_SYSTEM_PATTERNS: list[tuple[str, re.Pattern]] = [
    # ── Databases ──────────────────────────────────────────────────────────
    ("MySQL",           re.compile(r'\bMySQL\b',                    re.IGNORECASE)),
    ("PostgreSQL",      re.compile(r'\bPostgreSQL\b',               re.IGNORECASE)),
    ("MongoDB",         re.compile(r'\bMongoDB\b',                  re.IGNORECASE)),
    ("Oracle DB",       re.compile(r'\bOracle\s*(?:DB|Database)?\b',re.IGNORECASE)),
    ("MSSQL",           re.compile(r'\bMSSQL|SQL\s*Server\b',       re.IGNORECASE)),
    ("Redis",           re.compile(r'\bRedis\b',                    re.IGNORECASE)),
    ("Elasticsearch",   re.compile(r'\bElasticsearch\b',            re.IGNORECASE)),
    ("MariaDB",         re.compile(r'\bMariaDB\b',                  re.IGNORECASE)),
    ("SQLite",          re.compile(r'\bSQLite\b',                   re.IGNORECASE)),
    ("Cassandra",       re.compile(r'\bCassandra\b',                re.IGNORECASE)),
    ("CouchDB",         re.compile(r'\bCouchDB\b',                  re.IGNORECASE)),
    ("InfluxDB",        re.compile(r'\bInfluxDB\b',                 re.IGNORECASE)),
    ("DynamoDB",        re.compile(r'\bDynamoDB\b',                 re.IGNORECASE)),
    ("Memcached",       re.compile(r'\bMemcached\b',                re.IGNORECASE)),
    ("Neo4j",           re.compile(r'\bNeo4j\b',                    re.IGNORECASE)),

    # ── Operating Systems ──────────────────────────────────────────────────
    ("Windows Server",  re.compile(r'\bWindows\s*Server\s*(?:200[389]|201[269]|2022)?\b', re.IGNORECASE)),
    ("Windows 10",      re.compile(r'\bWindows\s*10\b',             re.IGNORECASE)),
    ("Windows 11",      re.compile(r'\bWindows\s*11\b',             re.IGNORECASE)),
    ("Windows XP",      re.compile(r'\bWindows\s*XP\b',             re.IGNORECASE)),
    ("Windows 7",       re.compile(r'\bWindows\s*7\b',              re.IGNORECASE)),
    ("Ubuntu",          re.compile(r'\bUbuntu\b',                   re.IGNORECASE)),
    ("Debian",          re.compile(r'\bDebian\b',                   re.IGNORECASE)),
    ("CentOS",          re.compile(r'\bCentOS\b',                   re.IGNORECASE)),
    ("Red Hat",         re.compile(r'\bRed\s*Hat(?:\s*Enterprise\s*Linux)?\b', re.IGNORECASE)),
    ("Fedora",          re.compile(r'\bFedora\b',                   re.IGNORECASE)),
    ("Kali Linux",      re.compile(r'\bKali(?:\s*Linux)?\b',        re.IGNORECASE)),
    ("macOS",           re.compile(r'\bmacOS|Mac\s*OS\s*X\b',       re.IGNORECASE)),
    ("iOS",             re.compile(r'\biOS\b',                      re.IGNORECASE)),
    ("Android",         re.compile(r'\bAndroid\b',                  re.IGNORECASE)),
    ("FreeBSD",         re.compile(r'\bFreeBSD\b',                  re.IGNORECASE)),
    ("OpenBSD",         re.compile(r'\bOpenBSD\b',                  re.IGNORECASE)),

    # ── Web Servers ────────────────────────────────────────────────────────
    ("Apache HTTP",     re.compile(r'\bApache\s*(?:HTTP\s*Server|HTTPD)?\b', re.IGNORECASE)),
    ("Nginx",           re.compile(r'\bNginx\b',                    re.IGNORECASE)),
    ("IIS",             re.compile(r'\bIIS|Internet\s*Information\s*Services\b', re.IGNORECASE)),
    ("Tomcat",          re.compile(r'\b(?:Apache\s*)?Tomcat\b',     re.IGNORECASE)),
    ("LiteSpeed",       re.compile(r'\bLiteSpeed\b',                re.IGNORECASE)),
    ("Caddy",           re.compile(r'\bCaddy\s*(?:Server)?\b',      re.IGNORECASE)),

    # ── CMS / Web Platforms ────────────────────────────────────────────────
    ("WordPress",       re.compile(r'\bWordPress\b',                re.IGNORECASE)),
    ("Drupal",          re.compile(r'\bDrupal\b',                   re.IGNORECASE)),
    ("Joomla",          re.compile(r'\bJoomla\b',                   re.IGNORECASE)),
    ("Magento",         re.compile(r'\bMagento\b',                  re.IGNORECASE)),
    ("Shopify",         re.compile(r'\bShopify\b',                  re.IGNORECASE)),
    ("Confluence",      re.compile(r'\bConfluence\b',               re.IGNORECASE)),
    ("Jira",            re.compile(r'\bJira\b',                     re.IGNORECASE)),

    # ── Cloud Platforms ────────────────────────────────────────────────────
    ("AWS",             re.compile(r'\bAWS|Amazon\s*Web\s*Services\b', re.IGNORECASE)),
    ("Azure",           re.compile(r'\bAzure|Microsoft\s*Azure\b',  re.IGNORECASE)),
    ("GCP",             re.compile(r'\bGCP|Google\s*Cloud(?:\s*Platform)?\b', re.IGNORECASE)),
    ("AWS S3",          re.compile(r'\bS3|Amazon\s*S3\b',           re.IGNORECASE)),
    ("AWS EC2",         re.compile(r'\bEC2|Amazon\s*EC2\b',         re.IGNORECASE)),
    ("AWS Lambda",      re.compile(r'\bLambda|AWS\s*Lambda\b',      re.IGNORECASE)),
    ("Cloudflare",      re.compile(r'\bCloudflare\b',               re.IGNORECASE)),
    ("DigitalOcean",    re.compile(r'\bDigitalOcean\b',             re.IGNORECASE)),
    ("Heroku",          re.compile(r'\bHeroku\b',                   re.IGNORECASE)),

    # ── Containers / Orchestration ─────────────────────────────────────────
    ("Docker",          re.compile(r'\bDocker\b',                   re.IGNORECASE)),
    ("Kubernetes",      re.compile(r'\bKubernetes|K8s\b',           re.IGNORECASE)),
    ("Helm",            re.compile(r'\bHelm\b',                     re.IGNORECASE)),
    ("Podman",          re.compile(r'\bPodman\b',                   re.IGNORECASE)),
    ("OpenShift",       re.compile(r'\bOpenShift\b',                re.IGNORECASE)),

    # ── Microsoft Enterprise ───────────────────────────────────────────────
    ("Exchange",        re.compile(r'\bMicrosoft\s*Exchange|Exchange\s*Server\b', re.IGNORECASE)),
    ("SharePoint",      re.compile(r'\bSharePoint\b',               re.IGNORECASE)),
    ("Active Directory",re.compile(r'\bActive\s*Directory|LDAP\b',  re.IGNORECASE)),
    ("Office 365",      re.compile(r'\bOffice\s*365|Microsoft\s*365|M365\b', re.IGNORECASE)),
    ("Teams",           re.compile(r'\bMicrosoft\s*Teams\b',        re.IGNORECASE)),
    ("Outlook",         re.compile(r'\bMicrosoft\s*Outlook|Outlook\b', re.IGNORECASE)),
    ("OneDrive",        re.compile(r'\bOneDrive\b',                 re.IGNORECASE)),
    ("Hyper-V",         re.compile(r'\bHyper-V\b',                  re.IGNORECASE)),
    ("SCCM",            re.compile(r'\bSCCM|System\s*Center\b',     re.IGNORECASE)),

    # ── Remote Access / VPN ────────────────────────────────────────────────
    ("Citrix",          re.compile(r'\bCitrix\b',                   re.IGNORECASE)),
    ("Pulse Secure",    re.compile(r'\bPulse\s*(?:Secure|VPN)?\b',  re.IGNORECASE)),
    ("GlobalProtect",   re.compile(r'\bGlobalProtect|Palo\s*Alto\s*VPN\b', re.IGNORECASE)),
    ("Fortinet VPN",    re.compile(r'\bFortiGate|FortiVPN|Fortinet\b', re.IGNORECASE)),
    ("SonicWall",       re.compile(r'\bSonicWall\b',                re.IGNORECASE)),
    ("OpenVPN",         re.compile(r'\bOpenVPN\b',                  re.IGNORECASE)),
    ("WireGuard",       re.compile(r'\bWireGuard\b',                re.IGNORECASE)),
    ("Cisco AnyConnect",re.compile(r'\bCisco\s*AnyConnect|AnyConnect\b', re.IGNORECASE)),
    ("RDP",             re.compile(r'\bRDP|Remote\s*Desktop\b',     re.IGNORECASE)),
    ("TeamViewer",      re.compile(r'\bTeamViewer\b',               re.IGNORECASE)),
    ("AnyDesk",         re.compile(r'\bAnyDesk\b',                  re.IGNORECASE)),

    # ── Network Devices ────────────────────────────────────────────────────
    ("Cisco IOS",       re.compile(r'\bCisco\s*(?:IOS|Router|Switch)?\b', re.IGNORECASE)),
    ("Juniper",         re.compile(r'\bJuniper\b',                  re.IGNORECASE)),
    ("Palo Alto",       re.compile(r'\bPalo\s*Alto\b',              re.IGNORECASE)),
    ("F5 BIG-IP",       re.compile(r'\bF5|BIG-IP\b',                re.IGNORECASE)),
    ("Barracuda",       re.compile(r'\bBarracuda\b',                re.IGNORECASE)),
    ("Checkpoint",      re.compile(r'\bCheck\s*Point\b',            re.IGNORECASE)),
    ("Netscaler",       re.compile(r'\bNetScaler|Citrix\s*ADC\b',   re.IGNORECASE)),

    # ── Development Frameworks / Languages ────────────────────────────────
    ("Log4j",           re.compile(r'\bLog4j(?:2)?\b',              re.IGNORECASE)),
    ("Apache Struts",   re.compile(r'\bApache\s*Struts\b',          re.IGNORECASE)),
    ("Spring",          re.compile(r'\bSpring(?:\s*Boot|Framework)?\b', re.IGNORECASE)),
    ("Node.js",         re.compile(r'\bNode\.?js\b',                re.IGNORECASE)),
    ("PHP",             re.compile(r'\bPHP\b',                      re.IGNORECASE)),
    ("Python",          re.compile(r'\bPython\b',                   re.IGNORECASE)),
    ("Ruby on Rails",   re.compile(r'\bRuby\s*(?:on\s*Rails)?\b',   re.IGNORECASE)),
    ("Java",            re.compile(r'\bJava\b(?!\s*Script)',         re.IGNORECASE)),
    ("JavaScript",      re.compile(r'\bJavaScript\b',               re.IGNORECASE)),
    ("PowerShell",      re.compile(r'\bPowerShell\b',               re.IGNORECASE)),
    ("Bash",            re.compile(r'\bBash|Shell\s*Script\b',      re.IGNORECASE)),

    # ── Security Tools ─────────────────────────────────────────────────────
    ("OpenSSL",         re.compile(r'\bOpenSSL\b',                  re.IGNORECASE)),
    ("OpenSSH",         re.compile(r'\bOpenSSH\b',                  re.IGNORECASE)),
    ("Samba",           re.compile(r'\bSamba\b',                    re.IGNORECASE)),
    ("Sudo",            re.compile(r'\bSudo\b',                     re.IGNORECASE)),
    ("Polkit",          re.compile(r'\bPolkit|pkexec\b',            re.IGNORECASE)),
    ("NSS",             re.compile(r'\bNSS|Name\s*Service\s*Switch\b', re.IGNORECASE)),

    # ── Email / Messaging ──────────────────────────────────────────────────
    ("Postfix",         re.compile(r'\bPostfix\b',                  re.IGNORECASE)),
    ("Sendmail",        re.compile(r'\bSendmail\b',                 re.IGNORECASE)),
    ("Zimbra",          re.compile(r'\bZimbra\b',                   re.IGNORECASE)),
    ("Roundcube",       re.compile(r'\bRoundcube\b',                re.IGNORECASE)),
    ("Slack",           re.compile(r'\bSlack\b',                    re.IGNORECASE)),
    ("Zoom",            re.compile(r'\bZoom\b',                     re.IGNORECASE)),

    # ── SCADA / ICS / OT ──────────────────────────────────────────────────
    ("SCADA",           re.compile(r'\bSCADA\b',                    re.IGNORECASE)),
    ("Modbus",          re.compile(r'\bModbus\b',                   re.IGNORECASE)),
    ("DNP3",            re.compile(r'\bDNP3\b',                     re.IGNORECASE)),
    ("PLC",             re.compile(r'\bPLC|Programmable\s*Logic\s*Controller\b', re.IGNORECASE)),
    ("HMI",             re.compile(r'\bHMI|Human.Machine\s*Interface\b', re.IGNORECASE)),
    ("Siemens",         re.compile(r'\bSiemens\b',                  re.IGNORECASE)),
    ("Schneider",       re.compile(r'\bSchneider\s*Electric\b',     re.IGNORECASE)),

    # ── Protocols / Services ──────────────────────────────────────────────
    ("SMB",             re.compile(r'\bSMB|Server\s*Message\s*Block\b', re.IGNORECASE)),
    ("SSH",             re.compile(r'\bSSH\b',                      re.IGNORECASE)),
    ("FTP",             re.compile(r'\bFTPS?\b',                    re.IGNORECASE)),
    ("Telnet",          re.compile(r'\bTelnet\b',                   re.IGNORECASE)),
    ("SNMP",            re.compile(r'\bSNMP\b',                     re.IGNORECASE)),
    ("DNS",             re.compile(r'\bDNS\b',                      re.IGNORECASE)),
    ("LDAP",            re.compile(r'\bLDAPS?\b',                   re.IGNORECASE)),
    ("Kerberos",        re.compile(r'\bKerberos\b',                 re.IGNORECASE)),
    ("NTLM",            re.compile(r'\bNTLM\b',                     re.IGNORECASE)),
    ("OAuth",           re.compile(r'\bOAuth\b',                    re.IGNORECASE)),
    ("SAML",            re.compile(r'\bSAML\b',                     re.IGNORECASE)),
    ("JWT",             re.compile(r'\bJWT|JSON\s*Web\s*Token\b',   re.IGNORECASE)),
]
# ── False-positive suppression ─────────────────────────────────────────────────

# Common tokens that match the domain regex but are not IOCs
_DOMAIN_STOPWORDS: frozenset[str] = frozenset({
    "example.com", "localhost.localdomain", "test.local",
    "schema.org", "w3.org", "xmlns.com", "google.com",
    "github.com", "microsoft.com", "apple.com", "amazon.com",
    "twitter.com", "facebook.com", "linkedin.com", "youtube.com",
    "wikipedia.org", "yahoo.com", "reddit.com", "nvd.nist.gov",
    "cve.mitre.org", "mitre.org", "nist.gov", "alienvault.com",
    "exploit-db.com"
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

    # Hashes first so long hex strings are claimed before domain regex runs.
    # Track captured spans to prevent shorter patterns re-matching inside a
    # longer hash that was already captured (e.g. MD5 re-matching inside SHA256).
    captured_spans: set[tuple[int, int]] = set()

    def _span_is_free(m: re.Match) -> bool:
        """Return True if this match does not overlap any already-captured span."""
        s, e = m.start(), m.end()
        return not any(s < ce and e > cs for cs, ce in captured_spans)

    for match in _RE_SHA256.finditer(text):
        if _span_is_free(match):
            captured_spans.add((match.start(), match.end()))
            _add("SHA256", match.group())

    for match in _RE_SHA1.finditer(text):
        if _span_is_free(match):
            captured_spans.add((match.start(), match.end()))
            _add("SHA1", match.group())

    for match in _RE_MD5.finditer(text):
        if _span_is_free(match):
            captured_spans.add((match.start(), match.end()))
            _add("MD5", match.group())
            
    # CVEs
    for match in _RE_CVE.finditer(text):
        _add("CVE", match.group().upper())

    # TTPS
    for match in _RE_TTP.finditer(text):
        _add("TTP", match.group().upper())

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
        # Skip if any segment looks like a version number or single letter (e.g., "v1.2.3" or "a.b")
        segments = val.split(".")
        if any(len(seg) <= 1 or seg.isdigit() for seg in segments if seg):
            continue
        # Skip single-segment TLD matches (e.g., "sentence.It" where "It" is 2-letter TLD)
        if len(segments) < 2:
            continue
        # Avoid re-capturing things already tagged as IPv4
        if any(e.entity_value == match.group() and e.entity_type == "IPv4"
               for e in results):
            continue
        _add("DOMAIN", val)

    return results

def extract_systems(text: str) -> list[ExtractedEntity]:
    """
    Scans text for known software/system names using the _SYSTEM_PATTERNS list.
    Returns deduplicated ExtractedEntity objects with type 'SYSTEM/SOFTWARE'.
    """
    if not text or not isinstance(text, str):
        return []

    seen:    set[str] = set()
    results: list[ExtractedEntity] = []

    for name, pattern in _SYSTEM_PATTERNS:
        if pattern.search(text):
            key = name.lower()
            if key not in seen:
                seen.add(key)
                results.append(ExtractedEntity(
                    entity_type="SYSTEM/SOFTWARE",
                    entity_value=name,
                ))

    return results

def extract_and_store(source_id: int, cleaned_text: str) -> list[ExtractedEntity]:
    """
    Extract all IOCs and SOFTWARE mentions from *cleaned_text* and persist
    each one to the ``entities`` table linked to *source_id*.
    """
    # Existing IOC extraction
    entities = extract_entities(cleaned_text)
    
    # New software/system extraction
    system_entities = extract_systems(cleaned_text)
    entities.extend(system_entities)

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
        "[entity_extractor] source_id=%d → %d entities extracted "
        "(%d IOCs + %d SOFTWARE)",
        source_id, len(entities), len(entities) - len(system_entities),
        len(system_entities),
    )
    return entities
