# API Reference

> LLM-Based Threat Intelligence Gathering System  
> IT4413E — Penetration Testing | HUST SOICT | 2025

All public methods across `collectors/` and `db/queries.py`.
Internal helpers (prefixed `_`) are documented in source docstrings only.

---

## Table of Contents

1. [BaseCollector](#basecollector)
2. [NVDCollector](#nvdcollector)
3. [OTXCollector](#otxcollector)
4. [RSSCollector](#rsscollector)
5. [db/queries.py](#dbqueriespy)
6. [Record Schema](#record-schema)
7. [Error Handling](#error-handling)

---

## BaseCollector

`collectors/base_collector.py`

Abstract base class. Cannot be instantiated directly. All collectors inherit from this.

---

### `__init__(source_name)`

```python
def __init__(self, source_name: str) -> None
```

| Parameter | Type | Description |
|---|---|---|
| `source_name` | `str` | Identifier written to every record's `source` field. E.g. `"nvd"`, `"alienvault"` |

---

### `fetch_by_time()` *(abstract)*

```python
def fetch_by_time(
    days_back: int | None = 7,
    year: int | None = None,
    max_results: int = 200,
) -> list[dict[str, Any]]
```

Fetch records within a time window. Implemented by each subclass.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `days_back` | `int \| None` | `7` | Rolling window: fetch records from last N days. Ignored if `year` is set. |
| `year` | `int \| None` | `None` | Full calendar year, e.g. `2021`. Takes priority over `days_back`. |
| `max_results` | `int` | `200` | Hard cap on total records returned. |

**Returns:** `list[dict]` — normalised records matching `format_record()` schema.

**Complexity:** O(N/P) requests where N = matching records, P = page size.

**Examples:**
```python
col.fetch_by_time()                              # last 7 days, all
col.fetch_by_time(days_back=30)                  # last 30 days
col.fetch_by_time(year=2021)                     # full year 2021
col.fetch_by_time(year=2021, max_results=500)    # capped at 500
```

---

### `fetch_by_keyword()` *(abstract)*

```python
def fetch_by_keyword(
    query: str,
    max_results: int = 20,
) -> list[dict[str, Any]]
```

Search by keyword, phrase, or CVE ID. Matching behaviour varies by source
(see subclass docs). Generally: partial match, case-insensitive, no exact
match required.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `query` | `str` | — | Search term. Plain word, phrase, or CVE ID. |
| `max_results` | `int` | `20` | Hard cap on results. |

**Returns:** `list[dict]` — normalised records.

**Complexity:** O(K/P) requests where K = matching records.

**Examples:**
```python
col.fetch_by_keyword("WannaCry")           # plain keyword
col.fetch_by_keyword("wanna")              # partial, still matches WannaCry
col.fetch_by_keyword("apache log4j")       # phrase, both words required
col.fetch_by_keyword("CVE-2021-44228")     # CVE ID (NVD routes to exact endpoint)
```

---

### `collect_and_store()`

```python
def collect_and_store(
    db_path: Path,
    mode: str = "time",
    **fetch_kwargs: Any,
) -> tuple[int, int]
```

Chains fetch → DB insert in one call. Concrete method — available on all
subclasses without override.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `db_path` | `Path` | — | Path to SQLite database file. |
| `mode` | `str` | `"time"` | `"time"` → calls `fetch_by_time(**fetch_kwargs)`. `"keyword"` → calls `fetch_by_keyword(**fetch_kwargs)`. |
| `**fetch_kwargs` | — | — | Forwarded to the chosen fetch method. |

**Returns:** `(inserted: int, skipped: int)` — inserted = new records, skipped = duplicates blocked by `dedup_key`.

**Complexity:** O(N · log M) where N = fetched records, M = existing DB rows.

**Examples:**
```python
nvd.collect_and_store(DB_PATH, mode="time", days_back=7)
nvd.collect_and_store(DB_PATH, mode="time", year=2021, cvss_severity="CRITICAL")
otx.collect_and_store(DB_PATH, mode="keyword", query="WannaCry")
```

---

### `format_record()`

```python
def format_record(
    title: str | None,
    description: str | None,
    url: str | None,
    published_date: str | None,
    raw: dict | None = None,
) -> dict[str, Any]
```

Concrete helper. Produces the standard DB-ready dict. All subclass
`normalize()` methods must call this for every record.

| Parameter | Type | Description |
|---|---|---|
| `title` | `str \| None` | Record title. CVE-ID for NVD, pulse name for OTX. Stripped of whitespace. |
| `description` | `str \| None` | Full text description. Stripped of whitespace. |
| `url` | `str \| None` | Source URL for the original item. |
| `published_date` | `str \| None` | ISO-8601 or RFC-2822 date string from the source. |
| `raw` | `dict \| None` | Source-specific extras (CVSS, IOC counts, etc.). Stored as JSON blob. |

**Returns:** `dict` with keys: `source`, `title`, `description`, `source_url`,
`published_date`, `collected_at`, `processed`, `raw`, `dedup_key`.

**Complexity:** O(1) — SHA-256 computed on fixed-length input (capped at 300 chars).

---

## NVDCollector

`collectors/nvd_collector.py`

Fetches CVE data from NVD REST API v2.

**Rate limits:**
- No key: 5 req / 30 s → `DEFAULT_DELAY = 6.0 s`
- With key: 50 req / 30 s → `DEFAULT_DELAY = 0.6 s`

---

### `__init__(api_key)`

```python
def __init__(self, api_key: str | None = None) -> None
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `api_key` | `str \| None` | `None` | NVD API key. Free at https://nvd.nist.gov/developers/request-an-api-key. Reduces delay from 6s to 0.6s. |

---

### `fetch_by_time()`

```python
def fetch_by_time(
    days_back: int | None = 7,
    year: int | None = None,
    max_results: int = 200,
    cvss_severity: str | None = None,
) -> list[dict[str, Any]]
```

Extends base with `cvss_severity` filter. All other parameters identical
to `BaseCollector.fetch_by_time()`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `cvss_severity` | `str \| None` | `None` | Filter by CVSS v3 severity. Accepted: `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`. Passed to NVD `cvssV3Severity` parameter — filtered server-side, no extra cost. `None` returns all severities. |

**Raises:** `ValueError` if `cvss_severity` is not a valid label.

**Examples:**
```python
nvd.fetch_by_time(days_back=7, cvss_severity="CRITICAL")
nvd.fetch_by_time(year=2021, cvss_severity="HIGH", max_results=500)
nvd.fetch_by_time(year=2023)    # all severities
```

---

### `fetch_by_keyword()`

```python
def fetch_by_keyword(
    query: str,
    max_results: int = 20,
) -> list[dict[str, Any]]
```

Auto-detects CVE ID format and routes accordingly:

- `query` matches `CVE-YYYY-NNNNN` → exact `cveId` NVD endpoint
- Otherwise → `keywordSearch` full-text endpoint (fuzzy, case-insensitive)

NVD's `keywordSearch` searches across CVE ID, description, and reference URLs.
Partial words work: `"wanna"` matches records containing "WannaCry".

**Complexity:**
- CVE-ID path: O(1) request
- Keyword path: O(K/P) requests, K = matching CVEs

---

### `normalize()`

```python
def normalize(self, raw_data: list[dict]) -> list[dict[str, Any]]
```

Converts raw NVD vulnerability containers to normalised records.

Extracted fields per record:

| Field | Source | Location in NVD response |
|---|---|---|
| `title` | CVE ID | `cve.id` |
| `description` | English description | `cve.descriptions[lang=en].value` |
| `published_date` | Publish date | `cve.published` |
| `raw.cvss_score` | CVSS base score | `metrics.cvssMetricV31[0].cvssData.baseScore` |
| `raw.cvss_severity` | Severity label | `metrics.cvssMetricV31[0].cvssData.baseSeverity` |
| `raw.cvss_vector` | Vector string | `metrics.cvssMetricV31[0].cvssData.vectorString` |
| `raw.cwes` | Weakness IDs | `weaknesses[].description[].value` (CWE-* only) |

CVSS preference order: v3.1 → v3.0 → v2.

---

## OTXCollector

`collectors/otx_collector.py`

Fetches threat pulse data from AlienVault OTX.
Free API key required: https://otx.alienvault.com

---

### `__init__(api_key)`

```python
def __init__(self, api_key: str | None = None) -> None
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `api_key` | `str \| None` | `None` | OTX API key. Falls back to `OTX_API_KEY` env var. Prints warning if not found. |

---

### `fetch_by_time()`

Same signature as `BaseCollector.fetch_by_time()`. Uses OTX activity feed
with `modified_since` parameter. Year mode uses Jan 1 of that year as cutoff.

Note: OTX paginates via a `next` URL in the response body.
`max_results` is respected by stopping pagination early.

---

### `fetch_by_keyword()`

```python
def fetch_by_keyword(
    query: str,
    max_results: int = 20,
) -> list[dict[str, Any]]
```

Hits OTX `/api/v1/search/pulses` endpoint.
Full-text search across pulse title, description, and tags.
Partial and case-insensitive matching supported server-side.

For CVE-ID specific lookup (pulses that structurally tagged this CVE
as an IOC), use `fetch_by_cve_id()` instead — more precise than keyword.

---

### `fetch_by_cve_id()` *(OTX only)*

```python
def fetch_by_cve_id(self, cve_id: str) -> list[dict[str, Any]]
```

Retrieves OTX pulses directly linked to a specific CVE ID via the
OTX indicator endpoint: `GET /api/v1/indicator/CVE/{cve_id}/general`

This is more precise than `fetch_by_keyword("CVE-XXXX")` because it returns
only pulses that **explicitly tagged** this CVE as an IOC, not pulses that
merely mention the ID in free text.

| Parameter | Type | Description |
|---|---|---|
| `cve_id` | `str` | CVE identifier. Normalised to uppercase. E.g. `"CVE-2017-0144"`. |

**Returns:** `list[dict]` — normalised pulse records. Each record includes
`raw["linked_cve"]` set to the queried CVE ID.

**Returns empty list** (not an error) if no pulses are linked.

**Complexity:** O(1) request + O(P) normalisation where P = pulses returned.

**Typical usage:**
```python
# Cross-source correlation:
# Step 1 — NVD gives you the CVE details
cve_record = nvd.fetch_by_keyword("CVE-2017-0144")[0]

# Step 2 — OTX shows which active campaigns exploit it
pulses = otx.fetch_by_cve_id("CVE-2017-0144")
# → WannaCry campaign, NotPetya campaign, etc.
```

---

### `normalize()`

Extracted fields per OTX pulse:

| Field | Source |
|---|---|
| `title` | `pulse.name` |
| `description` | `pulse.description` |
| `raw.adversary` | `pulse.adversary` |
| `raw.malware_families` | `pulse.malware_families[].display_name` |
| `raw.attack_ids` | `pulse.attack_ids[].id` — MITRE ATT&CK IDs if pulse author tagged them |
| `raw.ioc_counts` | Dict of `{type: count}` e.g. `{IPv4: 3, domain: 5}` |
| `raw.tags` | `pulse.tags` |

---

## RSSCollector

`collectors/rss_collector.py`

Fetches entries from public RSS feeds using `feedparser`.
No API key required.

**Available feeds:**

```python
KNOWN_FEEDS = {
    "exploitdb":         "https://www.exploit-db.com/rss.xml",
    "bleeping_computer": "https://www.bleepingcomputer.com/feed/",
    "sans_isc":          "https://isc.sans.edu/rssfeed_full.xml",
    "packet_storm":      "https://rss.packetstormsecurity.com/files/",
}
```

---

### `__init__(feed_url)`

```python
def __init__(self, feed_url: str = KNOWN_FEEDS["exploitdb"]) -> None
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `feed_url` | `str` | Exploit-DB RSS | URL of the RSS/Atom feed to fetch. |

---

### `fetch_by_time()`

Client-side filtering — full feed is pulled, then filtered by parsed
`published` date of each entry.

Both `days_back` and `year` modes supported. Date parsing handles RFC-2822
format (standard RSS) automatically via `email.utils.parsedate_to_datetime`.

**Limitation:** RSS feeds typically contain only the 50–100 most recent
entries. Historical year queries may return fewer results than expected
for older years.

---

### `fetch_by_keyword()`

Client-side filtering — full feed is pulled, then filtered by keyword
presence in `title` or `description`.

**Multi-word AND logic:** all words in `query` must appear.

```python
rss.fetch_by_keyword("apache rce")   # both "apache" AND "rce" must appear
rss.fetch_by_keyword("WannaCry")     # single term, case-insensitive partial match
```

**Complexity:** O(F) where F = feed entry count (typically 50–200).

---

## db/queries.py

`db/queries.py`

**Rule:** This is the only file that writes SQL. No other module in the
codebase may contain inline SQL statements.

---

### `get_processed_by_keyword()`

```python
def get_processed_by_keyword(
    query: str,
    db_path: Path = DB_PATH,
) -> list[dict[str, Any]]
```

Search processed records (`processed=1`) by keyword in title or description.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `query` | `str` | — | Search term, matched with SQL `LIKE %query%`. |
| `db_path` | `Path` | `DB_PATH` | Path to SQLite database. |

**Returns:** `list[dict]` ordered by `published_date DESC`. Empty list if not found.

**Complexity:** O(N · L) — full table scan with LIKE.
Add FTS5 virtual table if N > 100,000.

---

### `get_processed_by_cve_id()`

```python
def get_processed_by_cve_id(
    cve_id: str,
    db_path: Path = DB_PATH,
) -> dict[str, Any] | None
```

Exact CVE-ID lookup in processed records.

**Returns:** Single record dict, or `None` if not found.
Callers should handle `None` and display "Not found" to the user.

**Complexity:** O(N) — scan on `title` column.
Add `CREATE INDEX idx_raw_title ON raw_items(title)` if needed.

---

### `get_unprocessed_batch()`

```python
def get_unprocessed_batch(
    limit: int = 100,
    db_path: Path = DB_PATH,
) -> list[dict]
```

Returns up to `limit` records where `processed=0`, ordered by `collected_at`.
Used by `preprocessor/pipeline.py` to pull its next batch.

**Complexity:** O(log N + B) — index scan on `processed`, B = batch size.

---

### `mark_processed()`

```python
def mark_processed(
    item_id: int,
    db_path: Path = DB_PATH,
) -> None
```

Sets `processed=1` for the given `raw_items.id`.
Called by preprocessor after strip + dedup + encapsulate completes.

**Complexity:** O(log N) — primary key update.

---

### `insert_entity()`

```python
def insert_entity(
    source_id: int,
    entity_type: str,
    entity_value: str,
    confidence: float = 1.0,
    db_path: Path = DB_PATH,
) -> None
```

Insert a single extracted entity. Uses `INSERT OR IGNORE` so duplicate
(source_id, type, value) combinations are silently skipped.

| Parameter | Type | Description |
|---|---|---|
| `source_id` | `int` | Foreign key to `raw_items.id`. |
| `entity_type` | `str` | One of: `CVE`, `IPv4`, `IPv6`, `DOMAIN`, `MD5`, `SHA1`, `SHA256`, `MALWARE`, `THREAT_ACTOR`. |
| `entity_value` | `str` | The extracted value, e.g. `"192.168.1.1"`, `"WannaCry"`. |
| `confidence` | `float` | Confidence score 0.0–1.0. Default 1.0 for regex matches, lower for NER. |

**Complexity:** O(log E) — B-tree insert with UNIQUE constraint check.

---

## Record Schema

Every normalised record returned by collectors matches this schema:

```python
{
    "source":         str,   # "nvd" | "alienvault" | "exploit-db" | "reddit"
    "title":          str,   # CVE-ID, pulse name, or article title
    "description":    str,   # cleaned text description
    "source_url":     str,   # URL to original item
    "published_date": str,   # date string from source (ISO-8601 or RFC-2822)
    "collected_at":   str,   # ISO-8601 UTC timestamp of collection
    "processed":      int,   # always 0 at collection time
    "raw":            dict,  # source-specific extras (see per-collector docs)
    "dedup_key":      str,   # SHA-256 hex digest, 64 chars
}
```

The `raw` field contents by source:

**NVD:**
```python
{
    "cvss_score":    float | None,  # e.g. 9.8
    "cvss_severity": str | None,    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    "cvss_vector":   str | None,    # e.g. "CVSS:3.1/AV:N/AC:L/..."
    "cwes":          list[str],     # e.g. ["CWE-79", "CWE-89"]
}
```

**OTX:**
```python
{
    "adversary":        str,        # threat actor name if attributed
    "malware_families": list[str],  # e.g. ["WannaCry", "EternalBlue"]
    "attack_ids":       list[str],  # MITRE ATT&CK IDs if tagged
    "ioc_counts":       dict,       # e.g. {"IPv4": 3, "domain": 5, "FileHash-SHA256": 2}
    "tags":             list[str],  # pulse tags
    "linked_cve":       str,        # set only by fetch_by_cve_id()
}
```

**RSS / Exploit-DB:**
```python
{}   # no source-specific extras currently extracted
```

---

## Error Handling

All collector methods follow these conventions:

| Situation | Behaviour |
|---|---|
| Network error / timeout | Print `[!] <Source> error: <message>`, return empty list |
| HTTP 4xx / 5xx | `raise_for_status()` caught, print error, return empty list |
| CVE not found | Print `[!] CVE not found: <id>`, return empty list |
| No OTX pulses for CVE | Print `[!] No OTX pulses found for <id>`, return empty list |
| Invalid `cvss_severity` | Raise `ValueError` immediately with valid options listed |
| DB duplicate on insert | Silently skipped via `INSERT OR IGNORE` / `IntegrityError` catch |
| spaCy model not found | Raise `RuntimeError` with install instruction |
| Ollama not running | `ConnectionError` propagated — check with `check_ollama_running()` |

**No collector ever raises on network failure** — it logs and returns an empty
list so the pipeline can continue with other sources.