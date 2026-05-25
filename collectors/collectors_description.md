# LLM-Based Threat Intelligence Gathering System: Collectors Architecture

The Collectors layer is responsible for ingesting raw threat intelligence data from external sources and persisting it to the SQLite `raw_items` table. It is the entry point of the entire pipeline — no enrichment, translation, or LLM inference occurs here. All collectors share a common abstract base and enforce consistent deduplication, rate-limiting, and normalization contracts.

---

## Design Pattern: Abstract Base + Concrete Subclasses

All collectors inherit from `BaseCollector` and must implement three abstract methods: `fetch_by_time()`, `fetch_by_keyword()`, and `normalize()`. This guarantees every collector produces the same standardized record dict shape, which `sqlite_manager.insert_raw_item()` and the downstream preprocessor expect.

The base class also provides:
- **`collect_and_store()`** — chains fetch → DB insert in one call, routing through `db/sqlite_manager.py` to maintain strict SQL isolation.
- **`format_record()`** — produces the standard DB-ready dict with a consistent set of fields (`source`, `title`, `description`, `source_url`, `published_date`, `collected_at`, `raw`, `dedup_key`).
- **`_throttle()`** — enforces a minimum per-subclass delay between HTTP requests to respect API rate limits.
- **`_make_dedup_key()`** — default SHA-256 fingerprint over `source + title + description[:300]`. Subclasses override this when a structural ID (CVE ID, pulse ID) is available.

A `USE_GRAPH` environment toggle exists in the base class as a **Strangler Fig** migration flag. When `True`, records are routed to Neo4j instead of SQLite — this path is not yet implemented and is reserved for a future architecture phase.

---

## Component 1: NVD Collector (`nvd_collector.py`)

- **Source:** NIST National Vulnerability Database REST API v2
- **Auth:** Optional API key via `NVD_API_KEY` env var. Without a key, rate limit is 5 requests / 30s (`DEFAULT_DELAY = 6.0s`). With a key, 50 requests / 30s (`DEFAULT_DELAY = 0.6s`).
- **`fetch_by_time()`:** Supports two modes — a rolling window (`days_back`) and a full calendar year (`year`). Year mode automatically chunks requests into four quarters to stay within NVD's 120-day window limit.
- **`fetch_by_keyword()`:** Detects whether the query is a bare CVE ID (via regex) and routes to a dedicated exact-ID endpoint, or falls back to NVD's full-text `keywordSearch`.
- **`normalize()`:** Extracts English description, CVSS score/severity/vector, CWE IDs, and affected software names from CPE strings. CPE parsing produces `vendor_product` strings (e.g. `apache_log4j`) for the graph's `AFFECTS` edges. Only application (`a`) and OS (`o`) CPE types are included; hardware (`h`) is skipped.
- **Dedup key:** SHA-256 of `nvd:id:<CVE_ID>` — hashing the immutable CVE ID ensures upsert behaviour when a CVE's CVSS score is updated on re-fetch.

---

## Component 2: AlienVault OTX Collector (`otx_collector.py`)

- **Source:** AlienVault OTX Pulse API v1
- **Auth:** Required API key via `OTX_API_KEY` env var.
- **`fetch_by_time()`:** Uses OTX's `modified_since` activity endpoint. Supports `days_back` and `year` modes. OTX returns at most 50 pulses per page; pagination follows the `next` URL OTX provides.
- **`fetch_by_keyword()`:** Hits OTX's `/search/pulses` endpoint for full-text search across pulse title, description, and tags.
- **`fetch_by_cve_id()`:** Dedicated method using OTX's `/indicator/CVE/<id>/general` endpoint. More precise than keyword search — returns only pulses that explicitly tagged the CVE as an IOC, along with structurally linked threat actors and malware families.
- **`normalize()`:** Extracts pulse name, description (falls back to tags if empty), adversary, malware families, ATT&CK IDs, and per-type IOC counts.
- **Dedup key:** SHA-256 of `alienvault:id:<pulse_id>` — the immutable pulse ID is used so content updates do not create duplicate rows.

---

## Component 3: RSS Collector (`rss_collector.py`)

- **Source:** Any RSS/Atom feed. Pre-configured feeds include Exploit-DB, BleepingComputer, SANS ISC, Packet Storm, Xakep (Russian), and four Reddit security subreddits (`r/netsec`, `r/cybersecurity`, `r/blueteamsec`, `r/redteamsec`). Reddit feeds require no API key.
- **`fetch_by_time()`:** Pulls the full feed, then filters client-side by parsed publication date. Supports `days_back` and `year` modes.
- **`fetch_by_keyword()`:** Pulls the full feed, then applies AND logic across all query terms against each entry's title and summary.
- **Full-text scraping strategy:** For each entry, the collector attempts to scrape the full article text from the entry's URL. It tries domain-specific CSS selectors defined in `DOMAIN_CONFIG` in order, then validates the result (must be longer than the RSS summary and must not contain paywall marker strings). If validation fails, it falls back to the RSS summary. This logic lives in `_scrape_full_text()`.
- **`DOMAIN_CONFIG`:** A per-domain dictionary of CSS selector chains and paywall marker strings. Xakep.ru has a dedicated config due to its subscription paywall. The `default` config covers standard WordPress/CMS layouts.
- **Dedup key:** SHA-256 of `<source>:id:<entry_id>` using the RSS entry's own ID or URL — prevents false duplicates when a page's sidebar or navbar content changes between fetches.

---

## Component 4: Baseline Graph Builders (`sync_mitre_baseline.py`, `sync_nvd_baseline.py`)

These scripts are **run once** during first-time setup to populate the Neo4j Knowledge Graph. They are not part of the daily OSINT pipeline.

### `sync_mitre_baseline.py`
Downloads the MITRE ATT&CK Enterprise STIX 2.1 feed, embeds each technique description using `all-MiniLM-L6-v2`, merges `MITRE_TTP` nodes into Neo4j, and builds `TARGETS` edges to platform/software nodes from the `x_mitre_platforms` field. After all nodes are written, it creates the `threat_embeddings_index` vector index (384 dimensions, cosine similarity) using `IF NOT EXISTS` so re-runs are safe.

### `sync_nvd_baseline.py`
Orchestrates a full year-by-year CVE sync from 1999 to the current year. For each year it calls `NVDCollector.fetch_by_time(year=...)`, embeds descriptions, merges `CVE` nodes, builds `AFFECTS` edges from CPE data, and applies `EXPLOITS_TECHNIQUE` edges using the CTID CVE→ATT&CK mapping CSV.

Key design decisions:
- **CTID mapping:** The NVD API maps CVEs to CWE weakness IDs, not MITRE ATT&CK techniques. The CTID (Center for Threat-Informed Defense) public CSV provides a curated, authoritative CVE→TTP mapping. `fetch_ctid_mapping()` downloads and parses this CSV once, producing a `{ "CVE-XXXX-YYYY": ["T1190", ...] }` dict reused across all years.
- **Checkpoint system:** Progress is saved to `data/nvd_sync_state.json` after every successfully completed year. Failed years are recorded separately. CLI flags `--retry` and `--reset` allow targeted reruns without redoing completed work.
- **Run order:** `sync_mitre_baseline.py` must run first so that `MITRE_TTP` nodes exist before `sync_nvd_baseline.py` attempts to create `EXPLOITS_TECHNIQUE` edges into them.

---

## Component 5: Periodic Graph Updater (`backfiller.py`)

Runs on a schedule (e.g. weekly cron) to keep the Knowledge Graph current after the initial baseline sync. Provides two independent tasks selectable via CLI prompt:

- **Task 1 — NVD Sliding Window:** Fetches CVEs published or modified in the last 30 days, re-embeds, and merges into Neo4j. Applies CTID mappings to any new CVEs. Safe to re-run — Neo4j `MERGE` is idempotent.
- **Task 2 — MITRE Re-Sync:** Re-downloads the full MITRE STIX feed and merges updated techniques. Existing nodes are updated in-place via `MERGE + SET`; no index rebuild is needed since new nodes are automatically covered by the existing vector index.

Checkpoint state is saved to `data/sync_state.json` recording the UTC timestamp of the last successful run for each task.
