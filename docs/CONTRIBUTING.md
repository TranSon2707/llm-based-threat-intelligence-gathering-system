# Contributing Guide

> LLM-Based Threat Intelligence Gathering System  
> IT4413E - Penetration Testing | HUST SOICT | 2026

---

## Table of Contents

1. [Team Workflow](#team-workflow)
2. [Coding Standards](#coding-standards)
3. [How to Add a New Collector](#how-to-add-a-new-collector)
4. [How to Add a New Entity Type](#how-to-add-a-new-entity-type)
5. [How to Add a New Few-Shot Example](#how-to-add-a-new-few-shot-example)
6. [Git Workflow](#git-workflow)
7. [Testing Requirements](#testing-requirements)
8. [Absolute Rules](#absolute-rules)

---

## Team Workflow

### Branch ownership

Each team member works on their own branch. Never commit directly to `main`.

| Branch | Owner | Covers |
|---|---|---|
| `feat/collectors` | Cuong | `collectors/` |
| `feat/preprocessor` | Hai | `preprocessor/`, tests |
| `feat/enrichment` | Son | `enrichment/entity_extractor.py`, `enrichment/ner_spacy.py`, `cli/` |
| `feat/llm-chains` | Linh | `enrichment/attack_mapper.py`, `enrichment/report_generator.py`, `db/` |

---

## Coding Standards

### Python version and style

- Python 3.11.x required
- Docstrings on every public class and method

### No hardcoded values

| What | Where it goes |
|---|---|
| API keys | `.env` file, loaded via `python-dotenv` |
| File paths | `settings.yaml` or `config.py` |
| Model name | `settings.yaml` (`OLLAMA_MODEL`) |
| Batch sizes | `settings.yaml` (`BATCH_SIZE`) |
| DB path | `settings.yaml` (`DB_PATH`) |

```python
# wrong
conn = sqlite3.connect("data/threat_intel.db")

# correct
from config import DB_PATH
conn = sqlite3.connect(DB_PATH)
```

### No inline SQL

All SQLite logic lives strictly in `db/queries.py`. 

All Neo4j Knowledge Graph logic lives strictly in `db/graph_connector.py`. 

Every other module must import named functions from these files.

```python
# wrong - inline SQL/Cypher in preprocessor
conn.execute("UPDATE raw_items SET processed=1 WHERE id=?", (item_id,))

# correct
from db.queries import mark_processed
mark_processed(item_id)
```

---

## How to Add a New Collector

This is the most common contribution. Follow these steps exactly.

### Step 1 - Create the collector file

Create `collectors/<source_name>_collector.py`.
Subclass `BaseCollector` and implement the three required methods.

```python
# collectors/reddit_collector.py
from __future__ import annotations

from typing import Any
from collectors.base_collector import BaseCollector


class RedditCollector(BaseCollector):
    """
    Fetches posts from security subreddits via PRAW.
    Targets: r/netsec, r/cybersecurity.
    Free Reddit API credentials required.
    """

    DEFAULT_DELAY = 1.0

    def __init__(self, client_id: str, client_secret: str,
                user_agent: str = "llm-threat-intel/1.0") -> None:
        super().__init__(source_name="reddit")
        # initialise your API client here

    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 200,
    ) -> list[dict[str, Any]]:
        # implement time-windowed fetch
        ...

    def fetch_by_keyword(
        self,
        query: str,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        # implement keyword search
        ...

    def normalize(self, raw_data: list[Any]) -> list[dict[str, Any]]:
        records = []
        for post in raw_data:
            records.append(self.format_record(
                title          = post.title,
                description    = post.selftext,
                url            = f"https://reddit.com{post.permalink}",
                published_date = str(post.created_utc),
                raw            = {
                    "subreddit": post.subreddit.display_name,
                    "score":     post.score,
                    "author":    str(post.author),
                },
            ))
        return records
```

**Rules:**
- `source_name` must be lowercase, no spaces: `"reddit"`, `"virustotal"`
- `normalize()` must call `self.format_record()` for every item - never
construct the dict manually
- Never write to the DB inside a collector - use `collect_and_store()` from
the caller
- Set `DEFAULT_DELAY` appropriate to the source's rate limit
- **Shift-Left Deduplication:** You MUST override `_make_dedup_key()` to hash the source's immutable structural ID (e.g., `pulse_id`, `cve_id`, `post_id`) rather than the description. This ensures SQLite `ON CONFLICT DO UPDATE` correctly captures evolving threats.

### Step 2 - Add dependencies

Add any new libraries to `requirements.txt`:

```
praw>=7.7.0
```

### Step 3 - Add to settings

Register the new source in `settings.yaml`:

```yaml
collectors:
nvd:      enabled: true
otx:      enabled: true
exploitdb: enabled: true
reddit:   enabled: true    # ← add this
```

### Step 4 - Wire into CLI

In `cli/main.py`, add the new collector to the `collect` subcommand:

```python
# cli/main.py - inside build_collectors()
if settings.collectors.reddit.enabled:
    from collectors.reddit_collector import RedditCollector
    collectors.append(RedditCollector(
        client_id     = os.getenv("REDDIT_CLIENT_ID"),
        client_secret = os.getenv("REDDIT_CLIENT_SECRET"),
    ))
```

Add the credentials to `.env.example`:

```bash
REDDIT_CLIENT_ID=
REDDIT_CLIENT_SECRET=
```

### Step 5 - Write tests

Create `tests/test_reddit_collector.py`.
At minimum, test:

```python
def test_normalize_produces_required_keys():
    """Every record must have all format_record() keys including dedup_key."""

def test_dedup_key_is_deterministic():
    """Same input always produces same dedup_key."""

def test_fetch_by_keyword_returns_list():
    """fetch_by_keyword always returns list, never raises on empty result."""

def test_fetch_by_time_year_mode():
    """year= parameter restricts results to that calendar year."""
```

### Step 6 - Update docs

Add the new source to:
- `ARCHITECTURE.md` - Sources table in Stage 1
- `API_REFERENCE.md` - New section under the collector headers
- `README.md` - Data Sources table

---

## How to Add a New Entity Type

Entity types are extracted in `enrichment/entity_extractor.py` (regex) and
`enrichment/ner_spacy.py` (NER).

### Adding a regex entity type

```python
# enrichment/entity_extractor.py

# 1. Define the compiled pattern
_RE_BTC_ADDRESS = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

# 2. Add extraction in extract_entities() in the correct order
# (hashes first, then structured IDs, then freeform text last)
for match in _RE_BTC_ADDRESS.finditer(text):
    _add("BTC_ADDRESS", match.group())

# 3. Add the new type to the docstring entity type list at the top of the file
```

### Adding a NER pattern (malware or threat actor)

```python
# enrichment/ner_spacy.py - add to the appropriate list

MALWARE_PATTERNS.append(
    {"label": "MALWARE", "pattern": "BlackBasta"}
)

APT_PATTERNS.append(
    {"label": "THREAT_ACTOR", "pattern": "Volt Typhoon"}
)
```

Pattern format supports:
- Single string: `{"label": "MALWARE", "pattern": "WannaCry"}`
- Token list: `{"label": "THREAT_ACTOR", "pattern": [{"LOWER": "apt"}, {"TEXT": "41"}]}`

### Registering in the Database

**(SQLite):** If the new entity type needs to be stored in the relational database, `insert_entity()` in `db/queries.py` accepts any `entity_type` string, no schema change needed.

**(Neo4j):** If `USE_GRAPH=True`, the entity must be mapped into the Cypher query within `db/graph_connector.py` -> `insert_threat_intel()`. You must ensure the `MERGE` statement creates the correct node label (e.g., `(i:Indicator {value: ioc.value})`) and relationships.

---

## How to Add a New Few-Shot Example

Few-shot examples live in `enrichment/few_shot_examples.py` as
`FEW_SHOT_EXAMPLES: list[dict]`.

### Format

```python
{
    "text": "Short realistic threat intelligence excerpt (2-4 sentences).",
    "ttps": (
        '[\n'
        '  {\n'
        '    "id": "T1234.001",\n'
        '    "name": "Official MITRE Technique Name",\n'
        '    "tactic": "Tactic Name",\n'
        '    "justification": "One sentence citing exact evidence from the text."\n'
        '  }\n'
        ']'
    ),
}
```

### Rules for few-shot examples

1. **Verify the technique ID exists** - check https://attack.mitre.org before
adding. The attack_mapper validates against `mitreattack-python` at runtime
but catching errors in the examples early saves debugging time.

2. **Justification must cite the text** - it must reference specific words or
phrases from the `text` field, not generic descriptions.

3. **Cover a tactic not already covered** - check the coverage table in
`few_shot_examples.py` docstring before adding. Current coverage:
Initial Access, Execution, Lateral Movement, Credential Access,
Collection, Exfiltration, Persistence, Defense Evasion, Impact, C2.

4. **Keep text realistic** - use real malware names, real CVE IDs, real
attack descriptions. The LLM generalises better from realistic examples.

5. **Maximum 8 examples** - LangChain injects all examples into every prompt.
Too many examples bloat the context window and slow inference on llama3.

---

## Git Workflow

### Daily workflow

```bash
# Start of day - sync your branch with main
git checkout feat/collectors
git fetch origin
git rebase origin/main

# Work, then commit frequently
git add collectors/reddit_collector.py
git commit -m "feat(collectors): add RedditCollector with PRAW"

# Push your branch
git push origin feat/collectors
```

### Opening a pull request

1. Ensure all tests pass: `pytest tests/ -v`
2. Ensure no API keys are in any file: `git grep -i "api_key\s*=" -- "*.py"`
3. Push your branch and open PR on GitHub
4. Tag the relevant reviewer (see branch ownership table)
5. Address all review comments before merging

### Resolving conflicts

```bash
# If main has moved ahead while you were working
git fetch origin
git rebase origin/main

# Fix any conflicts in your editor, then
git add <conflicted_file>
git rebase --continue

# Force push your rebased branch (safe - your branch only)
git push --force-with-lease origin feat/collectors
```

### Never do these

```bash
# Never commit directly to main
git checkout main && git commit ...   # forbidden

# Never force push to main
git push --force origin main          # forbidden

# Never commit .env or the database
git add .env                          # forbidden
git add data/threat_intel.db          # forbidden
```

`.gitignore` should contain:

```
.env
data/
reports/
*.db
__pycache__/
.venv/
venv/
*.egg-info/
```

---

## Testing Requirements

### Test file location

```
tests/
├── test_nvd_collector.py
├── test_otx_collector.py
├── test_rss_collector.py
├── test_entity_extractor.py
├── test_ner_spacy.py
├── test_deduplicator.py
├── test_html_stripper.py
└── test_queries.py
```

### Minimum test coverage per module

| Module | Required tests |
|---|---|
| Every collector | `normalize()` output keys, `dedup_key` determinism, empty result on bad input |
| `entity_extractor.py` | Each regex type (CVE, IPv4, IPv6, domain, MD5, SHA1, SHA256), false-positive suppression, dedup within one text |
| `ner_spacy.py` | Known malware names detected, known APT groups detected, PERSON label mapped to THREAT_ACTOR |
| `deduplicator.py` | Same CVE from two sources → one processed record, SHA-256 collision test |
| `html_stripper.py` | Tags removed, whitespace normalised, empty string handled |
| `queries.py` | `insert_entity` dedup (INSERT OR IGNORE), `mark_processed` sets flag, `get_unprocessed_batch` respects limit |

### Test isolation - no real API calls in tests

Use `unittest.mock.patch` to mock all HTTP calls:

```python
from unittest.mock import patch, MagicMock

def test_nvd_fetch_by_keyword_returns_normalised_records():
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                "metrics": {},
                "weaknesses": [],
            }
        }]
    }
    mock_response.raise_for_status = MagicMock()

    with patch("requests.Session.get", return_value=mock_response):
        col = NVDCollector()
        results = col.fetch_by_keyword("log4shell")

    assert len(results) == 1
    assert results[0]["title"] == "CVE-2021-44228"
    assert "dedup_key" in results[0]
    assert len(results[0]["dedup_key"]) == 64   # SHA-256 hex
```

### Running tests

```bash
# All tests
pytest tests/ -v

# Single module
pytest tests/test_entity_extractor.py -v

# With coverage report
pytest tests/ --cov=collectors --cov=enrichment --cov=db --cov-report=term-missing
```

---

## Absolute Rules

These rules are non-negotiable. Violating any of them will block your PR.

| # | Rule |
|---|---|
| 1 | **No inline SQL/Cypher** outside `db/queries.py` or `db/graph_connector.py` |
| 2 | **No API keys** in any `.py`, `.yaml`, or `.md` file |
| 3 | **No direct DB writes** inside collectors - use `collect_and_store()` which delegates to the data layer. |
| 4 | **No LLM calls** outside `enrichment/attack_mapper.py` and `enrichment/report_generator.py` |
| 5 | **No real HTTP calls** in unit tests - mock all external requests |
| 6 | **No bare `except:`** - always catch specific exceptions |
| 7 | **`normalize()` must call `format_record()`** - never construct the record dict manually |
| 8 | **Preprocessor order is fixed**: strip → dedup → encapsulate - never reorder |
| 9 | **`temperature=0`** on all LLM calls for factual/mapping tasks |
| 10 | **Every LLM claim cites `source_id`** in report output - no uncited facts |