# LLM-Based Threat Intelligence Gathering System: Enrichment Architecture (Hybrid Graph-Vector Update)

The Enrichment layer is designed as a multi-stage pipeline that transitions from deterministic data extraction to semantic vector search and complex graph reasoning. This layer ensures that raw threat data is enriched with technical context, mapped to official frameworks, and evaluated for impact before reaching the final analyst.

---

## Stage 1: Deterministic Indicator Extraction

- **Primary File:** `entity_extractor.py`
- **Mechanism:** Pre-compiled Regular Expressions (Regex)
- **Purpose:** Identifies "Hard IOCs" such as explicit CVE IDs, IPv4/IPv6 addresses, Domains, and Cryptographic Hashes (MD5, SHA1, SHA256).
- **Strategy:** By performing this extraction first, the system handles high-volume, fixed-pattern data with 100% precision. Results are stored in the SQLite `entities` table via `db/sqlite_manager.insert_entity()`. Deduplication is enforced at the (type, value) level so the same IOC appearing multiple times in one report is stored only once.

---

## Stage 2: Semantic Entity Recognition (NER) & Extraction

- **Primary File:** `ner_spacy.py`
- **Mechanism:** spaCy NLP Pipeline (`en_core_web_sm`) boosted with a custom `EntityRuler`
- **Purpose:** Extracts "Soft Entities" like Threat Actor groups (e.g., Lazarus Group, APT28) and Malware families (e.g., Emotet, LockBit) that do not follow fixed regex patterns.
- **Strategy:** A custom `EntityRuler` is injected *before* spaCy's built-in NER component so domain-specific patterns take precedence. The ruler covers an extensible catalogue of known malware families and APT group aliases. False positives from the `PERSON` label are suppressed by checking the preceding token for common safe titles (e.g., "researcher", "analyst"). Results are stored in SQLite via `db/sqlite_manager.insert_entity()`.

---

## Stage 3: Behavioral Translation (HyDE Pattern)

- **Primary File:** `behavior_translator.py`
- **Mechanism:** Local LLM (Llama 3) via structured JSON prompting using LangChain
- **Purpose:** Eliminates the **"Vocabulary Mismatch"** problem between informal forum slang and formal MITRE terminology.
- **Strategy:** The LLM receives the sanitized OSINT text and is instructed to extract core adversarial behaviors, converting each into a single formal technical sentence. The output is a strict JSON array: `{"behaviors": ["Tech sentence 1", "Tech sentence 2"]}`. This standardizes informal language into precise technical descriptions before mathematical vector comparison — bridging the gap between how attackers describe their actions and how MITRE ATT&CK catalogues them.

---

## Stage 4: Semantic Vector Search & Graph Traversal

- **Primary File:** `kg_engine.py`
- **Mechanism:** Local Embedding Model (`all-MiniLM-L6-v2`) + Neo4j Vector Index & Cypher Graph Traversal
- **Purpose:** Maps the technical behaviors to official MITRE TTPs/CVEs and calculates the potential blast radius across affected software.
- **Strategy:**
  1. **Vectorization:** Each technical behavior sentence from Stage 3 is encoded into a 384-dimensional vector using the same `all-MiniLM-L6-v2` model used to build the graph.
  2. **Semantic Matching:** Neo4j's vector index (`threat_embeddings_index`) calculates Cosine Similarity across all CVE and MITRE_TTP nodes simultaneously.
  3. **Strict Thresholding:** Only matches with similarity **>= 80% (0.80)** are returned. If no behavior clears this threshold, the entire threat is flagged as a potential **Zero-Day or Novel Technique** (`is_zero_day: True`).
  4. **Blast Radius Traversal:** For every matched node, a single Cypher query traverses three hop paths in parallel:
     - **Hop 1:** `CVE -[:AFFECTS]-> Software` (direct CPE-based software links)
     - **Hop 2:** `CVE -[:EXPLOITS_TECHNIQUE]-> MITRE_TTP -[:TARGETS]-> Software` (CTID-mapped technique targets)
     - **Hop 3:** `MITRE_TTP -[:TARGETS]-> Software` (when the matched node is a TTP directly)

  All affected software names from all three hops are aggregated into a single `systems_at_risk` set.

---

## Stage 5: Analyst Synthesis & Proactive Reporting

- **Primary File:** `report_generator.py`
- **Mechanism:** Hybrid Retrieval-Augmented Generation (RAG)
- **Purpose:** Produces the final actionable executive summary.
- **Strategy:** The LLM is provided with a comprehensive closed-domain prompt containing:
  - The original OSINT article text (encapsulated in `<THREAT_DATA>` tags).
  - Extracted entities from SQLite (Actors, Malware, Hard IOCs).
  - Graph context from Neo4j (matched TTPs/CVEs, `is_zero_day` flag, and `systems_at_risk`).

  The LLM synthesizes this into a single intelligence report detailing the threat, its novelty (Zero-Day status), affected systems, and actionable mitigation advice grounded in the graph context. It is strictly mandated to append `[source_id: X]` citations for every claim. If the data is insufficient, it must return a standard **"Insufficient data to determine"** response to prevent analyst misinformation.