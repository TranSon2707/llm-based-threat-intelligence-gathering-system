# LLM-Based Threat Intelligence Gathering System: Enrichment Architecture (Hybrid Graph-Vector Update)

The Enrichment layer is designed as a multi-stage pipeline that transitions from deterministic data extraction to semantic vector search and complex graph reasoning. This layer ensures that raw threat data is enriched with technical context, mapped to official frameworks, and evaluated for impact before reaching the final analyst.

// B CHUA UPDATE HET DANG DOI NAO CHAY XONG GRAPH DA!!!
---

## Stage 1: Deterministic Indicator Extraction

- **Primary File:** `entity_extractor.py`
- **Mechanism:** Pre-compiled Regular Expressions (Regex)
- **Purpose:** Identifies "Hard IOCs" such as explicit CVE IDs, IPv4/IPv6 addresses, Domains, and Cryptographic Hashes (MD5, SHA1, SHA256).
- **Strategy:** By performing this extraction first, the system handles high-volume, fixed-pattern data with 100% precision. Results are stored exclusively in the SQLite `entities` table.

---

## Stage 2: Semantic Entity Recognition (NER) & Extraction

- **Primary File:** `ner_spacy.py` / `llm_entity_extractor.py`
- **Mechanism:** spaCy NLP Pipeline / Local Llama 3 Model
- **Purpose:** Extracts "Soft Entities" like Threat Actor groups (e.g., Lazarus) and Malware families (e.g., Emotet) that do not follow fixed regex patterns.
- **Strategy:** Extracted actors and malware are stored in the SQLite database to maintain a clean historical record of OSINT findings without bloating the core Knowledge Graph with unverified entities.

---

## Stage 3: Behavioral Translation (HyDE Pattern)

- **Primary File:** `behavior_translator.py`
- **Mechanism:** Local LLM (Llama 3) via structured JSON prompting
- **Purpose:** Eliminates the **"Vocabulary Mismatch"** problem between informal forum slang and formal MITRE terminology.
- **Strategy:** The LLM processes the translated text and extracts an array of distinct cyber attack techniques. For **each** technique, it generates a single, highly technical sentence summarizing the exact attack behavior. This standardizes the text before mathematical comparison.

---

## Stage 4: Semantic Vector Search & Graph Traversal

- **Primary File:** `kg_engine.py` *(replaces legacy `attack_mapper.py` and `few_shot_examples.py`)*
- **Mechanism:** Local Embedding Model (e.g., `all-MiniLM-L6-v2`) + Neo4j Vector Index & Cypher Graph Traversal
- **Purpose:** Maps the technical behaviors to official MITRE TTPs/CVEs and calculates the potential blast radius.
- **Strategy:**
  1. **Vectorization:** Python converts each technical behavior sentence from Stage 3 into a high-dimensional mathematical vector.
  2. **Semantic Matching:** Neo4j calculates Cosine Similarity against the official NVD/MITRE vectors stored in the graph.
  3. **Strict Thresholding:** The system retrieves all matched CVEs and MITRE TTPs that satisfy a strict similarity threshold of **>= 80% (0.80)**. If no historical vectors meet this threshold, the system flags the behavior as a potential **Zero-Day or Novel Technique**.
  4. **Blast Radius Traversal:** For every matched CVE/TTP, a Cypher query traverses the Neo4j graph (e.g., `-[AFFECTS]->`) to extract all known related software, systems, and standard mitigations.

---

## Stage 5: Analyst Synthesis & Proactive Reporting

- **Primary File:** `report_generator.py`
- **Mechanism:** Hybrid Retrieval-Augmented Generation (RAG)
- **Purpose:** Produces the final actionable executive summary.
- **Strategy:** The LLM is provided with a comprehensive prompt containing:
  - The original OSINT article text.
  - Extracted entities from SQLite (Actors, Malware, Hard IOCs).
  - Graph context from Neo4j (>= 80% matched TTPs/CVEs and systems at risk).

  The LLM synthesizes this into a single report, detailing the threat, identifying novelty (Zero-Day status), and providing actionable mitigation advice based on the graph context. It is strictly mandated to append `[source_id: X]` citations for every claim. If the data is insufficient, it must return a standard **"Insufficient data to determine"** response to prevent analyst misinformation.