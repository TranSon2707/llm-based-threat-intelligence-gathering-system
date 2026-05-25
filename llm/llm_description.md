# LLM-Based Threat Intelligence Gathering System: LLM Layer Architecture

The LLM layer is a thin, centralized adapter between the Python codebase and the local Llama 3 model served via Ollama. It does not perform any business logic — its sole responsibility is providing a single, consistently configured LLM client so no other module needs to know the model name, host URL, or temperature setting. The layer contains one file: `ollama_client.py`.

---

## Design Principle: Single Source of Truth for the LLM

Every module that needs to invoke the language model calls `get_llm()` from this layer rather than instantiating `OllamaLLM` directly. This enforces three guarantees across the entire codebase:

1. **DRY configuration** — model name, host URL, and temperature are declared exactly once. Switching from `llama3` to a newer model, or changing the Ollama port, requires a single line change here and zero changes elsewhere.
2. **Deterministic outputs** — `temperature=0` is set unconditionally. Threat intelligence tasks require factual, reproducible outputs; any creative variation in CVE descriptions, MITRE mappings, or executive summaries would be a correctness defect.

---

## Component: Ollama Client (`ollama_client.py`)

- **Function:** `get_llm() -> OllamaLLM`
- **Model:** `llama3` via `langchain_ollama.OllamaLLM` (the dedicated package, not the legacy `langchain_community` integration)
- **Host:** `http://localhost:11434` — the default Ollama local server address
- **Temperature:** `0` — deterministic mode; no sampling randomness

This function is intentionally stateless — it constructs and returns a new `OllamaLLM` instance on every call. LangChain's `OllamaLLM` is a lightweight wrapper with no persistent connection, so this carries no meaningful overhead and avoids stale-connection issues in long-running pipeline runs.

**Consumers in the current pipeline:**
- `preprocessor/language_detector.py` — calls `get_llm()` to power the non-English translation prompt
- `enrichment/behavior_translator.py` — calls `get_llm()` to power the HyDE behavior extraction prompt
- `reports/report_generator.py` — calls `get_llm()` for the final RAG executive summary

---

## Runtime Requirement

Ollama must be running locally before any pipeline stage that invokes `get_llm()` is executed. The three pipeline stages that call the LLM are:

| Stage | File | Task |
|---|---|---|
| Preprocessing | `preprocessor/language_detector.py` | Translate non-English OSINT text to English |
| Enrichment | `enrichment/behavior_translator.py` | Convert informal slang to formal technical behavior sentences (HyDE) |
| Reporting | `reports/report_generator.py` | Synthesize final intelligence report via closed-domain RAG |

Stages 1 and 2 of the enrichment layer (`entity_extractor.py`, `ner_spacy.py`) and the entire collector layer do **not** call the LLM and will run regardless of Ollama's availability.
