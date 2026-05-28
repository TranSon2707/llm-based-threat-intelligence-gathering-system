"""
llm/embedding_service.py
=========================
Vector embedding generation using Ollama's nomic-embed-text model.

Responsibilities
----------------
1. embed_text(text)            — core API: returns a 768-dimensional float array.
2. embed_and_cache_cve()       — embeds a CVE description and writes the vector
                                 to the `embedding` property of the matching
                                 Neo4j CVE node so it is never recomputed.
3. embed_and_cache_ttp()       — same for MITRE_TTP nodes.

Callers
-------
- backfiller.py  → embed_and_cache_cve() for each historical CVE record.
- Real-time pipeline (after language_detector.py normalises the text)
  → embed_text() or embed_and_cache_cve() for newly ingested threats.

Setup
-----
    ollama pull nomic-embed-text
    # Verify: curl http://localhost:11434/api/embeddings \\
    #   -d '{"model": "nomic-embed-text", "prompt": "test"}'

Architecture notes
------------------
- Embeddings are cached on Neo4j nodes to avoid O(N) recomputation on every
  GraphRAG retrieval.  Vector similarity search (HNSW index, threshold=0.72)
  is handled by db/retrieval_service.py.
- Temperature is irrelevant for embedding models; the Ollama /api/embeddings
  endpoint does not accept a temperature parameter.
- The embedding dimension for nomic-embed-text is 768.
"""
from __future__ import annotations

import logging

import requests

# graph_connector imports embedding_service; we only need the type hint.
from db.neo4j_manager import GraphConnector

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

OLLAMA_BASE_URL  = "http://localhost:11434"
EMBED_MODEL      = "nomic-embed-text"
EXPECTED_DIM     = 768


# ── EmbeddingService ──────────────────────────────────────────────────────────

class EmbeddingService:
    """
    Thin wrapper around the Ollama /api/embeddings endpoint.

    Example usage
    -------------
        embedder = EmbeddingService()

        # One-shot embedding (no Neo4j caching)
        vector = embedder.embed_text("Apache Log4j CVE-2021-44228 exploit")

        # Embed and persist to the Neo4j CVE node
        vector = embedder.embed_and_cache_cve(
            cve_id="CVE-2021-44228",
            description="Apache Log4j CVE-2021-44228 exploit",
            cvss_score=10.0,
            graph=graph_db,
        )
    """

    def __init__(self, base_url: str = OLLAMA_BASE_URL) -> None:
        self._endpoint = f"{base_url}/api/embeddings"
        self._verify_model_available()

    # ── Public interface ──────────────────────────────────────────────────────

    def embed_text(self, text: str) -> list[float]:
        """
        Generate a 768-dimensional embedding vector for *text*.

        Args:
            text: The string to embed. Long texts are accepted; Ollama handles
                  truncation internally for nomic-embed-text (max ~8192 tokens).

        Returns:
            A list of 768 floats (cosine-comparable unit vector).

        Raises:
            RuntimeError: If Ollama is not running or the model is not pulled.
            ValueError:   If the returned vector has an unexpected dimension.
        """
        if not text or not isinstance(text, str):
            logger.warning("[EmbeddingService] Empty or non-string input received; returning zero vector.")
            return [0.0] * EXPECTED_DIM

        clean_text = text.strip()
        if not clean_text:
            return [0.0] * EXPECTED_DIM

        try:
            response = requests.post(
                self._endpoint,
                json={"model": EMBED_MODEL, "prompt": clean_text},
                timeout=60,
            )
            response.raise_for_status()
            vector: list[float] = response.json().get("embedding", [])

        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                "[EmbeddingService] Cannot connect to Ollama at "
                f"{self._endpoint}. Is Ollama running? "
                "Start it with: ollama serve"
            ) from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"[EmbeddingService] Ollama request failed: {exc}"
            ) from exc

        if len(vector) != EXPECTED_DIM:
            raise ValueError(
                f"[EmbeddingService] Expected {EXPECTED_DIM}-dim vector from "
                f"{EMBED_MODEL}, got {len(vector)} dimensions. "
                "Is the correct model loaded? Run: ollama pull nomic-embed-text"
            )

        return vector

    def embed_and_cache_cve(
        self,
        cve_id: str,
        description: str,
        cvss_score: float | None,
        graph: "GraphConnector",
    ) -> list[float]:
        """
        Embed *description* and write the vector to the `embedding` property
        of the matching Neo4j ``CVE`` node via graph.merge_cve().

        If the CVE node does not yet exist it is created via MERGE.
        Subsequent calls for the same *cve_id* overwrite the cached vector
        (important when NVD updates a CVE description).

        Args:
            cve_id:       CVE identifier string, e.g. ``"CVE-2021-44228"``.
            description:  The CVE description text to embed.
            cvss_score:   CVSS base score, or None if not available.
            graph:        An initialised GraphConnector instance.

        Returns:
            The 768-dimensional embedding vector (same as embed_text()).
        """
        vector = self.embed_text(description)

        try:
            graph.merge_cve(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                embedding=vector,
            )
            logger.info("[EmbeddingService] Cached embedding for CVE node: %s", cve_id)
        except Exception as exc:
            # Non-fatal: the vector is still returned; Neo4j write failure
            # must not crash the backfill loop.
            logger.warning(
                "[EmbeddingService] Failed to cache embedding for %s in Neo4j: %s",
                cve_id, exc,
            )

        return vector

    def embed_and_cache_ttp(
        self,
        ttp_id: str,
        name: str,
        description: str,
        graph: "GraphConnector",
    ) -> list[float]:
        """
        Embed *description* and write the vector to the `embedding` property
        of the matching Neo4j ``MITRE_TTP`` node via graph.merge_mitre_ttp().

        Args:
            ttp_id:       MITRE ATT&CK technique ID, e.g. ``"T1190"``.
            name:         Official technique name, e.g. ``"Exploit Public-Facing Application"``.
            description:  The technique description text to embed.
            graph:        An initialised GraphConnector instance.

        Returns:
            The 768-dimensional embedding vector.
        """
        vector = self.embed_text(description)

        try:
            graph.merge_mitre_ttp(
                ttp_id=ttp_id,
                name=name,
                description=description,
                embedding=vector,
            )
            logger.info(
                "[EmbeddingService] Cached embedding for MITRE_TTP node: %s", ttp_id
            )
        except Exception as exc:
            logger.warning(
                "[EmbeddingService] Failed to cache embedding for TTP %s in Neo4j: %s",
                ttp_id, exc,
            )

        return vector

    # ── Private helpers ───────────────────────────────────────────────────────

    def _verify_model_available(self) -> None:
        """
        Check that the Ollama service is reachable and nomic-embed-text is pulled.
        Logs a warning (does not raise) so the pipeline can still start without
        the model — embed_text() will raise at call time if unavailable.
        """
        try:
            resp = requests.get(
                f"{OLLAMA_BASE_URL}/api/tags",
                timeout=5,
            )
            resp.raise_for_status()
            models = [m["name"] for m in resp.json().get("models", [])]

            # nomic-embed-text may appear as "nomic-embed-text" or
            # "nomic-embed-text:latest" depending on Ollama version
            if not any(EMBED_MODEL in m for m in models):
                logger.warning(
                    "[EmbeddingService] '%s' not found in Ollama. "
                    "Run: ollama pull %s",
                    EMBED_MODEL, EMBED_MODEL,
                )
            else:
                logger.info("[EmbeddingService] '%s' model is available.", EMBED_MODEL)

        except requests.exceptions.ConnectionError:
            logger.warning(
                "[EmbeddingService] Ollama not reachable at %s. "
                "Start it before calling embed_text().",
                OLLAMA_BASE_URL,
            )
        except Exception as exc:
            logger.warning("[EmbeddingService] Model check failed: %s", exc)


# ── Module-level convenience functions ───────────────────────────────────────

_service: EmbeddingService | None = None


def get_embedding_service() -> EmbeddingService:
    """
    Factory function returning a singleton EmbeddingService instance.

    Use this wherever a shared, lazily-initialised service is preferred
    over instantiating EmbeddingService() directly:

        from llm.embedding_service import get_embedding_service
        svc = get_embedding_service()
        vector = svc.embed_text(cleaned_description)
    """
    global _service
    if _service is None:
        _service = EmbeddingService()
    return _service


def embed_text(text: str) -> list[float]:
    """
    Module-level shortcut.  Creates a singleton EmbeddingService on first call.

    Use this in the real-time pipeline where you do not need Neo4j caching:

        from llm.embedding_service import embed_text
        vector = embed_text(cleaned_description)
    """
    return get_embedding_service().embed_text(text)


# ── Quick smoke test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print("[*] EmbeddingService smoke test")
    print(f"    Model  : {EMBED_MODEL}")
    print(f"    Endpoint: {OLLAMA_BASE_URL}/api/embeddings")

    svc = EmbeddingService()

    test_cases = [
        "CVE-2021-44228 Apache Log4j Remote Code Execution vulnerability.",
        "APT28 used Cobalt Strike beacons over HTTPS C2 channels.",
        "",  # Edge case: empty string should return zero vector, not error
    ]

    for text in test_cases:
        try:
            vec = svc.embed_text(text)
            preview = [round(v, 5) for v in vec[:5]]
            print(f"\n[+] Input   : {repr(text[:60])}")
            print(f"    Dim     : {len(vec)}")
            print(f"    Preview : {preview} ...")
            assert len(vec) == EXPECTED_DIM, f"Expected {EXPECTED_DIM} dims, got {len(vec)}"
            print("    [PASS]")
        except Exception as e:
            print(f"    [FAIL] {e}")

    print("\n[+] Smoke test complete.")