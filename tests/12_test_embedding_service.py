"""
=============================================================================
MODULE: 12_test_embedding_service.py
PURPOSE: Validates EmbeddingService correctness, error handling, and
         Neo4j caching integration.

HOW IT TESTS:
  Part A — Unit tests (no Ollama required, all HTTP mocked per Rule #5):
    1. Returns a 768-dim float list on valid input.
    2. Returns a zero vector for empty / whitespace-only input without
       hitting the network.
    3. Raises ValueError when Ollama returns the wrong dimension
       (catches misconfigured model, e.g. all-MiniLM returning 384).
    4. Raises RuntimeError on ConnectionError (Ollama not running).
    5. embed_and_cache_cve() calls GraphConnector.merge_cve() with the
       correct arguments including the computed embedding.
    6. embed_and_cache_ttp() calls GraphConnector.merge_mitre_ttp() with
       the correct arguments.
    7. A Neo4j write failure inside embed_and_cache_cve() is non-fatal —
       the vector is still returned so the backfill loop continues.
    8. get_embedding_service() returns an EmbeddingService instance.

  Part B — Live telemetry (requires: ollama serve + ollama pull nomic-embed-text):
    - Calls the real Ollama endpoint and measures latency.
    - Verifies the returned vector is 768-dimensional.
    - Checks cosine similarity: two CVE-style texts score > 0.60,
      two unrelated texts score < 0.95 (semantically distinct).

COMMANDS:
  Unit tests only (no Ollama needed):
    python -m unittest tests.12_test_embedding_service

  Live telemetry (Ollama must be running):
    python -m tests.12_test_embedding_service
=============================================================================
"""

import math
import time
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_vector(dim: int = 768) -> list[float]:
    """Return a fake unit vector of length *dim*."""
    val = 1.0 / math.sqrt(dim)
    return [val] * dim


def _cosine(a: list[float], b: list[float]) -> float:
    dot  = sum(x * y for x, y in zip(a, b))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


# ---------------------------------------------------------------------------
# Part A — Unit tests (all HTTP mocked)
# ---------------------------------------------------------------------------

class TestEmbedTextUnit(unittest.TestCase):
    """Core embed_text() behaviour — no live Ollama needed."""

    # Suppress _check_model warning noise during tests
    @patch("requests.get")
    def setUp(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "models": [{"name": "nomic-embed-text"}]
        }
        from llm.embedding_service import EmbeddingService
        self.svc = EmbeddingService()

    # ------------------------------------------------------------------
    # Test 1 — happy path
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_returns_768_dim_vector(self, mock_post):
        """embed_text() returns a list of exactly 768 floats."""
        fake_vec = _make_fake_vector(768)
        mock_post.return_value.status_code = 200
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"embedding": fake_vec}

        result = self.svc.embed_text("CVE-2021-44228 Apache Log4j RCE via JNDI.")

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 768)
        self.assertIsInstance(result[0], float)
        print("\n[PASS] test_returns_768_dim_vector")

    # ------------------------------------------------------------------
    # Test 2 — empty input skips network
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_empty_input_returns_zero_vector_no_network_call(self, mock_post):
        """Empty / whitespace input must return a zero vector without any HTTP call."""
        for empty in ("", "   ", "\t\n"):
            result = self.svc.embed_text(empty)
            self.assertEqual(len(result), 768)
            self.assertTrue(all(v == 0.0 for v in result),
                            f"Expected zero vector for input {repr(empty)}")

        mock_post.assert_not_called()
        print("[PASS] test_empty_input_returns_zero_vector_no_network_call")

    # ------------------------------------------------------------------
    # Test 3 — wrong dimension raises ValueError
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_wrong_dimension_raises_value_error(self, mock_post):
        """If Ollama returns 384 dims instead of 768, ValueError is raised."""
        wrong_vec = _make_fake_vector(384)
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"embedding": wrong_vec}

        with self.assertRaises(ValueError) as ctx:
            self.svc.embed_text("some text")

        self.assertIn("768", str(ctx.exception))
        self.assertIn("384", str(ctx.exception))
        print("[PASS] test_wrong_dimension_raises_value_error")

    # ------------------------------------------------------------------
    # Test 4 — Ollama not running raises RuntimeError
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_connection_error_raises_runtime_error(self, mock_post):
        """ConnectionError from requests is converted to a descriptive RuntimeError."""
        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError("refused")

        with self.assertRaises(RuntimeError) as ctx:
            self.svc.embed_text("Apache Log4j exploit")

        self.assertIn("Ollama", str(ctx.exception))
        print("[PASS] test_connection_error_raises_runtime_error")

    # ------------------------------------------------------------------
    # Test 5 — correct HTTP payload sent to Ollama
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_correct_payload_sent_to_ollama(self, mock_post):
        """embed_text() sends the right model name and prompt to /api/embeddings."""
        fake_vec = _make_fake_vector(768)
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"embedding": fake_vec}

        input_text = "Ransomware deploys Cobalt Strike beacon."
        self.svc.embed_text(input_text)

        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs[0][1]
        self.assertEqual(payload["model"], "nomic-embed-text")
        self.assertEqual(payload["prompt"], input_text.strip())
        print("[PASS] test_correct_payload_sent_to_ollama")


class TestCachingMethods(unittest.TestCase):
    """embed_and_cache_cve() and embed_and_cache_ttp() — verify Neo4j integration."""

    @patch("requests.get")
    def setUp(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "models": [{"name": "nomic-embed-text"}]
        }
        from llm.embedding_service import EmbeddingService
        self.svc = EmbeddingService()
        self.fake_vec = _make_fake_vector(768)

    # ------------------------------------------------------------------
    # Test 6 — embed_and_cache_cve calls merge_cve with correct args
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_embed_and_cache_cve_calls_merge_cve(self, mock_post):
        """embed_and_cache_cve() must call graph.merge_cve() with all four args."""
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"embedding": self.fake_vec}

        mock_graph = MagicMock()

        result = self.svc.embed_and_cache_cve(
            cve_id      = "CVE-2021-44228",
            description = "Apache Log4j JNDI injection RCE.",
            cvss_score  = 10.0,
            graph       = mock_graph,
        )

        mock_graph.merge_cve.assert_called_once_with(
            cve_id      = "CVE-2021-44228",
            description = "Apache Log4j JNDI injection RCE.",
            cvss_score  = 10.0,
            embedding   = self.fake_vec,
        )
        self.assertEqual(result, self.fake_vec)
        print("\n[PASS] test_embed_and_cache_cve_calls_merge_cve")

    # ------------------------------------------------------------------
    # Test 7 — embed_and_cache_ttp calls merge_mitre_ttp with correct args
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_embed_and_cache_ttp_calls_merge_mitre_ttp(self, mock_post):
        """embed_and_cache_ttp() must call graph.merge_mitre_ttp() with all four args."""
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"embedding": self.fake_vec}

        mock_graph = MagicMock()

        result = self.svc.embed_and_cache_ttp(
            ttp_id      = "T1190",
            name        = "Exploit Public-Facing Application",
            description = "Adversary exploits weakness in public-facing application.",
            graph       = mock_graph,
        )

        mock_graph.merge_mitre_ttp.assert_called_once_with(
            ttp_id      = "T1190",
            name        = "Exploit Public-Facing Application",
            description = "Adversary exploits weakness in public-facing application.",
            embedding   = self.fake_vec,
        )
        self.assertEqual(result, self.fake_vec)
        print("[PASS] test_embed_and_cache_ttp_calls_merge_mitre_ttp")

    # ------------------------------------------------------------------
    # Test 8 — Neo4j failure is non-fatal
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_neo4j_write_failure_is_non_fatal(self, mock_post):
        """If merge_cve() raises, embed_and_cache_cve() still returns the vector."""
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"embedding": self.fake_vec}

        mock_graph = MagicMock()
        mock_graph.merge_cve.side_effect = ConnectionRefusedError("Neo4j down")

        # Must NOT raise — backfill loop must continue even if Neo4j is unavailable
        result = self.svc.embed_and_cache_cve(
            cve_id      = "CVE-2023-99999",
            description = "Test CVE description.",
            cvss_score  = None,
            graph       = mock_graph,
        )

        self.assertEqual(len(result), 768)
        print("[PASS] test_neo4j_write_failure_is_non_fatal")


class TestModuleLevelFactory(unittest.TestCase):
    """get_embedding_service() factory function."""

    @patch("requests.get")
    def test_get_embedding_service_returns_instance(self, mock_get):
        """get_embedding_service() returns an EmbeddingService instance."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "models": [{"name": "nomic-embed-text"}]
        }

        from llm.embedding_service import EmbeddingService, get_embedding_service
        svc = get_embedding_service()
        self.assertIsInstance(svc, EmbeddingService)
        print("\n[PASS] test_get_embedding_service_returns_instance")


# ---------------------------------------------------------------------------
# Part B — Live telemetry (requires running Ollama + nomic-embed-text)
# ---------------------------------------------------------------------------

def run_live_telemetry():
    """
    Runs against the real Ollama endpoint.
    Skipped automatically if Ollama is not reachable.
    """
    import requests

    print("\n" + "=" * 60)
    print("[*] LIVE TELEMETRY — nomic-embed-text via Ollama")
    print("=" * 60)

    # Pre-flight: is Ollama up?
    try:
        health = requests.get("http://localhost:11434/api/tags", timeout=5)
        health.raise_for_status()
    except Exception:
        print("[!] Ollama not reachable — skipping live telemetry.")
        print("    Start Ollama and run: ollama pull nomic-embed-text")
        return

    # Check model is pulled
    pulled = [m["name"] for m in health.json().get("models", [])]
    if not any("nomic-embed-text" in m for m in pulled):
        print("[!] nomic-embed-text not pulled — skipping live telemetry.")
        print("    Run: ollama pull nomic-embed-text")
        return

    from llm.embedding_service import EmbeddingService
    svc = EmbeddingService()

    # ── Test cases ────────────────────────────────────────────────────────
    cases = [
        ("CVE description",
         "Apache Log4j 2 contains a remote code execution vulnerability via "
         "JNDI injection in the logging configuration. CVE-2021-44228."),

        ("Similar CVE (should score high similarity to above)",
         "A critical RCE flaw in Apache Log4j 2 allows unauthenticated "
         "attackers to execute arbitrary code by exploiting JNDI lookups."),

        ("Unrelated text (should score low similarity)",
         "The restaurant serves an excellent pasta carbonara with "
         "crispy pancetta and fresh parmesan cheese."),

        ("TTP description",
         "Adversary exploits a public-facing web application to gain "
         "initial access to the target network. MITRE T1190."),

        ("Empty string edge case", ""),
    ]

    vectors: dict[str, list[float]] = {}
    all_passed = True

    for label, text in cases:
        print(f"\n[Test] {label}")
        print(f"  Input   : {repr(text[:80])}" + ("..." if len(text) > 80 else ""))
        t0 = time.perf_counter()
        try:
            vec = svc.embed_text(text)
            elapsed = time.perf_counter() - t0

            dim_ok = len(vec) == 768
            status = "[PASS]" if dim_ok else "[FAIL]"
            print(f"  Dim     : {len(vec)}  {status}")
            print(f"  Latency : {elapsed:.3f}s")
            print(f"  Preview : {[round(v, 5) for v in vec[:5]]} ...")

            if not dim_ok:
                all_passed = False
            else:
                vectors[label] = vec

        except Exception as exc:
            print(f"  [FAIL]  {exc}")
            all_passed = False

    # ── Cosine similarity checks ──────────────────────────────────────
    print("\n" + "-" * 60)
    print("[*] SEMANTIC SIMILARITY CHECKS")
    print("-" * 60)

    cve_key     = "CVE description"
    similar_key = "Similar CVE (should score high similarity to above)"
    unrelated   = "Unrelated text (should score low similarity)"

    if cve_key in vectors and similar_key in vectors:
        sim = _cosine(vectors[cve_key], vectors[similar_key])
        ok  = sim > 0.60
        print(f"  CVE vs Similar CVE  : {sim:.4f}  {'[PASS] > 0.60' if ok else '[FAIL] expected > 0.60'}")
        if not ok:
            all_passed = False

    if cve_key in vectors and unrelated in vectors:
        sim = _cosine(vectors[cve_key], vectors[unrelated])
        ok  = sim < 0.95
        print(f"  CVE vs Unrelated    : {sim:.4f}  {'[PASS] < 0.95' if ok else '[FAIL] expected < 0.95'}")
        if not ok:
            all_passed = False

    print("\n" + "=" * 60)
    print(f"  Live telemetry result: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Run live telemetry first so output is grouped, then run unit tests
    run_live_telemetry()

    print("\n" + "=" * 60)
    print("[*] UNIT TESTS (mocked HTTP)")
    print("=" * 60)
    unittest.main(argv=[""], verbosity=2, exit=False)
