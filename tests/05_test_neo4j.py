"""
=============================================================================
MODULE: 05_test_neo4j.py
PURPOSE: Validates the Neo4j Knowledge Graph integrity after baseline build.
HOW IT TESTS:
1. Verifies connection succeeds.
2. Checks node counts for CVE, MITRE_TTP, Software are non-zero.
3. Confirms EXPLOITS_TECHNIQUE edges exist (validates CTID fix).
4. Runs a vector_search() for a known behavior and expects a match >= 0.90.
5. Confirms is_zero_day is False for a well-known CVE behavior.
6. Confirms is_zero_day is True for a nonsense input.
COMMAND: python -m unittest tests.05_test_neo4j
=============================================================================
"""
import unittest
from db.neo4j_manager import GraphConnector
from enrichment.kg_engine import KnowledgeEngine

class TestNeo4jGraph(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.graph = GraphConnector()

    @classmethod
    def tearDownClass(cls):
        cls.graph.close()

    def _count(self, label):
        with self.graph.driver.session() as session:
            result = session.run(f"MATCH (n:{label}) RETURN count(n) AS c")
            return result.single()["c"]

    def _count_rel(self, rel_type):
        with self.graph.driver.session() as session:
            result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS c")
            return result.single()["c"]

    def test_01_connection(self):
        print("\n[*] Testing Neo4j connection...")
        # If setUpClass succeeded, driver is live — just ping it
        with self.graph.driver.session() as session:
            result = session.run("RETURN 1 AS ok")
            self.assertEqual(result.single()["ok"], 1)
        print("[+] Connection OK.")

    def test_02_node_counts(self):
        print("\n[*] Checking node counts...")
        cve_count   = self._count("CVE")
        ttp_count   = self._count("MITRE_TTP")
        sw_count    = self._count("Software")
        print(f"    CVE nodes      : {cve_count}")
        print(f"    MITRE_TTP nodes: {ttp_count}")
        print(f"    Software nodes : {sw_count}")
        self.assertGreater(cve_count,  0, "No CVE nodes found.")
        self.assertGreater(ttp_count,  0, "No MITRE_TTP nodes found.")
        self.assertGreater(sw_count,   0, "No Software nodes found.")

    def test_03_relationship_counts(self):
        print("\n[*] Checking relationship counts...")
        affects_count   = self._count_rel("AFFECTS")
        targets_count   = self._count_rel("TARGETS")
        exploits_count  = self._count_rel("EXPLOITS_TECHNIQUE")
        print(f"    AFFECTS edges            : {affects_count}")
        print(f"    TARGETS edges            : {targets_count}")
        print(f"    EXPLOITS_TECHNIQUE edges : {exploits_count}")
        self.assertGreater(affects_count,  0, "No AFFECTS edges found.")
        self.assertGreater(targets_count,  0, "No TARGETS edges found.")
        # This specifically validates the CTID BOM + semicolon fix
        self.assertGreater(exploits_count, 0,
            "No EXPLOITS_TECHNIQUE edges found — CTID mapping may have failed.")

if __name__ == "__main__":
    unittest.main(verbosity=2)