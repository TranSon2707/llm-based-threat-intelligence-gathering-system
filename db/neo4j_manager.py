import logging
from neo4j import GraphDatabase
from db.queries import (
    LINK_MITRE_SOFTWARE,
    MERGE_MITRE_TTP,
    MERGE_CVE,
    LINK_CVE_SOFTWARE,
    VECTOR_SEARCH_AND_TRAVERSE,
    LINK_CVE_MITRE
)

logger = logging.getLogger(__name__)

class GraphConnector:
    """Manages connection pooling and graph executions for Neo4j."""
    
    # Connects to the local default Neo4j Bolt port
    def __init__(self, uri="neo4j://localhost:7687", user="neo4j", password="password"):
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            logger.info("Successfully connected to Neo4j.")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise

    def close(self):
        """Safely close the driver connection."""
        if self.driver:
            self.driver.close()

    def _execute_write(self, query: str, **kwargs):
        """Internal helper for executing database write transactions."""
        with self.driver.session() as session:
            try:
                result = session.execute_write(lambda tx: tx.run(query, **kwargs).data())
                return result
            except Exception as e:
                logger.error(f"Neo4j write error: {e}")
                raise

    def _execute_read(self, query: str, **kwargs):
        """Internal helper for executing database read transactions."""
        with self.driver.session() as session:
            try:
                result = session.execute_read(lambda tx: tx.run(query, **kwargs).data())
                return result
            except Exception as e:
                logger.error(f"Neo4j read error: {e}")
                raise

    # ---------------------------------------------------------
    # Baseline Data Synchronization (Write Operations)
    # ---------------------------------------------------------
    
    def merge_mitre_ttp(self, ttp_id: str, name: str, description: str, embedding: list):
        """Inserts or updates a MITRE TTP node and its vector."""
        self._execute_write(
            MERGE_MITRE_TTP, 
            ttp_id=ttp_id, 
            name=name, 
            description=description, 
            embedding=embedding
        )

    def merge_cve(self, cve_id: str, description: str, cvss_score: float, embedding: list):
        """Inserts or updates a CVE node and its vector."""
        self._execute_write(
            MERGE_CVE, 
            cve_id=cve_id, 
            description=description, 
            cvss_score=cvss_score, 
            embedding=embedding
        )

    def link_cve_software(self, cve_id: str, software_name: str):
        """Creates an AFFECTS relationship between a CVE and a Software node."""
        self._execute_write(
            LINK_CVE_SOFTWARE, 
            cve_id=cve_id, 
            software_name=software_name
        )

    def link_cve_mitre(self, cve_id: str, ttp_id: str):
        """Creates an EXPLOITS_TECHNIQUE hard edge between a CVE and a MITRE TTP."""
        self._execute_write(LINK_CVE_MITRE, cve_id=cve_id, ttp_id=ttp_id)

    def link_mitre_software(self, ttp_id: str, software_name: str):
        """Creates a TARGETS hard edge between a MITRE TTP and a Software platform."""
        self._execute_write(LINK_MITRE_SOFTWARE, ttp_id=ttp_id, software_name=software_name)

    # ---------------------------------------------------------
    # Active Enrichment (Read Operations)
    # ---------------------------------------------------------
    
    def vector_search(self, post_vector: list, threshold: float = 0.80, top_k: int = 15) -> list:
        """
        top_k controls how many candidates are retrieved before threshold filtering.
        Default 15 gives the threshold room to work without over-fetching.
        """
        return self._execute_read(
            VECTOR_SEARCH_AND_TRAVERSE,
            post_vector=post_vector,
            threshold=threshold,
            top_k=top_k,
        )