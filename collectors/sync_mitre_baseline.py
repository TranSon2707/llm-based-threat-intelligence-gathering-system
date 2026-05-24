"""
FILE: collectors/sync_mitre_baseline.py
ROLE: Graph Baseline Builder (Phase 0)
PURPOSE: Downloads MITRE ATT&CK Enterprise data, converts descriptions into 
vectors, and extracts targeted platforms to build -[:TARGETS]-> graph edges.
================
================
KEY POINTS:
MUST RUN IT BEFORE sync_nvd_baseline.py to ensure MITRE TTP nodes exist for CVE linking.
"""
import requests
import logging
from sentence_transformers import SentenceTransformer
from db.neo4j_manager import GraphConnector

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def sync_mitre():
    logger.info("[*] Initializing local embedding model (all-MiniLM-L6-v2)...")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    graph = GraphConnector()
    
    logger.info(f"[*] Fetching MITRE ATT&CK STIX 2.1 feed from {MITRE_STIX_URL}...")
    response = requests.get(MITRE_STIX_URL)
    response.raise_for_status()
    stix_data = response.json()
    
    objects = stix_data.get("objects", [])
    count = 0
    
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            ttp_id = next((ref["external_id"] for ref in ext_refs if ref.get("source_name") == "mitre-attack"), None)
            
            if not ttp_id:
                continue
                
            name = obj.get("name", "Unknown")
            description = obj.get("description", "")
            
            # 1. Generate Vector and Merge MITRE node
            embedding = model.encode(description).tolist()
            graph.merge_mitre_ttp(ttp_id, name, description, embedding)
            
            # 2. Build hard edges to targeted Software/Platforms
            platforms = obj.get("x_mitre_platforms", [])
            for platform in platforms:
                # E.g., Links T1548 -> [TARGETS] -> 'Windows'
                graph.link_mitre_software(ttp_id, platform.strip().lower())
                
            count += 1
    
    create_vector_index_if_needed(graph)
    graph.close()
    logger.info(f"[+] Successfully embedded {count} MITRE TTPs and mapped target software edges.")

def create_vector_index_if_needed(graph: GraphConnector):
    """
    Creates the Neo4j vector index on first run.
    IF NOT EXISTS makes this safe to re-run on subsequent syncs.
    Must run AFTER nodes with .embedding properties exist in the graph.
    """
    with graph.driver.session() as session:
        session.run("""
            CREATE VECTOR INDEX threat_embeddings_index IF NOT EXISTS
            FOR (n:CVE|MITRE_TTP) ON n.embedding
            OPTIONS {indexConfig: {
                `vector.dimensions`: 384,
                `vector.similarity_function`: 'cosine'
            }}
        """)
    logger.info("[+] Vector index 'threat_embeddings_index' confirmed.")

if __name__ == "__main__":
    sync_mitre()