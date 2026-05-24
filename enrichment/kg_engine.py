"""
FILE: enrichment/kg_engine.py
ROLE: Knowledge Engine & Zero-Day Evaluator (Phase 4)
PURPOSE: Executes semantic search and aggregates multi-hop graph paths 
(CVE -> MITRE -> Software).
"""
import logging
from sentence_transformers import SentenceTransformer
from db.neo4j_manager import GraphConnector

logger = logging.getLogger(__name__)

class KnowledgeEngine:
    def __init__(self):
        logger.info("[*] Spinning up Knowledge Engine...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.graph = GraphConnector()

    def evaluate_threat(self, behaviors: list) -> dict:
        zero_day_flag = True 
        matched_threats = []
        explicit_techniques = set()
        blast_radius = set()
        
        if not behaviors:
            return {"matched_threats": [], "techniques": [], "systems_at_risk": [], "is_zero_day": zero_day_flag}

        logger.info(f"[*] Querying Neo4j for {len(behaviors)} behaviors (Threshold >= 80%)...")
        
        for sentence in behaviors:
            vector = self.model.encode(sentence).tolist()
            results = self.graph.vector_search(post_vector=vector, threshold=0.80)
            
            if results:
                zero_day_flag = False
                
                for record in results:
                    # Capture CVE or MITRE ID
                    threat_id = record.get("threat_id")
                    if threat_id and threat_id not in matched_threats:
                        matched_threats.append(threat_id)
                    
                    # Capture Explicitly mapped TTPs (if it was a CVE that had a hard edge to MITRE)
                    ttps = record.get("explicit_ttps", [])
                    for ttp in ttps:
                        if ttp: explicit_techniques.add(ttp)
                        
                    # Aggregate Blast Radius (Direct AFFECTS + multi-hop TARGETS)
                    systems = record.get("systems_at_risk", [])
                    for sys in systems:
                        if sys: blast_radius.add(sys)
                        
        payload = {
            "matched_threats": matched_threats,
            "techniques": list(explicit_techniques),
            "systems_at_risk": list(blast_radius),
            "is_zero_day": zero_day_flag
        }
        
        logger.info(f"[+] Evaluation Complete. Zero-Day: {zero_day_flag}. Matches: {len(matched_threats)}. Systems at risk: {len(blast_radius)}")
        return payload

    def close(self):
        self.graph.close()