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
        unmatched_behaviors = []
        
        if not behaviors:
            return {"matched_threats": [], "techniques": [], "systems_at_risk": [], "is_zero_day": zero_day_flag, "unmatched_behaviors": unmatched_behaviors}

        logger.info(f"[*] Querying Neo4j for {len(behaviors)} behaviors (Threshold >= 80%)...")
        
        for sentence in behaviors:
            vector = self.model.encode(sentence).tolist()
            results = self.graph.vector_search(post_vector=vector, threshold=0.80)

            if results:
                zero_day_flag = False

                for record in results:
                    threat_id   = record.get("threat_id")
                    threat_type = record.get("threat_type")
                    score       = record.get("similarity_score")

                    if threat_id:
                        logger.info(f"    [{threat_type}] {threat_id} (score: {score:.4f})")

                    if threat_type == "CVE" and threat_id not in matched_threats:
                        matched_threats.append(threat_id)

                    elif threat_type == "MITRE_TTP" and threat_id not in matched_threats:
                        matched_threats.append(threat_id)
                        explicit_techniques.add(threat_id)

                    ttps = record.get("explicit_ttps", [])
                    for ttp in ttps:
                        if ttp:
                            explicit_techniques.add(ttp)

                    systems = record.get("systems_at_risk", [])
                    for sys in systems:
                        if sys:
                            blast_radius.add(sys)
            else:
                unmatched_behaviors.append(sentence)
                        
        matched_cves = [t for t in matched_threats if t.startswith("CVE-")]
        matched_ttps = [t for t in matched_threats if t.startswith("T")]

        payload = {
            "matched_cves":        matched_cves,
            "matched_ttps":        list(matched_ttps),
            "matched_threats":     matched_threats,      # kept for backward compat
            "techniques":          list(explicit_techniques),
            "systems_at_risk":     list(blast_radius),
            "is_zero_day":         zero_day_flag,
            "unmatched_behaviors": unmatched_behaviors,
        }

        logger.info(f"[+] Matched CVEs : {matched_cves}")
        logger.info(f"[+] Matched TTPs : {list(matched_ttps)}")
        logger.info(f"[+] Systems at risk: {list(blast_radius)}")
        logger.info(f"[+] Zero-Day: {zero_day_flag}")
        return payload

    def close(self):
        self.graph.close()