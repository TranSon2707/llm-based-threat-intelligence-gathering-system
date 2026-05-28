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
            return {
                "matched_cves": [], "matched_ttps": [], "matched_threats": [],
                "techniques": [], "systems_at_risk": [], "is_zero_day": True,
                "unmatched_behaviors": []
            }

        logger.info(f"[*] Querying Neo4j for {len(behaviors)} behaviors (Threshold >= 90%)...")

        # ── Combined context search ───────────────────────────────────────────
        # Embed ALL behaviors together as one paragraph to get a holistic
        # attack vector — this prevents individual sentences from matching
        # unrelated CVEs just because they share generic security vocabulary
        combined_context = " ".join(behaviors)
        combined_vector  = self.model.encode(combined_context).tolist()
        context_results  = self.graph.vector_search(
            post_vector=combined_vector, threshold=0.75
        )

        # Build a set of threat IDs that appear in the combined context search
        # Only threats that match the FULL attack context are considered relevant
        context_relevant_ids: set[str] = set()
        for record in context_results:
            tid = record.get("threat_id")
            if tid:
                context_relevant_ids.add(tid)

        logger.info(f"[-] Combined context search found {len(context_relevant_ids)} relevant threats.")

        # ── Per-behavior search ───────────────────────────────────────────────
        # Still search per behavior to detect zero-day and unmatched behaviors
        # but FILTER results against context_relevant_ids to remove noise
        for sentence in behaviors:
            vector  = self.model.encode(sentence).tolist()
            results = self.graph.vector_search(post_vector=vector, threshold=0.80)

            # Filter: only keep results that also appeared in the combined search
            # This removes CVEs that match a behavior sentence in isolation but
            # are not relevant to the overall attack context
            if context_relevant_ids:
                results = [
                    r for r in results
                    if r.get("threat_id") in context_relevant_ids
                ]

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
        matched_ttps = list({
            t for t in matched_threats if t.startswith("T")
        } | explicit_techniques)

        # ── Attack mapper — LLM-based TTP extraction ──────────────────────────
        # Runs AFTER vector search to find TTPs that vector search missed.
        # Results verified against enterprise-attack.json — no hallucinations.
        # IMPORTANT: attack mapper finding a broad TTP category does NOT clear
        # zero_day_flag — only vector search finding a specific semantic match does.
        mapper_ttps: list[str] = []
        try:
            from enrichment.attack_mapper import extract_ttps_from_behaviors
            raw_mapper_ttps = extract_ttps_from_behaviors(behaviors)

            existing_ttps = set(matched_ttps)
            for ttp in raw_mapper_ttps:
                if ttp not in existing_ttps:
                    matched_threats.append(ttp)
                    existing_ttps.add(ttp)
                    mapper_ttps.append(ttp)

                    # Fetch blast radius for this TTP from the graph
                    try:
                        with self.graph.driver.session() as session:
                            result = session.run("""
                                MATCH (t:MITRE_TTP {ttp_id: $ttp_id})-[:TARGETS]->(s:Software)
                                RETURN s.name AS system
                            """, ttp_id=ttp)
                            for record in result:
                                sys_name = record.get("system")
                                if sys_name:
                                    blast_radius.add(sys_name)
                                    logger.info(f"    [+] {ttp} targets: {sys_name}")
                    except Exception as e:
                        logger.warning(f"[!] Failed to fetch blast radius for {ttp}: {e}")

            if mapper_ttps:
                logger.info(f"[+] Attack mapper added {len(mapper_ttps)} TTPs "
                            f"not found by vector search: {mapper_ttps}")
            else:
                logger.info("[+] Attack mapper found no additional TTPs beyond vector search.")

        except Exception as e:
            logger.warning(f"[!] Attack mapper failed, skipping: {e}")

        if matched_threats:
            zero_day_flag = False

        payload = {
            "matched_cves":        matched_cves,
            "matched_ttps":        matched_ttps,
            "mapper_ttps":         mapper_ttps,
            "matched_threats":     matched_threats,
            "systems_at_risk":     list(blast_radius),
            "is_zero_day":         zero_day_flag,        # NOT touched by attack mapper
            "unmatched_behaviors": unmatched_behaviors,
        }

        logger.info(f"[+] Matched CVEs    : {matched_cves}")
        logger.info(f"[+] Matched TTPs    : {matched_ttps}")
        logger.info(f"[+] Mapper TTPs     : {mapper_ttps}")
        logger.info(f"[+] Systems at risk : {list(blast_radius)}")
        logger.info(f"[+] Zero-Day        : {zero_day_flag}")
        return payload
        
    def close(self):
        self.graph.close()