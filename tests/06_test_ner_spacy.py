""" 
=============================================================================
MODULE: test_ner_spacy.py
PURPOSE: Validates Named Entity Recognition (NER) for Actors and Malware.
HOW IT TESTS:
Processes a complex text containing multiple APT groups, aliases, and malware 
families. Prints the extracted entities to verify the spaCy EntityRuler config.
COMMAND: python -m unittest tests.06_test_ner_spacy
=============================================================================
"""
import unittest
from enrichment.ner_spacy import extract_ner_entities

class TestNERSpacy(unittest.TestCase):
    def test_complex_ner_hits(self):
        sample = """
        The Lazarus Group deployed WannaCry ransomware across hospital networks 
        last month. Simultaneously, APT28, also known as Fancy Bear, used 
        Emotet as a dropper to deliver Cobalt Strike beacons. 
        Researcher John Smith attributed the attack to a North Korean threat actor.
        Another group, LAPSUS$, was observed using RedLine Stealer to harvest credentials.
        """
        print("\n" + "="*50)
        print("[--- ORIGINAL COMPLEX SAMPLE TEXT ---]")
        print(sample.strip())
        print("="*50) 

        results = extract_ner_entities(sample)
        
        print("\n[*] EXTRACTED SEMANTIC ENTITIES (spaCy NER):")
        for e in results:
            print(f"    - {e.entity_type.ljust(15)} : {e.entity_value}")
            
        values = [e.entity_value for e in results]
        self.assertIn("Lazarus Group", values)
        self.assertIn("Fancy Bear", values)
        self.assertIn("LAPSUS$", values)
        self.assertIn("Cobalt Strike", values)
        self.assertNotIn("John Smith", values, "Researcher was falsely flagged as THREAT_ACTOR")

if __name__ == "__main__":
    unittest.main(verbosity=2)
