from enrichment.ner_spacy import extract_ner_entities

# This test covers the spaCy-based NER extraction logic.
# run by executing: python -m tests.test_ner_spacy
# enrichment test

sample = """
The Lazarus Group deployed WannaCry ransomware across hospital networks.
APT28, also known as Fancy Bear, used Emotet as a dropper to deliver Cobalt Strike.
Researcher John Smith attributed the attack to a North Korean threat actor.
"""

results = extract_ner_entities(sample)
for e in results:
    print(e.entity_type, "→", e.entity_value)