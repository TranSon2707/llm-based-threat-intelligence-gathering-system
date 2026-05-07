from enrichment.entity_extractor import extract_entities

# This test covers the regex-based entity extraction logic.
# run by executing: python -m tests.test_entity_extractor
# enrichment test

sample = """
CVE-2021-44228 was exploited by attackers at 192.168.1.101 and 2001:db8::1.
The C2 domain was evil.example.com.
Payload hash: d41d8cd98f00b204e9800998ecf8427e
SHA1:          da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256:        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""

results = extract_entities(sample)
for e in results:
    print(e.entity_type, "→", e.entity_value)