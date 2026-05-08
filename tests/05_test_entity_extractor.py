"""
=============================================================================
MODULE: test_entity_extractor.py
PURPOSE: Tests Regex-based extraction of technical IOCs.
HOW IT TESTS:
Runs a sample text containing CVEs, IPs, and Hashes through 'extract_entities'
and verifies that each entity type is correctly identified and deduplicated.
COMMAND: python -m unittest tests.05_test_entity_extractor
=============================================================================
"""
import unittest
from enrichment.entity_extractor import extract_entities

class TestEntityExtractor(unittest.TestCase):
    def test_complex_regex_patterns(self):
        sample = """
        URGENT BULLETIN: Threat actors are actively exploiting CVE-2021-44228 (Log4Shell) 
        and CVE-2023-23397. Initial access was traced to IPv4 192.168.1.101 and 
        IPv6 address 2001:db8::1. The malware communicates with a C2 domain 
        located at evil.example.com and a backup at proxy.malicious-site.org.
        Note: The schema.org domain should be ignored (stopword).
        Dropped payloads have the following signatures:
        MD5: d41d8cd98f00b204e9800998ecf8427e 
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        Duplicate IP 192.168.1.101 was seen again in logs.
        """
        print("\n" + "="*50)
        print("[--- ORIGINAL COMPLEX SAMPLE TEXT ---]")
        print(sample.strip())
        print("="*50)

        results = extract_entities(sample)
        
        print("\n[*] EXTRACTED HARD IOCs (Regex):")
        for e in results:
            print(f"    - {e.entity_type.ljust(10)} : {e.entity_value}")

        types = [e.entity_type for e in results]
        values = [e.entity_value for e in results]
        
        self.assertIn("CVE", types)
        self.assertIn("IPv4", types)
        self.assertIn("IPv6", types)
        self.assertIn("DOMAIN", types)
        self.assertIn("MD5", types)
        self.assertIn("SHA1", types)
        self.assertIn("SHA256", types)
        self.assertEqual(values.count("192.168.1.101"), 1, "Deduplication failed for IP")
        self.assertNotIn("schema.org", values, "Stopword domain was falsely extracted")

if __name__ == "__main__":
    unittest.main()