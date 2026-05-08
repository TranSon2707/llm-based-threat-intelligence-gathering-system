"""
=============================================================================
MODULE: test_few_shot.py
PURPOSE: Validates the integrity of Few-Shot examples for LLM guidance.
HOW IT TESTS:
1. Verifies that the 'FEW_SHOT_EXAMPLES' list contains all 5 required examples.
2. Ensures each example matches the 'EXAMPLE_PROMPT' structure (JSON format).
COMMAND: python -m unittest tests.08_test_few_shot
=============================================================================
"""
import unittest
from enrichment.few_shot_examples import FEW_SHOT_EXAMPLES, EXAMPLE_PROMPT

class TestFewShot(unittest.TestCase):
    def test_examples_integrity(self):
        # Verify count
        self.assertEqual(len(FEW_SHOT_EXAMPLES), 5)
        
        # Verify formatting
        for ex in FEW_SHOT_EXAMPLES:
            formatted = EXAMPLE_PROMPT.format(**ex)
            self.assertIn("Threat text:", formatted)
            self.assertIn("Mapped TTPs", formatted)

if __name__ == "__main__":
    unittest.main() 