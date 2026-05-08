"""
=============================================================================
FILE: preprocessor/encapsulator.py
ROLE: Prompt Injection Defense Mechanism
=============================================================================
PURPOSE:
Defends the LLM from executing malicious commands embedded in raw threat data.
It wraps the sanitized text in strict XML tags and provides a rigid system 
instruction to treat the content purely as passive data.
"""
import unittest

def encapsulate_threat_data(sanitized_text: str) -> str:
    """
    Wraps the cleaned text inside <THREAT_DATA> tags.
    """
    if not sanitized_text:
        return "<THREAT_DATA></THREAT_DATA>"
    return f"<THREAT_DATA>\n{sanitized_text}\n</THREAT_DATA>"

