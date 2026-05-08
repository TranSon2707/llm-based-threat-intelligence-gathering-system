"""
DESCRIPTION:
This file securely removes HTML formatting from raw threat intelligence data, extracting readable text and preserving relevant URLs for analysis, 
while mitigating evasion techniques.

- Overrides Python's `html.parser.HTMLParser` to ignore content within noisy or dangerous tags (<script>, <style>, <noscript>, <iframe>, <svg>) 
and formats hyperlink URLs into text brackets `[http...]`.
- Strips the HTML tags (in `strip_html`) *before* unescaping HTML entities (like &lt; or &gt;) to ensure malicious encoded scripts 
aren't accidentally rendered into executable prompt instructions.

EXAMPLE RESULT:
Input: "<p>Malware <script>alert(1)</script> found at <a href='http://evil.com'>this link</a>.</p>"
Output: "Malware found at [http://evil.com] ."
"""


import html
import unittest
from html.parser import HTMLParser

class HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.reset()
        self.text_data = []
        self.ignore_tags = {'script', 'style', 'noscript', 'iframe', 'svg'}
        self.skip_current = False
        self.inside_pre = False

    def handle_starttag(self, tag, attrs):
        """Ignore content inside certain tags and track <pre> for preserving whitespace."""
        if tag in self.ignore_tags:
            self.skip_current = True
            
        if tag in ('pre', 'code'):
            self.inside_pre = True
            
        if tag == 'a' and not self.skip_current:
            for attr, value in attrs:
                if attr == 'href' and value.startswith('http'):
                    self.text_data.append((f" [{value}] ", False))

    def handle_endtag(self, tag):
        """Reset skip flag when exiting ignored tags and track exiting <pre>."""
        if tag in self.ignore_tags:
            self.skip_current = False
            
        if tag in ('pre', 'code'):
            self.inside_pre = False

    def handle_data(self, data):
        """Collect text data if not inside ignored tags, preserving whitespace for <pre>."""
        if not self.skip_current:
            self.text_data.append((data, self.inside_pre))

    def get_clean_text(self):
        result = []
        for text, is_pre in self.text_data:
            if is_pre:
                result.append(text)
            else:
                cleaned = ' '.join(text.split())
                if cleaned:
                    result.append(cleaned)
        return ' '.join(result).strip()

def strip_html(raw_html: str) -> str:
    if not raw_html or not isinstance(raw_html, str):
        return ""
    
    try:
        #decoded_html = html.unescape(raw_html)
        #stripper = HTMLStripper()
        #stripper.feed(decoded_html)
        #return stripper.get_clean_text()
    
        # UPDATE: To prevent LLM prompt injection, we must first strip HTML tags before unescaping entities.
        # STEP 1: Strip actual HTML tags first
        stripper = HTMLStripper()
        stripper.feed(raw_html)
        clean_text = stripper.get_clean_text()
        
        # STEP 2: Unescape entities ONLY AFTER stripping
        # This turns &lt;script&gt; into text that the LLM can read
        return html.unescape(clean_text)
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return raw_html

if __name__ == "__main__":
    unittest.main(verbosity=2)