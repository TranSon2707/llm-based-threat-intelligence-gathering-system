"""
FILE: enrichment/behavior_translator.py
ROLE: Semantic Translation (Phase 3)
PURPOSE: Implements the HyDE pattern. Instructs the LLM to read informal 
OSINT text and output a strict JSON array of single-sentence technical behaviors.
"""
import json
import logging
from llm.ollama_client import get_llm
from langchain_core.prompts import PromptTemplate

logger = logging.getLogger(__name__)

# Strict prompt template requiring a specific JSON schema
HYDE_PROMPT = """
You are an expert Cyber Threat Intelligence Analyst with deep knowledge of MITRE ATT&CK and CVE databases.
Read the following translated OSINT text. Extract the core adversarial behaviors and technical actions.
Convert these into a strict JSON array of distinct single-sentence technical descriptions.

CRITICAL RULES:
1. Write each sentence using formal MITRE ATT&CK terminology. Mirror the exact phrasing style
   used in MITRE ATT&CK technique descriptions. Examples of correct phrasing style:
   - "Adversary used valid accounts with stolen credentials to maintain persistent access"
   - "Attacker executed remote code on target system by exploiting a vulnerability in the application"
   - "Adversary performed data exfiltration over command and control channel using encrypted protocol"
   - "Attacker moved laterally through the network using compromised credentials and remote services"
   - "Adversary established persistence by creating scheduled tasks on compromised systems"
2. Each sentence must describe ONE specific adversarial action or technique.
3. Avoid incident-specific details like organization names, country names, or dates —
   focus on the TECHNIQUE, not the victim.
4. Be specific enough that the sentence could match a MITRE TTP description directly.
5. Do NOT include any explanations, greetings, or markdown outside of the JSON.

JSON Schema Requirement:
{{"behaviors": ["Tech sentence 1", "Tech sentence 2"]}}

Input Text:
{osint_text}
"""

def translate_to_behaviors(osint_text: str) -> list:
    """Passes text to Llama 3 and returns a list of technical behavior strings."""
    
    # Early return for empty/whitespace input — no point calling the LLM
    if not osint_text or not osint_text.strip():
        logger.info("[*] Empty input — skipping LLM call.")
        return []
    
    logger.info("[*] Translating OSINT text to technical behaviors via LLM (HyDE)...")
    
    llm = get_llm()
    prompt = PromptTemplate(input_variables=["osint_text"], template=HYDE_PROMPT)
    chain = prompt | llm
    
    try:
        # Generate LLM response
        response = chain.invoke({"osint_text": osint_text})
        
        # Strip markdown fences first
        clean_json_str = response.strip().strip("```json").strip("```").strip()
        
        # Strip any natural language preamble before the JSON object
        # LLMs often add "Here is the output:" before the actual JSON
        brace_idx = clean_json_str.find("{")
        if brace_idx > 0:
            clean_json_str = clean_json_str[brace_idx:]
        
        # Also strip any trailing note after the closing brace
        last_brace_idx = clean_json_str.rfind("}")
        if last_brace_idx != -1:
            clean_json_str = clean_json_str[:last_brace_idx + 1]
        
        data = json.loads(clean_json_str)
        
        # Handle both {"behaviors": [...]} and bare [...] responses
        if isinstance(data, list):
            behaviors = data
        else:
            behaviors = data.get("behaviors", [])
            
        logger.info(f"[+] Extracted {len(behaviors)} distinct behaviors.")
        return behaviors
        
    except json.JSONDecodeError as e:
        logger.error(f"[-] LLM failed to return valid JSON. Error: {e}\nRaw LLM Output: {response}")
        return []
    except Exception as e:
        logger.error(f"[-] Behavior translation failed: {e}")
        return []