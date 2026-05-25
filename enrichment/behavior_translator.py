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
1. Write each sentence using formal MITRE ATT&CK terminology (e.g. "privilege escalation", "lateral movement", "command and control", "remote code execution").
2. Each sentence must describe ONE specific adversarial action or technique.
3. Be specific enough that the sentence could match a CVE description or MITRE TTP description.
4. Do NOT include any explanations, greetings, or markdown outside of the JSON.

JSON Schema Requirement:
{{"behaviors": ["Tech sentence 1", "Tech sentence 2"]}}

Input Text:
{osint_text}
"""

def translate_to_behaviors(osint_text: str) -> list:
    """Passes text to Llama 3 and returns a list of technical behavior strings."""
    logger.info("[*] Translating OSINT text to technical behaviors via LLM (HyDE)...")
    
    llm = get_llm()
    prompt = PromptTemplate(input_variables=["osint_text"], template=HYDE_PROMPT)
    chain = prompt | llm
    
    try:
        # Generate LLM response
        response = chain.invoke({"osint_text": osint_text})
        
        # Clean up possible markdown code blocks surrounding the JSON
        clean_json_str = response.strip().strip("```json").strip("```").strip()
        data = json.loads(clean_json_str)
        
        behaviors = data.get("behaviors", [])
        logger.info(f"[+] Extracted {len(behaviors)} distinct behaviors.")
        return behaviors
        
    except json.JSONDecodeError as e:
        logger.error(f"[-] LLM failed to return valid JSON. Error: {e}\nRaw LLM Output: {response}")
        return []
    except Exception as e:
        logger.error(f"[-] Behavior translation failed: {e}")
        return []