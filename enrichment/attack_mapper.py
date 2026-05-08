"""
PURPOSE:
Maps cleaned threat text to MITRE ATT&CK TTPs using a local LLM and Few-Shot prompting.
Includes an anti-hallucination filter to validate generated TTP IDs against the official MITRE dataset.
"""
import json
import os
from mitreattack.stix20 import MitreAttackData

# Using the specialized factory for few-shot pipelines
from llm.chain_builder import build_few_shot_chain
from enrichment.few_shot_examples import FEW_SHOT_EXAMPLES, EXAMPLE_PROMPT, SYSTEM_PREFIX, SUFFIX_TEMPLATE

MITRE_FILE = "enterprise-attack.json"
mitre_data = None

# Initialize MITRE reference data for validation
if os.path.exists(MITRE_FILE):
    try:
        mitre_data = MitreAttackData(MITRE_FILE)
    except Exception as e:
        print(f"[!] Error loading '{MITRE_FILE}': {e}")
else:
    print(f"[!] Warning: '{MITRE_FILE}' not found. Validation disabled.")

def validate_ttp_id(ttp_id: str) -> bool:
    """
    Checks if a generated TTP ID exists in the official MITRE ATT&CK dataset.
    This prevents the LLM from inventing fake IDs (Hallucination).
    """
    if not mitre_data:
        return False
    try:
        obj = mitre_data.get_object_by_attack_id(ttp_id, 'attack-pattern')
        return True if obj else False
    except Exception:
        return False

def map_text_to_mitre(cleaned_text: str) -> list:
    """
    Orchestrates the mapping process by invoking the Few-Shot chain 
    and filtering the output through the anti-hallucination layer.
    """
    # Build the chain using the unified factory
    chain = build_few_shot_chain(
        examples=FEW_SHOT_EXAMPLES,
        example_prompt_str=EXAMPLE_PROMPT,
        system_prefix=SYSTEM_PREFIX,
        suffix_str=SUFFIX_TEMPLATE,
        input_vars=["threat_text"]
    )
    
    print("[*] Requesting LLM to analyze MITRE ATT&CK mapping...")
    # Execute the chain with the specific threat context
    response = chain.invoke({"threat_text": cleaned_text})
    
    valid_ttps = []
    try:
        # Extract JSON block from the LLM's text response
        start_idx = response.find('[')
        end_idx = response.rfind(']') + 1
        
        if start_idx != -1 and end_idx != -1:
            json_str = response[start_idx:end_idx]
            extracted_ttps = json.loads(json_str)
            
            # Cross-validate every prediction against the MITRE database
            for ttp in extracted_ttps:
                ttp_id = ttp.get("id", "").strip()
                technique_name = ttp.get("name", "").strip()
                
                if validate_ttp_id(ttp_id):
                    valid_ttps.append({
                        "ttp_id": ttp_id,
                        "technique_name": technique_name,
                        "justification": ttp.get("justification", "")
                    })
                else:
                    print(f"[!] HALLUCINATION BLOCKED: Fabricated ID {ttp_id}")
        else:
            print("[!] Error: LLM response did not contain a valid JSON array.")
            
    except json.JSONDecodeError as e:
        print(f"[!] JSON Parsing Error: {e}")
        
    return valid_ttps