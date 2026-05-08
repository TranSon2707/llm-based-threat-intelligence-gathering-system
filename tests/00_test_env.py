"""
This test script verifies that the local environment is properly set up for both spaCy and the Ollama LLM.
Commands:
- python -m tests.00_test_env
"""
import spacy
import requests

def test_nlp_environment():
    print("[*] Testing spaCy NLP model...")
    try:
        nlp = spacy.load("en_core_web_sm")
        print("[+] spaCy loaded successfully.")
    except Exception as e:
        print(f"[-] spaCy failed: {e}")

def test_ollama_environment():
    print("\n[*] Testing local Ollama connection...")
    
    # 1. Check if the Ollama service is running
    try:
        health_check = requests.get("http://localhost:11434/api/tags", timeout=5)
        if health_check.status_code == 200:
            print("[+] Ollama service is running.")
        else:
            print(f"[-] Ollama returned unexpected status: {health_check.status_code}")
            return
    except requests.exceptions.ConnectionError: 
        print("[-] Ollama connection failed. Is the Ollama app running?")
        return

    # 2. Check the specific details of the llama3 model
    print("[*] Interrogating llama3 model details...")
    try:
        model_check = requests.post(
            "http://localhost:11434/api/show", 
            json={"name": "llama3"},
            timeout=5
        )
        
        if model_check.status_code == 200:
            details = model_check.json().get("details", {})
            param_size = details.get("parameter_size", "Unknown")
            quantization = details.get("quantization_level", "Unknown")
            
            print(f"[+] Model found: llama3")
            print(f"    - Parameters: {param_size}")
            print(f"    - Quantization: {quantization}")
        elif model_check.status_code == 404:
            print("[-] llama3 is not downloaded. Run: ollama pull llama3")
        else:
            print(f"[-] Failed to fetch model details: {model_check.status_code}")
            
    except Exception as e:
        print(f"[-] Error querying model: {e}")

if __name__ == "__main__":
    test_nlp_environment()
    test_ollama_environment()