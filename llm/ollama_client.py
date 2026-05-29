"""
This file is solely responsible for connecting the Python codebase to 
the local Llama 3 AI running via Ollama.

1. DRY (Don't Repeat Yourself): Instead of declaring IP, port, and model name 
   in every file, other modules simply call get_llm().
2. Maintainability: If the project switches from 'llama3' to another model 
   or changes the host URL, you only need to update exactly one line here, 
   and the entire system adapts.
3. Deterministic AI Behavior: The parameter `temperature=0` forces the AI 
   to return the most accurate, objective output without being "creative" 
   or hallucinating threat intelligence data.
"""
# UPDATED: Use the new dedicated langchain_ollama package

from langchain_ollama import OllamaLLM
from loguru import logger

def get_llm(model: str, num_ctx: int = 4096, num_predict: int = 2048):
   """
   Create and return a LangChain wrapper for the local Llama 3 model.

   Args:
        model       : The model to use. Default is "llama3".
        num_ctx     : context window size (input tokens). Default 4096.
                      Increase to 8192 if input prompts are very long.
        num_predict : max tokens to generate (output tokens). Default 2048.
                      Report generator needs ~1500 tokens for a full report

   Dedicated LLM for translation tasks.
   Uses qwen2.5:7b which is specifically optimized for multilingual tasks
   and follows instructions more reliably than llama3 for translation.
   Falls back to llama3 if qwen2.5 is not available.
    """
   import requests
   if model == "translation":
      try:
         r = requests.get("http://localhost:11434/api/tags", timeout=3)
         models = [m["name"] for m in r.json().get("models", [])]
         if any("qwen2.5" in m for m in models):
            logger.info("[*] Using qwen2.5:7b for translation tasks.")
            return OllamaLLM(
                  model="qwen2.5:7b",
                  base_url="http://localhost:11434",
                  temperature=0,
                  num_ctx=num_ctx,
                  num_predict=num_predict,
            )
         elif any("aya" in m for m in models):
            logger.info("[*] Using aya-expanse:8b for translation tasks.")
            return OllamaLLM(
               model="aya-expanse:8b",
               base_url="http://localhost:11434",
               temperature=0,
               num_ctx=num_ctx,
               num_predict=num_predict,
               )
         else:
            logger.warning("[!] No dedicated translation model found — falling back to llama3.")
            return OllamaLLM(
                  model="llama3",
                  base_url="http://localhost:11434",
                  temperature=0,
                  num_ctx=num_ctx,
                  num_predict=num_predict,
               )
      except Exception:
         logger.error("[!] Failed to connect to Ollama. Ensure the Ollama app is running and the model is downloaded.")
         raise
   elif model == "report" or model == "behavior_extraction" or model == "attack_mapper":
      try:
         r = requests.get("http://localhost:11434/api/tags", timeout=3)
         models = [m["name"] for m in r.json().get("models", [])]
         if any("llama3" in m for m in models):
            logger.info(f"[*] Using llama3 for {model} tasks.")
            return OllamaLLM(
               model="llama3",
               base_url="http://localhost:11434",
               temperature=0,
               num_ctx=num_ctx,
               num_predict=num_predict,
            )

      except Exception:
         logger.error("[!] Failed to connect to Ollama. Ensure the Ollama app is running and the model is downloaded.")
         raise