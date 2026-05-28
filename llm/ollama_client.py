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

def get_llm(num_ctx: int = 4096, num_predict: int = 2048):
    """
    Create and return a LangChain wrapper for the local Llama 3 model.

    Args:
        num_ctx     : context window size (input tokens). Default 4096.
                      Increase to 8192 if input prompts are very long.
        num_predict : max tokens to generate (output tokens). Default 2048.
                      Report generator needs ~1500 tokens for a full report.
    """
    return OllamaLLM(
        model="llama3",
        base_url="http://localhost:11434",
        temperature=0,
        num_ctx=num_ctx,
        num_predict=num_predict,
    )