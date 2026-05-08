"""
Instead of rewriting PromptTemplates and LLM initialization in every single 
script, other modules (like attack_mapper.py and report_generator.py) can 
simply call the functions here. This ensures a clean separation of concerns 
and makes it easier to update the underlying LLM logic in the future.

FUNCTIONS PROVIDED:
1. build_few_shot_chain(): Used for highly structured tasks (e.g., MITRE 
   ATT&CK extraction) where the LLM needs curated examples to output valid JSON.
2. build_standard_chain(): Used for standard generation tasks (e.g., writing 
   the final executive summary via Closed-Domain RAG).
"""

from langchain_core.prompts import PromptTemplate, FewShotPromptTemplate
from llm.ollama_client import get_llm

def build_few_shot_chain(examples: list, example_prompt_str: PromptTemplate, system_prefix: str, suffix_str: str, input_vars: list):
    """
    Builds a reusable LangChain pipeline using Few-Shot Prompting.
    This is highly optimized for complex extraction tasks like MITRE ATT&CK mapping,
    where the LLM needs strict examples to output a valid JSON format.
    """
    llm = get_llm()
    
    # Combine the system instructions, the examples, and the actual input placeholder
    prompt = FewShotPromptTemplate(
        examples=examples,
        example_prompt=example_prompt_str,
        prefix=system_prefix,
        suffix=suffix_str,
        input_variables=input_vars
    )
    
    # Return the assembled runnable chain
    return prompt | llm

def build_standard_chain(template_str: str, input_vars: list):
    """
    Builds a standard LangChain pipeline for general tasks.
    Used for Closed-Domain RAG tasks like generating the final Executive Summary.
    """
    llm = get_llm()
    
    prompt = PromptTemplate(
        input_variables=input_vars,
        template=template_str
    )
    
    # Return the assembled runnable chain
    return prompt | llm