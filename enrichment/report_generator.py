"""
PURPOSE:
Generates a final executive summary using Closed-Domain RAG.
Strictly uses only provided database context and mandates source_id citations.
"""
from llm.chain_builder import build_standard_chain

def generate_analyst_summary(source_id: int, cleaned_text: str, entities_list: list, ttp_list: list) -> str:
    """
    Compiles all extracted intelligence into a structured executive report.
    Mandates the use of citations to ensure data lineage and auditability.
    """
    
    # The blueprint for the final intelligence product
    template = """You are a strict Data Summarizer. Your ONLY job is to write EXACTLY ONE short paragraph summarizing the input data.

    CRITICAL RULES:
    1. Output EXACTLY ONE paragraph. No line breaks.
    2. NO lists, NO bullet points, NO bold text, NO headings.
    3. You MUST end the paragraph with the exact string: [source_id: {source_id}]

    EXAMPLE OF THE ONLY ACCEPTABLE FORMAT:
    A buffer overflow vulnerability in telnetd 2.7 allows remote code execution. Threat actors can overflow the buffer to leak BSS data and potentially gain root access. This corresponds to MITRE ATT&CK technique T1190 [source_id: {source_id}]
    
    CONTEXT:
    --- Original Text ---
    {text}
    
    --- Extracted Technical Indicators (Entities) ---
    {entities}
    
    --- Verified MITRE ATT&CK Techniques ---
    {ttps}
    
    REPORT:
    """
    
    # Assemble the pipeline via the standard factory
    chain = build_standard_chain(
        template_str=template,
        input_vars=["source_id", "text", "entities", "ttps"]
    )
    
    # Prepare the actual data payload
    context_data = {
        "source_id": source_id,
        "text": cleaned_text,
        "entities": str(entities_list),
        "ttps": str(ttp_list)
    }
    
    print("[*] Requesting LLM to generate the final analyst summary...")
    try:
        # Invoke the chain to get the final report text
        report = chain.invoke(context_data)
        
        # Ensure compatibility whether response is a string or Message object
        report_text = report.content if hasattr(report, "content") else str(report)
        return report_text.strip()
        
    except Exception as e:
        print(f"[!] LLM Generation Error for report: {e}")
        return "Insufficient data to determine"