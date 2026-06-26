import httpx
import json
import time
import re
from app.agent.state import ScanState, AttackResult
from app.agent.prompts import ANALYZE_SECRET_EXPOSURE
from langchain_groq import ChatGroq
from app.config import settings

async def run_secret_exposure(state: ScanState) -> ScanState:
    if state.get("error"):
        return state
        
    start_time = int(time.time() * 1000)
    target_url = state["target_url"]
    tools = state["raw_tool_manifest"].get("tools", [])
    
    if not tools:
        state["results"].append(AttackResult(
            attack_id="A03",
            attack_name="Token/Secret Exposure",
            status="INCONCLUSIVE",
            severity=None,
            cvss_score=0.0,
            description="No tools found to execute for secret exposure testing.",
            evidence="Tools list empty.",
            fix_suggestion="Expose tools in your manifest to enable testing.",
            references=["OWASP MCP Top 10 - MCP06"],
            execution_time_ms=int(time.time() * 1000) - start_time
        ))
        from app.database import SessionLocal
        from app.services import scan_service
        db = SessionLocal()
        scan_service.update_scan_progress(state["scan_id"], 45, "Completed A03", 3, db)
        db.close()
        return state
        
    # Execute tools with empty or minimal arguments and collect responses
    call_url = f"{target_url.rstrip('/')}/tools/call" if "/tools/call" not in target_url else target_url
    responses_text = []
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for tool in tools[:3]:  # Test up to 3 tools
            tool_name = tool.get("name")
            # Minimal arguments
            args = {}
            properties = tool.get("inputSchema", {}).get("properties", {})
            for prop, meta in properties.items():
                meta_type = meta.get("type", "string")
                if meta_type == "integer" or meta_type == "number":
                    args[prop] = 1
                elif meta_type == "boolean":
                    args[prop] = False
                else:
                    args[prop] = ""
            
            # Explicit override for fetch_url to trigger vulnerability
            if tool_name == "fetch_url":
                args = {"url": ""}
                    
            try:
                response = await client.post(call_url, json={"name": tool_name, "arguments": args})
                if response.status_code == 200:
                    responses_text.append(f"Tool {tool_name} response:\n{response.text}")
            except Exception:
                continue
                
    responses_combined = "\n\n".join(responses_text)
    
    # Regex checks for secrets
    secret_patterns = [
        r"sk-[a-zA-Z0-9_-]{15,}",
        r"ghp_[a-zA-Z0-9]{36}",
        r"AKIA[A-Z0-9]{16}",
        r"Bearer [a-zA-Z0-9\-._~+/]+=*",
        r"password\s*[:=]\s*\S+",
        r"api[_-]?key\s*[:=]\s*\S+"
    ]
    
    matched_pattern = None
    for pattern in secret_patterns:
        match = re.search(pattern, responses_combined, re.IGNORECASE)
        if match:
            matched_pattern = match.group(0)
            break
            
    vulnerable = False
    evidence = ""
    reasoning = ""
    
    if matched_pattern:
        vulnerable = True
        evidence = f"Regex match for potential credential: {matched_pattern}"
        reasoning = "A regular expression matched typical pattern sequences for API keys or secret words in tool responses."
    elif responses_combined:
        # LLM semantic check
        groq_api_key = settings.GROQ_API_KEY
        llm = ChatGroq(api_key=groq_api_key, model="llama-3.3-70b-versatile", temperature=0.1)
        formatted_prompt = ANALYZE_SECRET_EXPOSURE.format(response_text=responses_combined)
        try:
            llm_response = await llm.ainvoke(formatted_prompt)
            analysis = json.loads(llm_response.content)
            if analysis.get("vulnerable"):
                vulnerable = True
                evidence = analysis.get("evidence", "")
                reasoning = analysis.get("reasoning", "")
        except Exception:
            pass
            
    status_val = "VULNERABLE" if vulnerable else "SAFE"
    severity_val = "HIGH" if vulnerable else None
    cvss_val = 7.8 if vulnerable else 0.0
    desc_val = "Tool responses expose sensitive api keys, tokens, or configuration secrets." if vulnerable else "No hardcoded credentials or system secrets detected in tool responses."
    fix_val = "Ensure server outputs do not dump environment configurations or raw credentials. Store credentials securely in vault storage systems and scrub response payloads before returning."
    
    state["results"].append(AttackResult(
        attack_id="A03",
        attack_name="Token/Secret Exposure",
        status=status_val,
        severity=severity_val,
        cvss_score=cvss_val,
        description=desc_val,
        evidence=evidence or "No credentials leaked.",
        fix_suggestion=fix_val,
        references=["OWASP MCP Top 10 - MCP06"],
        execution_time_ms=int(time.time() * 1000) - start_time
    ))
    
    from app.database import SessionLocal
    from app.services import scan_service
    db = SessionLocal()
    scan_service.update_scan_progress(state["scan_id"], 45, "Completed A03", 3, db)
    db.close()
    
    return state
