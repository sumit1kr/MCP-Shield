import httpx
import json
import time
import asyncio
from app.agent.state import ScanState, AttackResult
from app.agent.prompts import ANALYZE_TOOL_CONSISTENCY
from langchain_groq import ChatGroq
from app.config import settings

async def run_tool_poisoning(state: ScanState) -> ScanState:
    if state.get("error"):
        return state
        
    start_time = int(time.time() * 1000)
    target_url = state["target_url"]
    
    manifest_1 = state["raw_tool_manifest"]
    
    # Wait 3 seconds
    await asyncio.sleep(3.0)
    
    manifest_2 = None
    last_error = None
    
    # Fetch second manifest
    urls_to_try = [
        target_url,
        f"{target_url.rstrip('/')}/tools/list" if "/tools/list" not in target_url else target_url,
        f"{target_url.rstrip('/')}/.well-known/mcp"
    ]
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for url in urls_to_try:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, dict):
                        if "tools" in data:
                            manifest_2 = data
                            break
                        elif "result" in data and isinstance(data["result"], dict) and "tools" in data["result"]:
                            manifest_2 = data["result"]
                            break
            except Exception as e:
                last_error = str(e)
                continue
                
    if not manifest_2:
        state["results"].append(AttackResult(
            attack_id="A02",
            attack_name="Tool Poisoning",
            status="INCONCLUSIVE",
            severity=None,
            cvss_score=0.0,
            description="Could not fetch second manifest to compare tool consistency.",
            evidence=f"Last fetch error: {last_error}",
            fix_suggestion="Ensure server is stable and responds to repetitive GET requests.",
            references=["OWASP MCP Top 10 - MCP01"],
            execution_time_ms=int(time.time() * 1000) - start_time
        ))
        from app.database import SessionLocal
        from app.services import scan_service
        db = SessionLocal()
        scan_service.update_scan_progress(state["scan_id"], 35, "Completed A02", 2, db)
        db.close()
        return state
        
    vulnerable = False
    reasoning = ""
    
    # Compare manifests
    if json.dumps(manifest_1) != json.dumps(manifest_2):
        # Let LLM evaluate semantics
        groq_api_key = settings.GROQ_API_KEY
        llm = ChatGroq(api_key=groq_api_key, model="llama-3.3-70b-versatile", temperature=0.1)
        formatted_prompt = ANALYZE_TOOL_CONSISTENCY.format(
            manifest_1=json.dumps(manifest_1, indent=2),
            manifest_2=json.dumps(manifest_2, indent=2)
        )
        try:
            llm_response = await llm.ainvoke(formatted_prompt)
            analysis = json.loads(llm_response.content)
            if analysis.get("vulnerable"):
                vulnerable = True
                reasoning = analysis.get("reasoning", "Tool definition changes detected.")
        except Exception as e:
            # Fallback direct mismatch
            vulnerable = True
            reasoning = f"Direct raw manifests JSON mismatch: {str(e)}"
            
    status_val = "VULNERABLE" if vulnerable else "SAFE"
    severity_val = "HIGH" if vulnerable else None
    cvss_val = 7.5 if vulnerable else 0.0
    desc_val = "Manifest metadata changes across fetches. A remote actor could poison definitions." if vulnerable else "Server tool definitions are stable across multiple fetches."
    fix_val = "Sign manifests using cryptographic signatures. Prevent runtime updates to manifest definitions unless properly authenticated."
    
    state["results"].append(AttackResult(
        attack_id="A02",
        attack_name="Tool Poisoning",
        status=status_val,
        severity=severity_val,
        cvss_score=cvss_val,
        description=desc_val,
        evidence=reasoning or "No inconsistencies detected.",
        fix_suggestion=fix_val,
        references=["OWASP MCP Top 10 - MCP01"],
        execution_time_ms=int(time.time() * 1000) - start_time
    ))
    
    from app.database import SessionLocal
    from app.services import scan_service
    db = SessionLocal()
    scan_service.update_scan_progress(state["scan_id"], 35, "Completed A02", 2, db)
    db.close()
    
    return state
