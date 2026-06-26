import httpx
import json
import time
import asyncio
from app.agent.state import ScanState, AttackResult
from app.agent.prompts import ANALYZE_TOOL_CONSISTENCY
from langchain_groq import ChatGroq
from app.config import settings
async def run_rug_pull(state: ScanState) -> ScanState:
    if state.get("error"):
        return state
        
    start_time = int(time.time() * 1000)
    target_url = state["target_url"]
    
    manifests = [state["raw_tool_manifest"]]
    
    # Fetch at t=15s and t=30s
    for gap in [15.0, 15.0]:
        # Avoid long sleep under mocked redis local tests for test speedup
        # But run real sleep here
        await asyncio.sleep(0.5 if "test_mcpshield" in settings.DATABASE_URL else gap)
        
        manifest = None
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
                                manifest = data
                                break
                            elif "result" in data and isinstance(data["result"], dict) and "tools" in data["result"]:
                                manifest = data["result"]
                                break
                except Exception:
                    continue
        if manifest:
            manifests.append(manifest)
            
    vulnerable = False
    evidence = ""
    
    if len(manifests) > 1:
        first_manifest_str = json.dumps(manifests[0])
        # Compare all subsequent manifests with the first one
        for idx, m in enumerate(manifests[1:]):
            if json.dumps(m) != first_manifest_str:
                # LLM Semantic Check
                groq_api_key = settings.GROQ_API_KEY
                llm = ChatGroq(api_key=groq_api_key, model="llama-3.3-70b-versatile", temperature=0.1)
                formatted_prompt = ANALYZE_TOOL_CONSISTENCY.format(
                    manifest_1=json.dumps(manifests[0], indent=2),
                    manifest_2=json.dumps(m, indent=2)
                )
                try:
                    llm_response = await llm.ainvoke(formatted_prompt)
                    analysis = json.loads(llm_response.content)
                    if analysis.get("vulnerable"):
                        vulnerable = True
                        evidence = f"Semantic discrepancy detected at fetch {idx+1}: {analysis.get('reasoning')}"
                        break
                except Exception:
                    vulnerable = True
                    evidence = f"Direct raw manifests mismatch at fetch {idx+1}"
                    break
                    
    status_val = "VULNERABLE" if vulnerable else "SAFE"
    severity_val = "MEDIUM" if vulnerable else None
    cvss_val = 6.5 if vulnerable else 0.0
    desc_val = "Manifest definitions changed dynamically during operational life. Indicates potential dynamic tool manipulation." if vulnerable else "Server tool definitions remain semantically stable across multiple time intervals."
    fix_val = "Deploy immutable manifests. Ensure updates to tools list require server restarts or administrative approvals rather than dynamic metadata generation."
    
    state["results"].append(AttackResult(
        attack_id="A06",
        attack_name="Rug Pull Detection",
        status=status_val,
        severity=severity_val,
        cvss_score=cvss_val,
        description=desc_val,
        evidence=evidence or "Manifest definitions remain stable.",
        fix_suggestion=fix_val,
        references=["OWASP MCP Top 10 - MCP01"],
        execution_time_ms=int(time.time() * 1000) - start_time
    ))
    
    from app.database import SessionLocal
    from app.services import scan_service
    db = SessionLocal()
    scan_service.update_scan_progress(state["scan_id"], 75, "Completed A06", 6, db)
    db.close()
    
    return state
