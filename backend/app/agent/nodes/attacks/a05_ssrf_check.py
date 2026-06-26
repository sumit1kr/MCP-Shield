import httpx
import json
import time
from app.agent.state import ScanState, AttackResult
from app.agent.prompts import ANALYZE_SSRF_RESPONSE
from langchain_groq import ChatGroq
from app.config import settings
async def run_ssrf_check(state: ScanState) -> ScanState:
    if state.get("error"):
        return state
        
    start_time = int(time.time() * 1000)
    target_url = state["target_url"]
    tools = state["raw_tool_manifest"].get("tools", [])
    
    if not tools:
        state["results"].append(AttackResult(
            attack_id="A05",
            attack_name="SSRF Check",
            status="INCONCLUSIVE",
            severity=None,
            cvss_score=0.0,
            description="No tools found to perform SSRF checking against.",
            evidence="Tools list is empty.",
            fix_suggestion="Define tools in manifest to enable security testing.",
            references=["OWASP MCP Top 10 - MCP04"],
            execution_time_ms=int(time.time() * 1000) - start_time
        ))
        from app.database import SessionLocal
        from app.services import scan_service
        db = SessionLocal()
        scan_service.update_scan_progress(state["scan_id"], 65, "Completed A05", 5, db)
        db.close()
        return state
        
    groq_api_key = settings.GROQ_API_KEY
    llm = ChatGroq(api_key=groq_api_key, model="llama-3.3-70b-versatile", temperature=0.1)
    
    # Internal URLs
    internal_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/",
        "http://10.0.0.1/"
    ]
    
    call_url = f"{target_url.rstrip('/')}/tools/call" if "/tools/call" not in target_url else target_url
    tool = next((t for t in tools if t.get("name") == "fetch_url"), tools[0])
    tool_name = tool.get("name")
    
    vulnerable = False
    evidence = ""
    reasoning = ""
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for url_payload in internal_urls:
            args = {}
            properties = tool.get("inputSchema", {}).get("properties", {})
            for prop in properties:
                args[prop] = url_payload
                
            try:
                start_req = time.time()
                response = await client.post(call_url, json={"name": tool_name, "arguments": args})
                duration = time.time() - start_req
                
                if response.status_code == 200:
                    response_text = response.text
                    
                    # Timing difference (> 2s suggests internal fetch blocking or timing out)
                    # Or direct leakage of AWS metadata / router pages
                    if "AMI" in response_text or "instance-id" in response_text or "local-hostname" in response_text or duration > 2.0:
                        vulnerable = True
                        evidence = f"Timing anomaly ({duration:.2f}s) or direct AWS metadata leakage observed for payload '{url_payload}': {response_text}"
                        reasoning = "Response latency or content inspection indicated a connection or timeout fetching internal resources."
                        break
                    else:
                        formatted_prompt = ANALYZE_SSRF_RESPONSE.format(response_text=response_text)
                        llm_response = await llm.ainvoke(formatted_prompt)
                        try:
                            analysis = json.loads(llm_response.content)
                            if analysis.get("vulnerable"):
                                vulnerable = True
                                evidence = analysis.get("evidence", response_text)
                                reasoning = analysis.get("reasoning", "")
                                break
                        except Exception:
                            pass
            except Exception:
                continue
                
    status_val = "VULNERABLE" if vulnerable else "SAFE"
    severity_val = "HIGH" if vulnerable else None
    cvss_val = 8.6 if vulnerable else 0.0
    desc_val = "Downstream SSRF vulnerability. The server allows input parameters to trigger outbound requests to private network coordinates." if vulnerable else "No SSRF vulnerabilities or internal connection attempts were successfully detected."
    fix_val = "Implement strict outbound URL filtering (allowlist only). Block outbound requests to local loopback addresses (127.0.0.1) and private IP ranges (10.x.x.x, 192.168.x.x, 172.16.x.x, 169.254.169.254)."
    
    state["results"].append(AttackResult(
        attack_id="A05",
        attack_name="SSRF Check",
        status=status_val,
        severity=severity_val,
        cvss_score=cvss_val,
        description=desc_val,
        evidence=evidence or "No internal resources fetched.",
        fix_suggestion=fix_val,
        references=["OWASP MCP Top 10 - MCP04"],
        execution_time_ms=int(time.time() * 1000) - start_time
    ))
    
    from app.database import SessionLocal
    from app.services import scan_service
    db = SessionLocal()
    scan_service.update_scan_progress(state["scan_id"], 65, "Completed A05", 5, db)
    db.close()
    
    return state
