import httpx
import json
import time
from app.agent.state import ScanState, AttackResult
from app.agent.prompts import ANALYZE_SHELL_INJECTION
from langchain_groq import ChatGroq
from app.config import settings

async def run_shell_injection(state: ScanState) -> ScanState:
    if state.get("error"):
        return state
        
    start_time = int(time.time() * 1000)
    target_url = state["target_url"]
    tools = state["raw_tool_manifest"].get("tools", [])
    
    if not tools:
        state["results"].append(AttackResult(
            attack_id="A04",
            attack_name="Shell Injection",
            status="INCONCLUSIVE",
            severity=None,
            cvss_score=0.0,
            description="No tools found to execute shell injection payloads against.",
            evidence="Tools list is empty.",
            fix_suggestion="Define tools in manifest to enable security testing.",
            references=["OWASP MCP Top 10 - MCP02"],
            execution_time_ms=int(time.time() * 1000) - start_time
        ))
        from app.database import SessionLocal
        from app.services import scan_service
        db = SessionLocal()
        scan_service.update_scan_progress(state["scan_id"], 55, "Completed A04", 4, db)
        db.close()
        return state
        
    groq_api_key = settings.GROQ_API_KEY
    llm = ChatGroq(api_key=groq_api_key, model="llama-3.3-70b-versatile", temperature=0.1)
    
    # Send metacharacter shell payloads into all string arguments of the first tool
    payloads = [
        "; ls -la",
        "$(whoami)",
        "`id`",
        "| cat /etc/passwd"
    ]
    
    call_url = f"{target_url.rstrip('/')}/tools/call" if "/tools/call" not in target_url else target_url
    tool = next((t for t in tools if t.get("name") == "execute"), tools[0])
    tool_name = tool.get("name")
    
    vulnerable = False
    evidence = ""
    reasoning = ""
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for payload in payloads:
            args = {}
            properties = tool.get("inputSchema", {}).get("properties", {})
            for prop in properties:
                args[prop] = payload
                
            try:
                response = await client.post(call_url, json={"name": tool_name, "arguments": args})
                if response.status_code == 200:
                    response_text = response.text
                    
                    # Direct check for shell indications
                    # e.g., root, id=, uid=, total [0-9]+ or common shell errors
                    if any(x in response_text for x in ["uid=", "groups=", "root:", "Permission denied", "Directory of", "bin/sh"]):
                        vulnerable = True
                        evidence = f"Shell execution indicator found directly in response to payload '{payload}': {response_text}"
                        reasoning = "System command execution was detected via direct string matching in tool response."
                        break
                    else:
                        # LLM Semantic Check
                        formatted_prompt = ANALYZE_SHELL_INJECTION.format(response_text=response_text)
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
    severity_val = "CRITICAL" if vulnerable else None
    cvss_val = 9.8 if vulnerable else 0.0
    desc_val = "Downstream shell execution is exposed. Injected arguments are directly interpreted by shell processes." if vulnerable else "No shell injection command execution was successfully executed or detected."
    fix_val = "Avoid invoking shell subsystems (e.g. subprocess with shell=True, os.system). Use parameterized program arguments or API equivalents. Strictly validate parameters against strict alphanumeric regexes."
    
    state["results"].append(AttackResult(
        attack_id="A04",
        attack_name="Shell Injection",
        status=status_val,
        severity=severity_val,
        cvss_score=cvss_val,
        description=desc_val,
        evidence=evidence or "No commands executed.",
        fix_suggestion=fix_val,
        references=["OWASP MCP Top 10 - MCP02"],
        execution_time_ms=int(time.time() * 1000) - start_time
    ))
    
    from app.database import SessionLocal
    from app.services import scan_service
    db = SessionLocal()
    scan_service.update_scan_progress(state["scan_id"], 55, "Completed A04", 4, db)
    db.close()
    
    return state
