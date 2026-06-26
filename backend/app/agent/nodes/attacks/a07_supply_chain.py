import httpx
import time
from urllib.parse import urlparse
from app.agent.state import ScanState, AttackResult
async def run_supply_chain(state: ScanState) -> ScanState:
    if state.get("error"):
        return state
        
    start_time = int(time.time() * 1000)
    target_url = state["target_url"]
    
    parsed = urlparse(target_url)
    
    # Check 1: HTTPS only
    is_http_only = parsed.scheme == "http"
    
    # Check 2 & 3: CSP and X-Content-Type-Options headers
    has_csp = False
    has_x_content_type = False
    ssl_error = None
    
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=True) as client:
            response = await client.get(target_url)
            headers = response.headers
            
            # Check CSP header
            has_csp = "content-security-policy" in headers or "x-webkit-csp" in headers
            
            # Check X-Content-Type-Options
            has_x_content_type = headers.get("x-content-type-options", "").lower() == "nosniff"
    except httpx.ConnectError as ce:
        ssl_error = f"Connection failed: {str(ce)}"
    except Exception as e:
        ssl_error = str(e)
        
    vulnerable = False
    evidence_list = []
    
    if is_http_only:
        vulnerable = True
        evidence_list.append("HTTP protocol is used. Plaintext transport leaves tools vulnerable to MITM attacks.")
    if ssl_error:
        # If cert verification fails or connection error
        if "cert" in ssl_error.lower() or "ssl" in ssl_error.lower() or "verify" in ssl_error.lower():
            vulnerable = True
            evidence_list.append(f"SSL handshake or certificate validation failed: {ssl_error}")
    if not has_csp:
        vulnerable = True
        evidence_list.append("Missing Content-Security-Policy (CSP) headers.")
    if not has_x_content_type:
        vulnerable = True
        evidence_list.append("Missing X-Content-Type-Options: nosniff header.")
        
    status_val = "VULNERABLE" if vulnerable else "SAFE"
    severity_val = "MEDIUM" if vulnerable else None
    cvss_val = 5.9 if vulnerable else 0.0
    desc_val = "Insecure channel or supply chain configuration. Transport mechanism lacks rigid integrity/encryption controls." if vulnerable else "The server implements secure HTTPS communication with valid certificates and security configuration headers."
    fix_val = "Enforce HTTPS transport only. Ensure valid certificate chain. Apply CSP and X-Content-Type-Options: nosniff headers to prevent MIME sniffing and cross-site scripts."
    
    state["results"].append(AttackResult(
        attack_id="A07",
        attack_name="Supply Chain Check",
        status=status_val,
        severity=severity_val,
        cvss_score=cvss_val,
        description=desc_val,
        evidence="\n".join(evidence_list) if vulnerable else "Security headers and HTTPS verification passed.",
        fix_suggestion=fix_val,
        references=["OWASP MCP Top 10 - MCP09", "MCP-09: Insufficient Security Headers"],
        execution_time_ms=int(time.time() * 1000) - start_time
    ))
    
    from app.database import SessionLocal
    from app.services import scan_service
    db = SessionLocal()
    scan_service.update_scan_progress(state["scan_id"], 85, "Completed A07", 7, db)
    db.close()
    
    return state
