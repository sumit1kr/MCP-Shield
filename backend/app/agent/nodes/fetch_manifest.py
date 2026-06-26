import httpx
from app.agent.state import ScanState

async def fetch_manifest(state: ScanState) -> ScanState:
    target_url = state["target_url"]
    
    # Try the endpoints as specified: GET {target_url}, {target_url}/tools/list, {target_url}/.well-known/mcp
    urls_to_try = [
        target_url,
        f"{target_url.rstrip('/')}/tools/list" if "/tools/list" not in target_url else target_url,
        f"{target_url.rstrip('/')}/.well-known/mcp"
    ]
    
    raw_manifest = None
    last_error = None
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for url in urls_to_try:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    # An MCP manifest typically has a "tools" list directly or inside key "result" -> "tools"
                    if isinstance(data, dict):
                        if "tools" in data:
                            raw_manifest = data
                            break
                        elif "result" in data and isinstance(data["result"], dict) and "tools" in data["result"]:
                            raw_manifest = data["result"]
                            break
            except Exception as e:
                last_error = str(e)
                continue
                
    if not raw_manifest:
        state["error"] = f"Target server unreachable or not a valid MCP endpoint. Last error: {last_error}"
        state["raw_tool_manifest"] = {}
    else:
        state["raw_tool_manifest"] = raw_manifest
        
    return state
