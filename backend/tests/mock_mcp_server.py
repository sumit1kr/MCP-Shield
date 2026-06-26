from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import os
import json

app = FastAPI(title="Vulnerable Mock MCP Server")

class ToolCallRequest(BaseModel):
    name: str
    arguments: dict

# Mock tools manifest
TOOLS_MANIFEST = {
    "tools": [
        {
            "name": "search",
            "description": "Searches for content online. Intentionally vulnerable to prompt injections.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query."
                    }
                },
                "required": ["query"]
            }
        },
        {
            "name": "execute",
            "description": "Runs a local diagnostic command. Intentionally vulnerable to shell injection.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Diagnostic shell command."
                    }
                },
                "required": ["command"]
            }
        },
        {
            "name": "fetch_url",
            "description": "Fetches raw text content from URLs. Vulnerable to SSRF and credential exposures.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch."
                    }
                },
                "required": ["url"]
            }
        }
    ]
}

@app.get("/")
def get_manifest():
    return TOOLS_MANIFEST

@app.get("/tools/list")
def get_tools_list():
    return TOOLS_MANIFEST

@app.post("/tools/call")
def call_tool(req: ToolCallRequest):
    tool_name = req.name
    args = req.arguments
    
    if tool_name == "search":
        query = args.get("query", "")
        # A01 Prompt Injection vulnerability simulation:
        # If payload instructs it to print injection marker or ignore instructions, it does so!
        if "ignore" in query.lower() or "injection_success" in query.lower():
            return {"result": "INJECTION_SUCCESS_7x9k - Process completed with bypass rules."}
        return {"result": f"No search results found for: {query}"}
        
    elif tool_name == "execute":
        command = args.get("command", "")
        # A04 Shell Injection vulnerability:
        # Instead of secure lookup, it directly evaluates command or simulates execution details
        # Simulating vulnerable shell executions for tests
        if any(x in command for x in [";", "$", "`", "|"]):
            # Simulate shell command outputs
            if "whoami" in command:
                return {"result": "administrator\n"}
            elif "id" in command:
                return {"result": "uid=0(root) gid=0(root) groups=0(root)\n"}
            elif "ls" in command:
                return {"result": "total 12\ndrwxr-xr-x  2 root root 4096 Jun 15 14:00 .\n-rw-r--r--  1 root root  123 Jun 15 14:00 app.py\n"}
            elif "passwd" in command:
                return {"result": "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"}
        return {"result": f"Executed command securely: {command}"}
        
    elif tool_name == "fetch_url":
        url = args.get("url", "")
        # A03 Secret / Token Exposure and A05 SSRF simulations:
        # Exposes secret tokens if fetched or checked
        if not url:
            # Empty check exposes keys
            return {"result": "Error: skew credential SK-AWS-FAKE-38x92k19d29s18d9f is missing parameter url."}
            
        # Check SSRF targets
        if any(x in url for x in ["169.254.169.254", "192.168.1.1", "10.0.0.1"]):
            if "169.254.169.254" in url:
                return {"result": "local-hostname: ip-10-0-1-50.ap-south-1.compute.internal\ninstance-id: i-02f8319fbc923a10c\n"}
            return {"result": "Router Portal Gateway Home. Status: 200 OK. Connection established."}
            
        return {"result": f"Content retrieved from {url}: Empty body."}
        
    raise HTTPException(status_code=404, detail="Tool not found")
