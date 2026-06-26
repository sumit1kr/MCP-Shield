from app.agent.state import ScanState

def get_risk_level(score: int) -> str:
    if score == 0:       return "SAFE"
    elif score <= 20:    return "LOW"
    elif score <= 40:    return "MEDIUM"
    elif score <= 70:    return "HIGH"
    else:                return "CRITICAL"

async def aggregate_results(state: ScanState) -> ScanState:
    if state.get("error"):
        return state
        
    results = state["results"]
    
    # Calculate Risk Score
    weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    raw = 0
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_passed = 0
    
    for v in results:
        status_val = v.status
        severity_val = v.severity
        if status_val == "VULNERABLE":
            raw += weights.get(severity_val, 0)
            if severity_val == "CRITICAL":
                total_critical += 1
            elif severity_val == "HIGH":
                total_high += 1
            elif severity_val == "MEDIUM":
                total_medium += 1
            elif severity_val == "LOW":
                total_low += 1
        else:
            total_passed += 1
            
    risk_score = min(int((raw / 210) * 100), 100)
    risk_level = get_risk_level(risk_score)
    
    # We store the final aggregates inside a custom metadata field in state if needed,
    # or just sort results in-place: CRITICAL -> HIGH -> MEDIUM -> LOW -> SAFE
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}
    
    state["results"] = sorted(
        results,
        key=lambda x: (0 if x.status == "VULNERABLE" else 1, severity_order.get(x.severity, 4))
    )
    
    return state
