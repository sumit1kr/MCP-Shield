from langgraph.graph import StateGraph, START, END
from app.agent.state import ScanState
from app.agent.nodes.fetch_manifest import fetch_manifest
from app.agent.nodes.attacks.a01_prompt_injection import run_prompt_injection
from app.agent.nodes.attacks.a02_tool_poisoning import run_tool_poisoning
from app.agent.nodes.attacks.a03_secret_exposure import run_secret_exposure
from app.agent.nodes.attacks.a04_shell_injection import run_shell_injection
from app.agent.nodes.attacks.a05_ssrf_check import run_ssrf_check
from app.agent.nodes.attacks.a06_rug_pull import run_rug_pull
from app.agent.nodes.attacks.a07_supply_chain import run_supply_chain
from app.agent.nodes.aggregate_results import aggregate_results

def build_scan_graph():
    # Define StateGraph with state class ScanState
    builder = StateGraph(ScanState)
    
    # Register Nodes
    builder.add_node("fetch_manifest", fetch_manifest)
    builder.add_node("run_prompt_injection", run_prompt_injection)
    builder.add_node("run_tool_poisoning", run_tool_poisoning)
    builder.add_node("run_secret_exposure", run_secret_exposure)
    builder.add_node("run_shell_injection", run_shell_injection)
    builder.add_node("run_ssrf_check", run_ssrf_check)
    builder.add_node("run_rug_pull", run_rug_pull)
    builder.add_node("run_supply_chain", run_supply_chain)
    builder.add_node("aggregate_results", aggregate_results)
    
    # Linear Attack Chain setup
    builder.add_edge(START, "fetch_manifest")
    builder.add_edge("fetch_manifest", "run_prompt_injection")
    builder.add_edge("run_prompt_injection", "run_tool_poisoning")
    builder.add_edge("run_tool_poisoning", "run_secret_exposure")
    builder.add_edge("run_secret_exposure", "run_shell_injection")
    builder.add_edge("run_shell_injection", "run_ssrf_check")
    builder.add_edge("run_ssrf_check", "run_rug_pull")
    builder.add_edge("run_rug_pull", "run_supply_chain")
    builder.add_edge("run_supply_chain", "aggregate_results")
    builder.add_edge("aggregate_results", END)
    
    # Compile graph
    return builder.compile()
