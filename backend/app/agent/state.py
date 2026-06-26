from typing import TypedDict, Optional, List
from dataclasses import dataclass

@dataclass
class AttackResult:
    attack_id: str
    attack_name: str
    status: str              # VULNERABLE | SAFE | INCONCLUSIVE
    severity: Optional[str]   # CRITICAL | HIGH | MEDIUM | LOW | None
    cvss_score: Optional[float]
    description: str
    evidence: str
    fix_suggestion: str
    references: List[str]
    execution_time_ms: int

class ScanState(TypedDict):
    scan_id: str
    target_url: str
    attack_index: int
    results: List[AttackResult]
    raw_tool_manifest: dict
    error: Optional[str]
