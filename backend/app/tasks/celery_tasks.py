import time
import json
import redis
from celery_worker import celery_app
from app.config import settings
from app.database import SessionLocal
from app.models import Scan
from app.agent.graph import build_scan_graph
from app.services import report_service

class InMemoryRedisMock:
    def __init__(self):
        self.store = {}
        
    def get(self, key: str):
        return self.store.get(key)
        
    def set(self, key: str, value: str):
        self.store[key] = str(value)
        return True
        
    def setex(self, key: str, time: int, value: str):
        self.store[key] = str(value)
        return True
        
    def incr(self, key: str):
        val = int(self.store.get(key, 0)) + 1
        self.store[key] = str(val)
        return val
        
    def expire(self, key: str, time: int):
        return True

try:
    redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    redis_client.ping()
except Exception:
    redis_client = InMemoryRedisMock()

@celery_app.task(name="tasks.run_scan")
def run_scan(scan_id: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return f"Scan {scan_id} not found"
            
        scan.status = "running"
        scan.progress = 10
        scan.current_attack = "Fetching tool list"
        db.commit()
        
        status_data = {
            "scan_id": str(scan.id),
            "status": "running",
            "progress": 10,
            "current_attack": "Fetching tool list",
            "attacks_done": 0,
            "attacks_total": 7
        }
        redis_client.setex(f"scan_status:{scan_id}", 600, json.dumps(status_data))
        
        # Build state and compile graph
        initial_state = {
            "scan_id": str(scan.id),
            "target_url": scan.target_url,
            "attack_index": 0,
            "results": [],
            "raw_tool_manifest": {},
            "error": None
        }
        
        graph = build_scan_graph()
        # Execute the compiled LangGraph agent run synchronously
        final_state = graph.invoke(initial_state)
        
        # Check if manifest fetch error occurred
        if final_state.get("error"):
            raise Exception(final_state["error"])
            
        # Compile attack results lists and save report
        vulnerabilities_payload = []
        for r in final_state["results"]:
            vulnerabilities_payload.append({
                "attack_id": r.attack_id,
                "attack_name": r.attack_name,
                "status": r.status,
                "severity": r.severity,
                "cvss_score": r.cvss_score,
                "description": r.description,
                "evidence": r.evidence,
                "fix_suggestion": r.fix_suggestion,
                "references": r.references,
                "execution_time": r.execution_time_ms
            })
            
        # Save report through report service
        report = report_service.create_report(scan.id, vulnerabilities_payload, db)
        
        # Mark scan as complete
        scan.status = "complete"
        scan.progress = 100
        scan.current_attack = None
        scan.completed_at = datetime.utcnow() if hasattr(scan, 'completed_at') else None
        # Record final duration
        if scan.started_at:
            delta = datetime.utcnow() - scan.started_at
            scan.duration_seconds = int(delta.total_seconds())
        db.commit()
        
        # Final update to Redis
        status_data.update({
            "status": "complete",
            "progress": 100,
            "current_attack": None,
            "attacks_done": 7
        })
        redis_client.setex(f"scan_status:{scan_id}", 600, json.dumps(status_data))
        
        return f"Scan {scan_id} completed successfully"
        
    except Exception as e:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.progress = 100
            db.commit()
            
            status_data = {
                "scan_id": scan_id,
                "status": "failed",
                "progress": 100,
                "current_attack": None,
                "attacks_done": scan.attacks_done if scan else 0,
                "attacks_total": 7
            }
            redis_client.setex(f"scan_status:{scan_id}", 600, json.dumps(status_data))
        return f"Scan {scan_id} failed: {str(e)}"
    finally:
        db.close()

from datetime import datetime # Ensure datetime import is available
