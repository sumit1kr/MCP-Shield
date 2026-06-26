from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.models import Report, Vulnerability, Scan
from app.services import s3_service, pdf_service
import uuid
import secrets

def get_risk_level(score: int) -> str:
    if score == 0:       return "SAFE"
    elif score <= 20:    return "LOW"
    elif score <= 40:    return "MEDIUM"
    elif score <= 70:    return "HIGH"
    else:                return "CRITICAL"

def create_report(scan_id: uuid.UUID, vulnerabilities: list, db: Session) -> Report:
    if isinstance(scan_id, str):
        scan_id = uuid.UUID(scan_id)
        
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        
    # Calculate Risk Score
    weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    raw = 0
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_passed = 0
    
    for v in vulnerabilities:
        status_val = v.get("status")
        severity_val = v.get("severity")
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
    
    # Store raw data for JSON report response
    vulnerabilities_data = []
    for v in vulnerabilities:
        vulnerabilities_data.append({
            "attack_id": v.get("attack_id", v.get("id", "")),
            "attack_name": v.get("attack_name", v.get("name", "")),
            "status": v.get("status", ""),
            "severity": v.get("severity"),
            "cvss_score": float(v.get("cvss_score")) if v.get("cvss_score") is not None else None,
            "description": v.get("description"),
            "evidence": v.get("evidence"),
            "fix_suggestion": v.get("fix_suggestion", v.get("fix")),
            "references": v.get("references")
        })
        
    # Save Report
    report = Report(
        scan_id=scan_id,
        risk_score=risk_score,
        risk_level=risk_level,
        total_critical=total_critical,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        total_passed=total_passed,
        raw_data={"vulnerabilities": vulnerabilities_data, "target_url": scan.target_url, "risk_score": risk_score, "risk_level": risk_level}
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    
    # Save individual vulnerabilities to DB
    for v in vulnerabilities:
        db_vuln = Vulnerability(
            report_id=report.id,
            attack_id=v.get("attack_id", v.get("id", "")),
            attack_name=v.get("attack_name", v.get("name", "")),
            status=v.get("status", ""),
            severity=v.get("severity"),
            cvss_score=v.get("cvss_score"),
            description=v.get("description"),
            evidence=v.get("evidence"),
            fix_suggestion=v.get("fix_suggestion", v.get("fix")),
            references=v.get("references"),
            execution_time=v.get("execution_time")
        )
        db.add(db_vuln)
    db.commit()
    db.refresh(report)
    
    return report

def get_report(scan_id, user_id, db: Session) -> Report:
    if isinstance(scan_id, str):
        scan_id = uuid.UUID(scan_id)
    if isinstance(user_id, str):
        user_id = uuid.UUID(user_id)
        
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report

def get_public_report(share_token: str, db: Session) -> Report:
    report = db.query(Report).filter(Report.share_token == share_token, Report.share_enabled == True).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Public report not found or sharing is disabled")
    return report

def enable_sharing(scan_id, user_id, db: Session) -> str:
    if isinstance(scan_id, str):
        scan_id = uuid.UUID(scan_id)
    if isinstance(user_id, str):
        user_id = uuid.UUID(user_id)
        
    report = get_report(scan_id, user_id, db)
    if not report.share_token:
        report.share_token = secrets.token_hex(16) # Generate random 32-char token
    report.share_enabled = True
    db.commit()
    db.refresh(report)
    return report.share_token
