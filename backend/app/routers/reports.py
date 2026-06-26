from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Report, Scan
from app.schemas import ReportOut, VulnerabilityOut
from app.services import report_service, s3_service, pdf_service
from app.dependencies import get_current_user
import uuid

router = APIRouter(tags=["reports"])

def build_report_out(report: Report, scan: Scan) -> ReportOut:
    vulnerabilities_out = []
    for v in report.vulnerabilities:
        vulnerabilities_out.append(VulnerabilityOut(
            attack_id=v.attack_id,
            attack_name=v.attack_name,
            status=v.status,
            severity=v.severity,
            cvss_score=float(v.cvss_score) if v.cvss_score is not None else None,
            description=v.description,
            evidence=v.evidence,
            fix_suggestion=v.fix_suggestion,
            references=v.references
        ))
        
    share_url = f"/report/public/{report.share_token}" if report.share_token and report.share_enabled else None
    
    return ReportOut(
        scan_id=report.scan_id,
        risk_score=report.risk_score,
        risk_level=report.risk_level,
        total_critical=report.total_critical,
        total_high=report.total_high,
        total_medium=report.total_medium,
        total_low=report.total_low,
        total_passed=report.total_passed,
        vulnerabilities=vulnerabilities_out,
        pdf_url=report.pdf_url,
        share_url=share_url,
        created_at=report.created_at
    )

@router.get("/api/v1/reports/{scan_id}", response_model=ReportOut)
def get_report_details(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if isinstance(scan_id, str):
        scan_id = uuid.UUID(scan_id)
    report = report_service.get_report(scan_id, current_user.id, db)
    # Fetch scan directly to build output
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    return build_report_out(report, scan)

@router.post("/api/v1/reports/{scan_id}/share")
def share_report(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if isinstance(scan_id, str):
        scan_id = uuid.UUID(scan_id)
    token = report_service.enable_sharing(scan_id, current_user.id, db)
    share_url = f"/report/public/{token}"
    return {"share_url": share_url}

@router.get("/api/v1/reports/{scan_id}/pdf")
def get_report_pdf(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if isinstance(scan_id, str):
        scan_id = uuid.UUID(scan_id)
    report = report_service.get_report(scan_id, current_user.id, db)
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    # Check if pdf already uploaded, if not generate and upload
    if not report.pdf_s3_key:
        report_data = {
            "target_url": scan.target_url,
            "scanned_at": scan.completed_at.isoformat() if scan.completed_at else scan.created_at.isoformat(),
            "risk_score": report.risk_score,
            "risk_level": report.risk_level,
            "vulnerabilities": [{
                "attack_id": v.attack_id,
                "attack_name": v.attack_name,
                "status": v.status,
                "severity": v.severity,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
                "description": v.description,
                "evidence": v.evidence,
                "fix_suggestion": v.fix_suggestion,
                "references": v.references
            } for v in report.vulnerabilities]
        }
        
        pdf_bytes = pdf_service.generate_pdf(report_data)
        s3_key = s3_service.upload_pdf(str(scan_id), str(current_user.id), pdf_bytes)
        
        # Save S3 key to DB
        report.pdf_s3_key = s3_key
        # We also generate presigned download URL
        report.pdf_url = s3_service.generate_presigned_url(s3_key)
        db.commit()
        db.refresh(report)
        
    # Generate fresh presigned download URL (since they expire after 15 mins)
    presigned_download_url = s3_service.generate_presigned_url(report.pdf_s3_key)
    return {"pdf_url": presigned_download_url}

@router.get("/api/v1/report/public/{token}", response_model=ReportOut)
def get_public_report_details(
    token: str,
    db: Session = Depends(get_db)
):
    report = report_service.get_public_report(token, db)
    scan = db.query(Scan).filter(Scan.id == report.scan_id).first()
    return build_report_out(report, scan)
