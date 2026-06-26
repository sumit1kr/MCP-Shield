from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from urllib.parse import urlparse
from app.database import get_db
from app.models import User
from app.schemas import ScanCreate, ScanOut, ScanStatus
from app.services import scan_service
from app.dependencies import get_current_user
import uuid
import re

router = APIRouter(prefix="/scans", tags=["scans"])

def validate_target_url(url: str):
    # Maximum length 500 chars
    if len(url) > 500:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL is too long. Max 500 characters."
        )
        
    # Must start with http:// or https://
    parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL must start with http:// or https://"
        )
        
    # Must NOT be localhost, 127.x.x.x, 192.168.x.x, 10.x.x.x, 172.16-31.x.x
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid URL hostname."
        )
        
    is_localhost = hostname.lower() == "localhost"
    is_loopback = bool(re.match(r"^127\.\d+\.\d+\.\d+$", hostname))
    is_private_10 = bool(re.match(r"^10\.\d+\.\d+\.\d+$", hostname))
    is_private_172 = bool(re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$", hostname))
    is_private_192 = bool(re.match(r"^192\.168\.\d+\.\d+$", hostname))
    
    if is_localhost or is_loopback or is_private_10 or is_private_172 or is_private_192:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SSRF Protection: Private and local networks are not allowed targets."
        )

@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def create_new_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Validate target URL
    validate_target_url(scan_data.target_url)
    
    # Create the scan and dispatch Celery
    scan = scan_service.create_scan(current_user.id, scan_data, db)
    return scan

@router.get("", response_model=list[ScanOut])
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return scan_service.get_user_scans(current_user.id, skip, limit, db)

@router.get("/{scan_id}", response_model=ScanOut)
def get_scan_details(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return scan_service.get_scan(scan_id, current_user.id, db)

@router.get("/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Try reading from Redis cache first
    cached_status = scan_service.redis_client.get(f"scan_status:{str(scan_id)}")
    if cached_status:
        try:
            status_dict = json.loads(cached_status)
            return ScanStatus(
                scan_id=uuid.UUID(status_dict["scan_id"]),
                status=status_dict["status"],
                progress=status_dict["progress"],
                current_attack=status_dict.get("current_attack"),
                attacks_done=status_dict.get("attacks_done", 0),
                attacks_total=status_dict.get("attacks_total", 7)
            )
        except Exception:
            pass  # Fall back to DB on decoding error
            
    # Database fallback
    scan = scan_service.get_scan(scan_id, current_user.id, db)
    return ScanStatus(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        current_attack=scan.current_attack,
        attacks_done=scan.attacks_done,
        attacks_total=scan.attacks_total
    )

import json # Ensure json is available for cached decoding

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan_service.delete_scan(scan_id, current_user.id, db)
    return None
