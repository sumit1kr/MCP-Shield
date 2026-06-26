from pydantic import BaseModel, EmailStr, Field
from uuid import UUID
from datetime import datetime
from typing import Optional

# Auth
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class UserOut(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

# Scans
class ScanCreate(BaseModel):
    target_url: str
    server_name: Optional[str] = None
    scan_type: str = "full"

class ScanOut(BaseModel):
    id: UUID
    server_name: Optional[str]
    target_url: str
    status: str
    progress: int
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class ScanStatus(BaseModel):
    scan_id: UUID
    status: str
    progress: int
    current_attack: Optional[str]
    attacks_done: int
    attacks_total: int

# Reports
class VulnerabilityOut(BaseModel):
    attack_id: str
    attack_name: str
    status: str
    severity: Optional[str]
    cvss_score: Optional[float]
    description: Optional[str]
    evidence: Optional[str]
    fix_suggestion: Optional[str]
    references: Optional[list[str]]

class ReportOut(BaseModel):
    scan_id: UUID
    risk_score: int
    risk_level: str
    total_critical: int
    total_high: int
    total_medium: int
    total_low: int
    total_passed: int
    vulnerabilities: list[VulnerabilityOut]
    pdf_url: Optional[str]
    share_url: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True
