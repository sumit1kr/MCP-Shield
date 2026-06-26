import pytest
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db
from app.services import report_service, scan_service
from app.schemas import ScanCreate

TEST_DB_FILE = "./test_mcpshield_reports.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{TEST_DB_FILE}"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except PermissionError:
            pass
    Base.metadata.create_all(bind=engine)
    yield
    engine.dispose()
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except PermissionError:
            pass

@pytest.fixture(autouse=True)
def clean_tables():
    db = TestingSessionLocal()
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.commit()
    db.close()

client = TestClient(app)

def get_auth_headers(email="reportuser@example.com"):
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "securepassword123"}
    )
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "securepassword123"}
    )
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_generate_and_retrieve_report():
    headers = get_auth_headers("r1@example.com")
    db = TestingSessionLocal()
    
    # 1. Create a scan
    scan = scan_service.create_scan(
        user_id=db.query(scan_service.User).first().id,
        data=ScanCreate(target_url="https://api.github.com", server_name="GitHub Target"),
        db=db
    )
    
    # 2. Add fake vulnerability data & build report
    vulns = [
        {"id": "A01", "name": "Prompt Injection", "status": "VULNERABLE", "severity": "CRITICAL", "cvss_score": 9.1, "description": "Injection test", "fix": "Sanitize inputs", "references": []},
        {"id": "A02", "name": "Tool Poisoning", "status": "SAFE", "severity": None, "cvss_score": 0.0, "description": "Safe test", "fix": None, "references": []}
    ]
    report = report_service.create_report(scan.id, vulns, db)
    
    # 3. Retrieve report via API
    response = client.get(f"/api/v1/reports/{scan.id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == str(scan.id)
    assert data["risk_score"] == 14  # (30 / 210) * 100 = 14
    assert data["risk_level"] == "LOW"
    assert len(data["vulnerabilities"]) == 2
    db.close()

def test_share_report_publicly():
    headers = get_auth_headers("r2@example.com")
    db = TestingSessionLocal()
    
    scan = scan_service.create_scan(
        user_id=db.query(scan_service.User).first().id,
        data=ScanCreate(target_url="https://api.github.com"),
        db=db
    )
    vulns = [{"id": "A01", "name": "Prompt Injection", "status": "VULNERABLE", "severity": "CRITICAL"}]
    report = report_service.create_report(scan.id, vulns, db)
    
    # Enable sharing
    share_resp = client.post(f"/api/v1/reports/{scan.id}/share", headers=headers)
    assert share_resp.status_code == 200
    share_url = share_resp.json()["share_url"]
    assert "public" in share_url
    
    # Fetch public endpoint without headers
    token = share_url.split("/")[-1]
    public_resp = client.get(f"/api/v1/report/public/{token}")
    assert public_resp.status_code == 200
    assert public_resp.json()["scan_id"] == str(scan.id)
    db.close()

def test_get_report_pdf():
    headers = get_auth_headers("r3@example.com")
    db = TestingSessionLocal()
    
    scan = scan_service.create_scan(
        user_id=db.query(scan_service.User).first().id,
        data=ScanCreate(target_url="https://api.github.com"),
        db=db
    )
    vulns = [{"id": "A01", "name": "Prompt Injection", "status": "VULNERABLE", "severity": "CRITICAL"}]
    report = report_service.create_report(scan.id, vulns, db)
    
    # Request PDF Url
    response = client.get(f"/api/v1/reports/{scan.id}/pdf", headers=headers)
    assert response.status_code == 200
    assert "pdf_url" in response.json()
    assert ".pdf" in response.json()["pdf_url"]
    db.close()
