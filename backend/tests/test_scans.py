import pytest
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db
from app.services import scan_service

TEST_DB_FILE = "./test_mcpshield_scans.db"
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
def clean_tables_and_rate_limits():
    db = TestingSessionLocal()
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.commit()
    db.close()
    # Reset mock Redis store rate limits
    if hasattr(scan_service.redis_client, "store"):
        scan_service.redis_client.store.clear()

client = TestClient(app)

# Helper to register and get a valid token
def get_auth_headers(email="scanuser@example.com"):
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

def test_create_scan_success():
    headers = get_auth_headers("user1@example.com")
    response = client.post(
        "/api/v1/scans",
        json={"target_url": "https://api.github.com", "server_name": "GitHub API Server"},
        headers=headers
    )
    assert response.status_code == 202
    data = response.json()
    assert data["target_url"] == "https://api.github.com"
    assert data["server_name"] == "GitHub API Server"
    assert "id" in data

def test_create_scan_ssrf_protection():
    headers = get_auth_headers("user2@example.com")
    # Loopback
    response = client.post(
        "/api/v1/scans",
        json={"target_url": "http://127.0.0.1/mcp", "server_name": "Localhost Server"},
        headers=headers
    )
    assert response.status_code == 422
    assert "Private and local networks are not allowed targets" in response.json()["detail"]
    
    # Private IP
    response = client.post(
        "/api/v1/scans",
        json={"target_url": "https://192.168.1.50/mcp"},
        headers=headers
    )
    assert response.status_code == 422

def test_create_scan_rate_limiting():
    headers = get_auth_headers("user3@example.com")
    # Run 10 scans successfully
    for i in range(10):
        resp = client.post(
            "/api/v1/scans",
            json={"target_url": f"https://api{i}.github.com"},
            headers=headers
        )
        assert resp.status_code == 202
        
    # The 11th scan should fail with 429
    resp = client.post(
        "/api/v1/scans",
        json={"target_url": "https://api11.github.com"},
        headers=headers
    )
    assert resp.status_code == 429
    assert "Rate limit exceeded" in resp.json()["detail"]

def test_list_and_get_scan():
    headers = get_auth_headers("user4@example.com")
    create_resp = client.post(
        "/api/v1/scans",
        json={"target_url": "https://api.github.com", "server_name": "Test Server"},
        headers=headers
    )
    scan_id = create_resp.json()["id"]
    
    # List scans
    list_resp = client.get("/api/v1/scans", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
    assert list_resp.json()[0]["id"] == scan_id
    
    # Get details
    detail_resp = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == scan_id

def test_get_scan_status():
    headers = get_auth_headers("user5@example.com")
    create_resp = client.post(
        "/api/v1/scans",
        json={"target_url": "https://api.github.com", "server_name": "Status Server"},
        headers=headers
    )
    scan_id = create_resp.json()["id"]
    
    # Check status
    status_resp = client.get(f"/api/v1/scans/{scan_id}/status", headers=headers)
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert data["scan_id"] == scan_id
    assert "status" in data
    assert "progress" in data
