import pytest
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db

# Use a file-based SQLite database for testing to avoid :memory: connection isolation issues
TEST_DB_FILE = "./test_mcpshield.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{TEST_DB_FILE}"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override get_db dependency
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    # Setup database file once per test session
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except PermissionError:
            pass
    Base.metadata.create_all(bind=engine)
    yield
    # Dispose engine to close active connections
    engine.dispose()
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except PermissionError:
            pass

@pytest.fixture(autouse=True)
def clean_tables():
    # Clear tables before each test to maintain isolation without deleting the db file
    db = TestingSessionLocal()
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.commit()
    db.close()

client = TestClient(app)

def test_register_user_success():
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "testuser@example.com", "password": "securepassword123", "full_name": "Test User"}
    )
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

def test_register_user_duplicate_email():
    # Register first time
    client.post(
        "/api/v1/auth/register",
        json={"email": "duplicate@example.com", "password": "password123"}
    )
    # Register again with same email
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "duplicate@example.com", "password": "password123"}
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "This email is already registered. Login instead?"

def test_login_user_success():
    # Register first
    client.post(
        "/api/v1/auth/register",
        json={"email": "loginuser@example.com", "password": "securepassword123"}
    )
    # Login
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "loginuser@example.com", "password": "securepassword123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data

def test_login_user_invalid_credentials():
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@example.com", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

def test_get_current_user_profile():
    # Register first
    reg_response = client.post(
        "/api/v1/auth/register",
        json={"email": "profileuser@example.com", "password": "securepassword123", "full_name": "Profile User"}
    )
    token = reg_response.json()["access_token"]
    
    # Get profile
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "profileuser@example.com"
    assert data["full_name"] == "Profile User"
