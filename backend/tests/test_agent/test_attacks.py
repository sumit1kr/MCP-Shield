import pytest
import os
import asyncio
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
from app.database import Base, engine, SessionLocal
from app.models import Scan, User
import uuid

# Set up test scan in database since nodes try to update progress in DB
@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Ensure a dummy user exists
    user = db.query(User).first()
    if not user:
        user = User(id=uuid.uuid4(), email="agenttest@example.com", hashed_password="dummy_password")
        db.add(user)
        db.commit()
    db.close()
    yield
    # We keep it clean
    
@pytest.fixture
def clean_scans():
    db = SessionLocal()
    db.query(Scan).delete()
    db.commit()
    db.close()

@pytest.mark.asyncio
async def test_prompt_injection_vulnerable(clean_scans):
    db = SessionLocal()
    user = db.query(User).first()
    scan = Scan(id=uuid.uuid4(), user_id=user.id, target_url="http://127.0.0.1:8001", status="queued")
    db.add(scan)
    db.commit()
    scan_id_str = str(scan.id)
    db.close()
    
    state = ScanState(
        scan_id=scan_id_str,
        target_url="http://127.0.0.1:8001",
        attack_index=0,
        results=[],
        raw_tool_manifest={},
        error=None
    )
    
    # 1. Fetch manifest
    state = await fetch_manifest(state)
    assert len(state["raw_tool_manifest"].get("tools", [])) == 3
    
    # 2. Run prompt injection node
    state = await run_prompt_injection(state)
    assert len(state["results"]) == 1
    result = state["results"][0]
    assert result.attack_id == "A01"
    assert result.status == "VULNERABLE"
    assert result.severity == "CRITICAL"
    assert result.cvss_score == 9.1

@pytest.mark.asyncio
async def test_tool_poisoning_safe(clean_scans):
    db = SessionLocal()
    user = db.query(User).first()
    scan = Scan(id=uuid.uuid4(), user_id=user.id, target_url="http://127.0.0.1:8001", status="queued")
    db.add(scan)
    db.commit()
    scan_id_str = str(scan.id)
    db.close()
    
    state = ScanState(
        scan_id=scan_id_str,
        target_url="http://127.0.0.1:8001",
        attack_index=0,
        results=[],
        raw_tool_manifest={},
        error=None
    )
    state = await fetch_manifest(state)
    
    # Run poisoning node (should be SAFE since mock manifest is static)
    state = await run_tool_poisoning(state)
    assert len(state["results"]) == 1
    result = state["results"][0]
    assert result.attack_id == "A02"
    assert result.status == "SAFE"
    assert result.severity is None

@pytest.mark.asyncio
async def test_secret_exposure_vulnerable(clean_scans):
    db = SessionLocal()
    user = db.query(User).first()
    scan = Scan(id=uuid.uuid4(), user_id=user.id, target_url="http://127.0.0.1:8001", status="queued")
    db.add(scan)
    db.commit()
    scan_id_str = str(scan.id)
    db.close()
    
    state = ScanState(
        scan_id=scan_id_str,
        target_url="http://127.0.0.1:8001",
        attack_index=0,
        results=[],
        raw_tool_manifest={},
        error=None
    )
    state = await fetch_manifest(state)
    
    # Run secret exposure node (should be VULNERABLE since mock server fetch_url empty call leaks keys)
    state = await run_secret_exposure(state)
    assert len(state["results"]) == 1
    result = state["results"][0]
    assert result.attack_id == "A03"
    assert result.status == "VULNERABLE"
    assert result.severity == "HIGH"
    assert result.cvss_score == 7.8

@pytest.mark.asyncio
async def test_shell_injection_vulnerable(clean_scans):
    db = SessionLocal()
    user = db.query(User).first()
    scan = Scan(id=uuid.uuid4(), user_id=user.id, target_url="http://127.0.0.1:8001", status="queued")
    db.add(scan)
    db.commit()
    scan_id_str = str(scan.id)
    db.close()
    
    state = ScanState(
        scan_id=scan_id_str,
        target_url="http://127.0.0.1:8001",
        attack_index=0,
        results=[],
        raw_tool_manifest={},
        error=None
    )
    state = await fetch_manifest(state)
    
    # Run shell injection node (should be VULNERABLE due to direct execution simulation)
    state = await run_shell_injection(state)
    assert len(state["results"]) == 1
    result = state["results"][0]
    assert result.attack_id == "A04"
    assert result.status == "VULNERABLE"
    assert result.severity == "CRITICAL"
    assert result.cvss_score == 9.8

@pytest.mark.asyncio
async def test_ssrf_check_vulnerable(clean_scans):
    db = SessionLocal()
    user = db.query(User).first()
    scan = Scan(id=uuid.uuid4(), user_id=user.id, target_url="http://127.0.0.1:8001", status="queued")
    db.add(scan)
    db.commit()
    scan_id_str = str(scan.id)
    db.close()
    
    state = ScanState(
        scan_id=scan_id_str,
        target_url="http://127.0.0.1:8001",
        attack_index=0,
        results=[],
        raw_tool_manifest={},
        error=None
    )
    state = await fetch_manifest(state)
    
    # Run SSRF check node
    state = await run_ssrf_check(state)
    assert len(state["results"]) == 1
    result = state["results"][0]
    assert result.attack_id == "A05"
    assert result.status == "VULNERABLE"
    assert result.severity == "HIGH"
    assert result.cvss_score == 8.6

@pytest.mark.asyncio
async def test_supply_chain_check_vulnerable(clean_scans):
    db = SessionLocal()
    user = db.query(User).first()
    scan = Scan(id=uuid.uuid4(), user_id=user.id, target_url="http://127.0.0.1:8001", status="queued")
    db.add(scan)
    db.commit()
    scan_id_str = str(scan.id)
    db.close()
    
    state = ScanState(
        scan_id=scan_id_str,
        target_url="http://127.0.0.1:8001",
        attack_index=0,
        results=[],
        raw_tool_manifest={},
        error=None
    )
    
    # Run supply chain (vulnerable because mock server is HTTP, missing CSP, etc.)
    state = await run_supply_chain(state)
    assert len(state["results"]) == 1
    result = state["results"][0]
    assert result.attack_id == "A07"
    assert result.status == "VULNERABLE"
    assert result.severity == "MEDIUM"
    assert result.cvss_score == 5.9
