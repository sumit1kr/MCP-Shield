import uuid
import json
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, Text, TIMESTAMP, DECIMAL, ARRAY, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator, CHAR, TEXT
from app.database import Base

# Platform-independent GUID/UUID type for SQLite and PostgreSQL compatibility
class GUID(TypeDecorator):
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            try:
                return str(uuid.UUID(str(value)))
            except ValueError:
                return str(value)
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            return uuid.UUID(value)
        return value

# SQLite compatible array type (stores as JSON string on SQLite, ARRAY on PostgreSQL)
class SQLiteCompatibleArray(TypeDecorator):
    impl = TEXT
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(ARRAY(Text))
        else:
            return dialect.type_descriptor(TEXT)

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == 'postgresql':
            return value
        else:
            return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if dialect.name == 'postgresql':
            return value
        else:
            try:
                return json.loads(value)
            except Exception:
                return []


class User(Base):
    __tablename__ = "users"
    
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    scans_today = Column(Integer, default=0)
    scans_reset_at = Column(TIMESTAMP, default=datetime.utcnow)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scans = relationship("Scan", back_populates="user", cascade="all, delete")


class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    server_name = Column(String(200))
    target_url = Column(Text, nullable=False)
    scan_type = Column(String(20), default="full")
    status = Column(String(20), default="queued")
    progress = Column(Integer, default=0)
    current_attack = Column(String(100))
    attacks_total = Column(Integer, default=7)
    attacks_done = Column(Integer, default=0)
    error_message = Column(Text)
    celery_task_id = Column(String(255))
    started_at = Column(TIMESTAMP)
    completed_at = Column(TIMESTAMP)
    duration_seconds = Column(Integer)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    user = relationship("User", back_populates="scans")
    report = relationship("Report", back_populates="scan", uselist=False)

    @property
    def risk_score(self):
        return self.report.risk_score if self.report else None

    @property
    def risk_level(self):
        return self.report.risk_level if self.report else None



class Report(Base):
    __tablename__ = "reports"
    
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    scan_id = Column(GUID, ForeignKey("scans.id", ondelete="CASCADE"), unique=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    total_critical = Column(Integer, default=0)
    total_high = Column(Integer, default=0)
    total_medium = Column(Integer, default=0)
    total_low = Column(Integer, default=0)
    total_passed = Column(Integer, default=0)
    raw_data = Column(JSONB, nullable=False)
    pdf_s3_key = Column(String(500))
    pdf_url = Column(Text)
    share_token = Column(String(100), unique=True)
    share_enabled = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="report")
    vulnerabilities = relationship("Vulnerability", back_populates="report", cascade="all, delete")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    report_id = Column(GUID, ForeignKey("reports.id", ondelete="CASCADE"))
    attack_id = Column(String(10), nullable=False)
    attack_name = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False)
    severity = Column(String(20))
    cvss_score = Column(DECIMAL(3, 1))
    description = Column(Text)
    evidence = Column(Text)
    fix_suggestion = Column(Text)
    references = Column(SQLiteCompatibleArray)
    execution_time = Column(Integer)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    report = relationship("Report", back_populates="vulnerabilities")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False)
    expires_at = Column(TIMESTAMP, nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
