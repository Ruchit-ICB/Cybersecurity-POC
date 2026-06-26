import os
from datetime import datetime
from typing import Any

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.dialects.sqlite import JSON

Base = declarative_base()

class LogEntry(Base):
    __tablename__ = "log_entries"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String(50), index=True)
    level = Column(String(20), index=True)
    message = Column(Text)
    raw_data = Column(JSON)  # Stores parsed JSON metadata

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    alert_type = Column(String(100), index=True)  # e.g., 'SQL Injection'
    severity = Column(String(20), index=True)     # 'low', 'medium', 'high', 'critical'
    description = Column(Text)
    source_ip = Column(String(50))
    confidence = Column(Float)
    mitre_tactic = Column(String(100))
    ai_summary = Column("gemini_summary", Text, nullable=True)

class Metric(Base):
    __tablename__ = "metrics"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    name = Column(String(50), index=True)
    value = Column(Float)
    host = Column(String(100))

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(50), unique=True, index=True)
    description = Column(Text)
    cvss_score = Column(Float)
    severity = Column(String(20))
    mitigation = Column(Text)

class SystemHealth(Base):
    __tablename__ = "system_health"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    network_tx = Column(Float)
    network_rx = Column(Float)
    active_connections = Column(Integer)

def init_db(db_path: str = "sqlite:///cybersec.db") -> tuple[Any, Any]:
    """Initialize the database and return the engine and session factory."""
    # Ensure directory exists if it's a file path
    if db_path.startswith("sqlite:///"):
        file_path = db_path.replace("sqlite:///", "")
        if file_path and not file_path.startswith(":memory:"):
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

    engine = create_engine(db_path, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal

# Global default session factory (can be overridden during testing)
_, SessionLocal = init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
