"""SQLAlchemy models for ScoutX results storage.

Everything discovered goes into SQLite — subdomains, alive hosts, findings,
module status, screenshots. This enables scan diffing, querying, and the
web dashboard without re-parsing JSON files.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.types import JSON


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all ScoutX models."""
    pass


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(32), primary_key=True)
    target = Column(String(255), nullable=False, index=True)
    profile = Column(String(32), default="balanced")
    status = Column(String(32), default="running")
    started_at = Column(DateTime, nullable=False, default=_utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    config_snapshot = Column(JSON, nullable=True)
    output_dir = Column(String(512), nullable=True)

    # Relationships
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    modules = relationship("Module", back_populates="scan", cascade="all, delete-orphan")
    screenshots = relationship("Screenshot", back_populates="scan", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(32), ForeignKey("scans.id"), nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    status_code = Column(Integer, nullable=True)
    title = Column(String(512), nullable=True)
    server = Column(String(128), nullable=True)
    technologies = Column(JSON, nullable=True)
    cdn = Column(String(64), nullable=True)
    waf = Column(String(64), nullable=True)
    alive = Column(Boolean, default=False)
    source = Column(String(64), nullable=True)
    first_seen = Column(DateTime, nullable=True, default=_utcnow)
    last_seen = Column(DateTime, nullable=True, default=_utcnow)

    scan = relationship("Scan", back_populates="hosts")
    __table_args__ = (Index("ix_hosts_scan_hostname", "scan_id", "hostname"),)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(32), ForeignKey("scans.id"), nullable=False)
    plugin_name = Column(String(64), nullable=False, index=True)
    finding_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=True)
    confidence = Column(String(16), nullable=True)
    title = Column(String(512), nullable=True)
    description = Column(Text, nullable=True)
    target_url = Column(String(1024), nullable=True)
    hostname = Column(String(255), nullable=True, index=True)
    raw_data = Column(JSON, nullable=True)
    evidence = Column(Text, nullable=True)
    discovered_at = Column(DateTime, nullable=False, default=_utcnow)
    validated = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)

    scan = relationship("Scan", back_populates="findings")
    __table_args__ = (Index("ix_findings_scan_type", "scan_id", "finding_type"),)


class Module(Base):
    __tablename__ = "modules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(32), ForeignKey("scans.id"), nullable=False)
    name = Column(String(64), nullable=False)
    status = Column(String(32), default="pending")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    extra_data = Column("metadata", JSON, nullable=True)

    scan = relationship("Scan", back_populates="modules")
    __table_args__ = (Index("ix_modules_scan_name", "scan_id", "name"),)


class Screenshot(Base):
    __tablename__ = "screenshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(32), ForeignKey("scans.id"), nullable=False)
    url = Column(String(1024), nullable=False)
    hostname = Column(String(255), nullable=True)
    file_path = Column(String(512), nullable=True)
    title = Column(String(512), nullable=True)
    status = Column(String(32), default="pending")
    error_message = Column(String(512), nullable=True)
    captured_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="screenshots")
