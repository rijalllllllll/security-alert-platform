"""Alert domain model.

Mirrors a real SOC L1 triage workflow: alerts are ingested from sources
(SIEM/EDR), triaged through a status lifecycle, classified as FP / BTP / TP,
tagged with MITRE ATT&CK references, enriched with threat-intel lookups,
and annotated with a chronological timeline of analyst notes.
"""
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON
from sqlalchemy.types import JSON

from .database import Base

# Workflow-agnostic JSON column (works on SQLite and PostgreSQL)
JsonType = JSON().with_variant(SQLiteJSON, "sqlite")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["new", "analyzing", "escalated", "false_positive", "resolved"]
CLASSIFICATIONS = ["fp", "btp", "tp"]


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    description = Column(Text, default="")
    source = Column(String(64), default="")          # SIEM/EDR: QRadar, Wazuh, Sentinel, ...
    severity = Column(String(16), default="medium")  # critical | high | medium | low | info
    category = Column(String(64), default="")        # e.g. Malware, Phishing, C2, Brute-force
    ip_address = Column(String(64), default="")
    domain = Column(String(255), default="")
    file_hash = Column(String(128), default="")

    # MITRE ATT&CK references, e.g. ["TA0001 Initial Access", "T1566 Phishing"]
    mitre = Column(JsonType, default=list)

    # Triage state
    status = Column(String(24), default="new", index=True)          # new → analyzing → escalated|false_positive|resolved
    classification = Column(String(8), nullable=True, index=True)   # fp | btp | tp
    assignee = Column(String(64), default="")
    priority = Column(Integer, default=0)                            # SOC priority (higher = more urgent)

    # Raw payload as received from the source (kept for deep-dive)
    raw = Column(JsonType, nullable=True)
    # Threat-intel enrichment results: {"vt_ip": {...}, "abuseipdb": {...}}
    enrichments = Column(JsonType, default=dict)
    # Analyst timeline: [{"ts": "...", "user": "...", "action": "...", "note": "..."}]
    timeline = Column(JsonType, default=list)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "severity": self.severity,
            "category": self.category,
            "ip_address": self.ip_address,
            "domain": self.domain,
            "file_hash": self.file_hash,
            "mitre": self.mitre or [],
            "status": self.status,
            "classification": self.classification,
            "assignee": self.assignee,
            "priority": self.priority,
            "raw": self.raw,
            "enrichments": self.enrichments or {},
            "timeline": self.timeline or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }