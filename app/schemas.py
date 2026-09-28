"""Pydantic request/response schemas."""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from .models import CLASSIFICATIONS, SEVERITIES, STATUSES


class AlertCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    source: str = ""
    severity: str = "medium"
    category: str = ""
    ip_address: str = ""
    domain: str = ""
    file_hash: str = ""
    mitre: list[str] = []
    raw: Optional[dict[str, Any]] = None

    @field_validator("severity")
    @classmethod
    def severity_valid(cls, v: str) -> str:
        v = v.lower()
        if v not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        return v


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    classification: Optional[str] = None
    assignee: Optional[str] = None
    priority: Optional[int] = None
    note: Optional[str] = None  # appended to the timeline
    user: Optional[str] = "analyst"

    @field_validator("status")
    @classmethod
    def status_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        return v

    @field_validator("classification")
    @classmethod
    def classification_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {CLASSIFICATIONS}")
        return v


class NoteCreate(BaseModel):
    note: str = Field(min_length=1)
    user: str = "analyst"


class TimelineEntry(BaseModel):
    ts: datetime
    user: str
    action: str
    note: str = ""


class AlertOut(BaseModel):
    id: str
    title: str
    description: str
    source: str
    severity: str
    category: str
    ip_address: str
    domain: str
    file_hash: str
    mitre: list[str]
    status: str
    classification: Optional[str]
    assignee: str
    priority: int
    raw: Optional[dict[str, Any]]
    enrichments: dict[str, Any]
    timeline: list[Any]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class StatsOut(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_classification: dict[str, int]
    open_critical: int
    false_positive_rate: Optional[float]


class HealthOut(BaseModel):
    status: str
    app: str
    version: str