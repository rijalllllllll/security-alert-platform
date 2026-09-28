"""Alert API: ingestion, triage, classification, enrichment, timeline."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .. import enrichment
from ..auth import require_api_key
from ..database import get_db
from ..models import Alert, CLASSIFICATIONS
from ..schemas import AlertCreate, AlertOut, AlertUpdate, NoteCreate, StatsOut

router = APIRouter(prefix="/api", tags=["alerts"])

_DEP = Depends(require_api_key)


def _touch(db: Session, alert: Alert, user: str, action: str, note: str = "") -> None:
    alert.timeline = [
        *(alert.timeline or []),
        {"ts": datetime.utcnow().isoformat(), "user": user, "action": action, "note": note},
    ]


@router.post("/alerts", response_model=AlertOut, status_code=status.HTTP_201_CREATED, dependencies=[_DEP])
def ingest(payload: AlertCreate, db: Session = Depends(get_db)) -> Alert:
    """Ingest a new alert from a SIEM/EDR or any monitoring source."""
    alert = Alert(**payload.model_dump())
    _touch(db, alert, "system", "alert ingested")
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/alerts", response_model=list[AlertOut], dependencies=[_DEP])
def list_alerts(
    db: Session = Depends(get_db),
    severity: Optional[str] = None,
    status_: Optional[str] = Query(default=None, alias="status"),
    classification: Optional[str] = None,
    source: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[Alert]:
    """List alerts with filters. `q` searches title/description/IP/domain."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.lower())
    if status_:
        query = query.filter(Alert.status == status_)
    if classification:
        query = query.filter(Alert.classification == classification.lower())
    if source:
        query = query.filter(Alert.source.ilike(f"%{source}%"))
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Alert.title.ilike(like),
                Alert.description.ilike(like),
                Alert.ip_address.ilike(like),
                Alert.domain.ilike(like),
                Alert.file_hash.ilike(like),
            )
        )
    return query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/alerts/{alert_id}", response_model=AlertOut, dependencies=[_DEP])
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertOut, dependencies=[_DEP])
def update_alert(alert_id: str, payload: AlertUpdate, db: Session = Depends(get_db)) -> Alert:
    """Triage an alert: update status/classification/assignee and append a note."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    changes = []
    for field in ("status", "classification", "assignee", "priority"):
        value = getattr(payload, field)
        if value is not None:
            setattr(alert, field, value)
            changes.append(f"{field}={value}")
    if payload.note:
        _touch(db, alert, payload.user, "triage update", payload.note)
    else:
        _touch(db, alert, payload.user, "triage update", "; ".join(changes))

    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/alerts/{alert_id}/notes", response_model=AlertOut, dependencies=[_DEP])
def add_note(alert_id: str, payload: NoteCreate, db: Session = Depends(get_db)) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    _touch(db, alert, payload.user, "note", payload.note)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/alerts/{alert_id}/enrich", response_model=AlertOut, dependencies=[_DEP])
def enrich_alert(alert_id: str, db: Session = Depends(get_db)) -> Alert:
    """Run threat-intel enrichment (VirusTotal / AbuseIPDB) on the alert's IOC."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not alert.ip_address and not alert.domain:
        raise HTTPException(status_code=400, detail="Alert has no IP or domain to enrich")

    enriched: dict = dict(alert.enrichments or {})
    added = []
    if alert.ip_address:
        for key, value in enrichment.enrich_ip(alert.ip_address).items():
            enriched[key] = value
            added.append(key)
    if alert.domain:
        for key, value in enrichment.enrich_domain(alert.domain).items():
            enriched[key] = value
            added.append(key)
    alert.enrichments = enriched
    _touch(db, alert, "system", "enrichment", f"ran threat-intel lookups: {', '.join(added)}")
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/stats", response_model=StatsOut, dependencies=[_DEP])
def stats(db: Session = Depends(get_db)) -> StatsOut:
    total = db.query(func.count(Alert.id)).scalar() or 0
    by_severity = {
        s: db.query(func.count(Alert.id)).filter(Alert.severity == s).scalar() or 0
        for s in ("critical", "high", "medium", "low", "info")
    }
    by_status = {
        s: db.query(func.count(Alert.id)).filter(Alert.status == s).scalar() or 0
        for s in ("new", "analyzing", "escalated", "false_positive", "resolved")
    }
    by_classification = {
        c: db.query(func.count(Alert.id)).filter(Alert.classification == c).scalar() or 0
        for c in ("fp", "btp", "tp")
    }
    open_critical = (
        db.query(func.count(Alert.id))
        .filter(Alert.severity == "critical", Alert.status.in_(("new", "analyzing")))
        .scalar()
        or 0
    )
    classified = sum(by_classification.values())
    false_positive_rate = round(by_classification["fp"] / classified, 3) if classified else None
    return StatsOut(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        by_classification=by_classification,
        open_critical=open_critical,
        false_positive_rate=false_positive_rate,
    )