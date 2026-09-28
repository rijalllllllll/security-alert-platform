"""API tests for the Security Alert Management Platform."""
import os
import shutil

os.environ["DATABASE_URL"] = "sqlite:///./test_alerts.db"
os.environ.setdefault("ALERT_API_KEYS", "test-key-123")
os.environ.setdefault("REQUIRE_AUTH", "true")

from fastapi.testclient import TestClient  # noqa: E402

from app.database import init_db  # noqa: E402
from app.main import app  # noqa: E402

init_db()  # create tables for the test database
client = TestClient(app)
KEY = {"X-API-Key": "test-key-123"}


def setup_module():
    pass


def teardown_module():
    for f in ("test_alerts.db",):
        if os.path.exists(f):
            os.remove(f)


def _mk(title="Test alert", **kw):
    payload = {"title": title, "description": "desc", "source": "Wazuh", "severity": "high", **kw}
    return client.post("/api/alerts", json=payload, headers=KEY)


def test_healthz_open():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_ingest_requires_api_key():
    r = client.post("/api/alerts", json={"title": "x"})
    assert r.status_code == 401


def test_list_requires_api_key():
    r = client.get("/api/alerts")
    assert r.status_code == 401


def test_ingest_and_list():
    r = _mk(severity="critical")
    assert r.status_code == 201
    body = r.json()
    assert body["title"] == "Test alert"
    assert body["status"] == "new"
    assert body["timeline"][0]["action"] == "alert ingested"

    r2 = client.get("/api/alerts", headers=KEY)
    assert r2.status_code == 200
    assert any(a["id"] == body["id"] for a in r2.json())


def test_invalid_severity_rejected():
    r = _mk(severity="catastrophic")
    assert r.status_code == 422


def test_triage_update_appends_timeline():
    alert = _mk().json()
    r = client.patch(
        f"/api/alerts/{alert['id']}",
        json={"status": "analyzing", "classification": "btp", "assignee": "Rijalul",
              "note": "Scanner host confirmed; benign true positive."},
        headers=KEY,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "analyzing"
    assert body["classification"] == "btp"
    assert body["assignee"] == "Rijalul"
    assert body["timeline"][-1]["note"] == "Scanner host confirmed; benign true positive."


def test_add_note():
    alert = _mk().json()
    r = client.post(f"/api/alerts/{alert['id']}/notes", json={"note": "escalate to L2", "user": "Rijalul"}, headers=KEY)
    assert r.status_code == 200
    assert r.json()["timeline"][-1]["note"] == "escalate to L2"
    assert r.json()["timeline"][-1]["user"] == "Rijalul"


def test_enrich_requires_ioc():
    alert = _mk(title="no ioc here").json()
    r = client.post(f"/api/alerts/{alert['id']}/enrich", headers=KEY)
    assert r.status_code == 400


def test_search_by_ip():
    _mk(title="Beacon", ip_address="203.0.113.99")
    r = client.get("/api/alerts?q=203.0.113.99", headers=KEY)
    assert r.status_code == 200
    assert all(a["ip_address"] == "203.0.113.99" for a in r.json())


def test_filter_by_status_and_severity():
    _mk(title="crit new one", severity="critical", status="new")
    r = client.get("/api/alerts?severity=critical&status=new", headers=KEY)
    assert r.status_code == 200
    assert all(a["severity"] == "critical" and a["status"] == "new" for a in r.json())


def test_stats():
    client.get("/api/alerts", headers=KEY)
    r = client.get("/api/stats", headers=KEY)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 6
    assert body["by_severity"]["critical"] >= 1
    assert set(body["by_status"]) == {"new", "analyzing", "escalated", "false_positive", "resolved"}


def test_not_found():
    r = client.get("/api/alerts/does-not-exist", headers=KEY)
    assert r.status_code == 404


def test_update_invalid_status():
    alert = _mk().json()
    r = client.patch(f"/api/alerts/{alert['id']}", json={"status": "banana"}, headers=KEY)
    assert r.status_code == 422