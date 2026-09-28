# Security Alert Management Platform

Open-source SOC alert triage and management platform — ingest alerts from any SIEM/EDR, triage them through a status lifecycle, classify them as **TP / BTP / FP**, tag **MITRE ATT&CK**, enrich IOCs with **VirusTotal / AbuseIPDB**, and keep a chronological analyst timeline. Single-page dashboard, zero build step.

Built from real SOC L1 triage workflow experience: the classification scheme (`fp` / `btp` / `tp`), the severity ladder, the timeline of analyst notes, and the enrichment step all mirror how a Tier-1 analyst actually works a queue.

## Why it exists

Alert fatigue is the SOC's core problem. A queue without discipline buries true positives. This platform is the *workflow layer* between "SIEM says something" and "the ticket says what it was": one screen to see the queue, triage it, classify it honestly, and leave an audit trail for L2/L3 and for the analyst who picks it up tomorrow.

## Features

- **Alert ingestion API** — `POST /api/alerts` from any source (QRadar, Wazuh, Sentinel, GuardDuty, …); raw payload kept for deep-dive.
- **Triage lifecycle** — `new → analyzing → escalated | false_positive | resolved`, assignee, priority.
- **Honest classification** — `fp` (false positive), `btp` (benign true positive), `tp` (true positive) per IOC dimension.
- **MITRE ATT&CK tagging** — tactic + technique per alert (e.g. `TA0011 Command and Control` / `T1071 Application Layer Protocol`).
- **Threat-intel enrichment** — one-click VirusTotal (IP/domain) and AbuseIPDB (IP) lookups; optional API keys, graceful skip when not configured.
- **Analyst timeline** — every state change and note is append-only and timestamped.
- **Dashboard** — stats cards (open criticals, FP rate, TP count), full-text search, severity/status/source filters, detail panel with all IOC + raw JSON + enrichments.
- **API-key auth** — `X-API-Key` header, multiple keys supported, auth on by default.
- **Demo data** — `python scripts/seed_demo.py` seeds a realistic queue (including real-world cases like LockBit sinkhole FPs and CDN-fronted crypto-mining FPs).
- **Docker-ready** — single container, SQLite by default, PostgreSQL via `DATABASE_URL`.

## Architecture

```
SIEM / EDR / any source
        │   POST /api/alerts  (X-API-Key)
        ▼
┌───────────────────────────────┐        ┌────────────────────┐
│  FastAPI (app/)               │        │  Threat-intel      │
│  ┌──────────┬───────────────┐ │        │  VirusTotal        │
│  │ alerts   │  enrichment   │─┼───────▶│  AbuseIPDB         │
│  │ router   │  module       │ │        └────────────────────┘
│  ├──────────┴───────────────┤ │
│  │ SQLAlchemy + SQLite/     │ │
│  │ PostgreSQL (alerts DB)   │ │
│  └──────────────────────────┘ │
└───────────────┬───────────────┘
                │  GET /api/alerts · /api/stats (X-API-Key)
                ▼
        Static dashboard (vanilla JS, no build step)
```

## Quick start

```bash
# 1. Run
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # set ALERT_API_KEYS to something real
uvicorn app.main:app --reload   # → http://localhost:8000

# 2. (optional) seed demo alerts for a populated queue
python scripts/seed_demo.py

# 3. Ingest an alert
curl -X POST http://localhost:8000/api/alerts \
  -H "X-API-Key: dev-key-123" -H "Content-Type: application/json" \
  -d '{
    "title": "Multiple failed SSH login attempts",
    "description": "40+ failed root logins in 10 min",
    "source": "Wazuh", "severity": "high", "category": "Brute-force",
    "ip_address": "203.0.113.7",
    "mitre": ["TA0006 Credential Access", "T1110 Brute Force"]
  }'

# 4. Triage it
curl -X PATCH http://localhost:8000/api/alerts/<id> \
  -H "X-API-Key: dev-key-123" -H "Content-Type: application/json" \
  -d '{"status": "escalated", "classification": "tp", "assignee": "L2-OC",
       "note": "Attack chain confirmed — blocked source, notified asset owner"}'
```

Open the dashboard at `http://localhost:8000`, click **API Key**, paste your key, and work the queue. Interactive API docs: `http://localhost:8000/docs`.

## Docker

```bash
cp .env.example .env
docker compose up --build    # → http://localhost:8000
```

## API surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/alerts` | API key | Ingest alert from SIEM/EDR |
| GET | `/api/alerts` | API key | List/filter/search (`severity`, `status`, `classification`, `source`, `q`, `limit`, `offset`) |
| GET | `/api/alerts/{id}` | API key | Alert detail |
| PATCH | `/api/alerts/{id}` | API key | Triage: status / classification / assignee / priority + note |
| POST | `/api/alerts/{id}/notes` | API key | Append analyst note |
| POST | `/api/alerts/{id}/enrich` | API key | Run IOC enrichment (VT / AbuseIPDB) |
| GET | `/api/stats` | API key | Queue stats (by severity/status/classification, FP rate, open criticals) |
| GET | `/healthz` | — | Health check |

## Roadmap

- [ ] SIEM adapters (QRadar AQL / Wazuh API / Sentinel) as ingestion plugins
- [ ] PostgreSQL migrations (Alembic)
- [ ] Bulk triage actions, watchlists, SLA timers per severity
- [ ] Export queue (CSV / ticket template for ITSM hand-off)

## License

MIT — see [LICENSE](LICENSE). Built and maintained by [Rijalul Fahmi](https://github.com/rijalllllllll). Contributions, issues, and PRs welcome.