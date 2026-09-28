"""Seed the database with realistic SOC alerts for demo / screenshots.

Usage:
    python scripts/seed_demo.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal, init_db
from app.models import Alert


DEMO_ALERTS = [
    dict(
        title="Suspicious outbound connection to known LockBit C2 infrastructure",
        description="QRadar offense: repeated outbound TLS connections from 10.10.4.201 to an IP previously associated "
                    "with LockBit ransomware C2 infrastructure. 3 events in 5 minutes.",
        source="IBM QRadar", severity="critical", category="Command & Control",
        ip_address="62.0.58.94", mitre=["TA0011 Command and Control", "T1071 Application Layer Protocol"],
        raw={"offense_id": 68231, "event_count": 3, "log_source": "ltm2.pertamina.com", "protocol": "TLS"},
    ),
    dict(
        title="Multiple failed SSH login attempts (brute-force)",
        description="Wazuh alert: 40+ failed SSH authentications for user 'root' from a single source within 10 minutes. "
                    "No successful login followed.",
        source="Wazuh", severity="high", category="Brute-force",
        ip_address="203.0.113.7", mitre=["TA0006 Credential Access", "T1110 Brute Force"],
        status="analyzing", assignee="Rijalul",
    ),
    dict(
        title="Crypto-mining process detected on cloud workload",
        description="GuardDuty finding: EC2 instance i-0ab12cd34 (out-of-scope DMZ) executing known mining binary "
                    "with outbound traffic to a CDN-fronted pool.",
        source="AWS GuardDuty", severity="high", category="Crypto Mining",
        domain="104.21.api-pool.example", mitre=["TA0040 Impact", "T1496 Resource Hijacking"],
    ),
    dict(
        title="User login from unusual location followed by large data export",
        description="Sentinel: interactive sign-in success from a location not seen for this account in 90 days, "
                    "within 20 minutes of a bulk SharePoint download (~2.1 GB).",
        source="Microsoft Sentinel", severity="medium", category="Account Compromise",
        ip_address="198.51.100.23", mitre=["TA0001 Initial Access", "T1078 Valid Accounts"],
        status="escalated", assignee="L2-OC",
        timeline=[{"ts": "2026-09-27T09:12:00", "user": "Rijalul", "action": "triage update",
                   "note": "Risky sign-in confirmed; account flagged for forced password reset; handed to L2 for UEBA review."}],
    ),
    dict(
        title="Suspicious DNS query to LockBit .onion domain",
        description="QRadar DNS anomaly: internal host resolving a .onion domain. Closer inspection required before "
                    "any containment action.",
        source="IBM QRadar", severity="medium", category="C2 Beaconing",
        ip_address="62.0.58.94", mitre=["TA0011 Command and Control"],
        status="false_positive", classification="fp", assignee="Rijalul",
        timeline=[{"ts": "2026-09-26T14:40:00", "user": "Rijalul", "action": "triage update",
                   "note": "A-record TTL=0 = CheckPoint sinkhole response, not real C2 hit. Benign; closed as FP."}],
    ),
    dict(
        title="Phishing email with macro-enabled attachment delivered to mailbox",
        description="Reported by user: email impersonating internal IT support with attachment 'invoice_09.docm'. "
                    "Attachment detonated in sandbox — no network callback observed; mailbox rules added by attacker.",
        source="Microsoft Sentinel", severity="high", category="Phishing",
        file_hash="7a9f2c4b8e1d6f3a5c0b9274e6d1a8c3", mitre=["TA0001 Initial Access", "T1566 Phishing"],
        status="resolved", classification="tp", assignee="Rijalul",
        timeline=[{"ts": "2026-09-25T11:05:00", "user": "Rijalul", "action": "triage update",
                   "note": "Confirmed TP — sandbox flagged macro behavior. Mailbox cleaned, user re-trained, IOC listed."}],
    ),
    dict(
        title="Port scan detected from internal host",
        description="Internal host performed a full TCP sweep across the 192.168.13.0/24 segment in under 60 seconds.",
        source="Wazuh", severity="low", category="Reconnaissance",
        ip_address="192.168.13.8", mitre=["TA0007 Discovery", "T1046 Network Service Discovery"],
        status="resolved", classification="btp", assignee="Rijalul",
        timeline=[{"ts": "2026-09-24T08:30:00", "user": "Rijalul", "action": "triage update",
                   "note": "BTP — source is the approved vulnerability scanner host. No action needed."}],
    ),
]


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        for item in DEMO_ALERTS:
            timeline = item.pop("timeline", None)
            alert = Alert(**item)
            if timeline:
                alert.timeline = timeline
            db.add(alert)
        db.commit()
        print(f"Seeded {len(DEMO_ALERTS)} demo alerts.")
    finally:
        db.close()


if __name__ == "__main__":
    main()