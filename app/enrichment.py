"""Threat-intel enrichment.

Performs best-effort lookups against VirusTotal (IP/domain) and AbuseIPDB (IP).
Providers are optional: when the corresponding API key is not configured, the
lookup is skipped and reported as such — no failures, no hard dependency.

This mirrors the enrichment step of a real SOC L1 triage workflow.
"""
import json
import logging
from typing import Any, Callable

import requests

from . import config

log = logging.getLogger(__name__)
TIMEOUT = 6


def _safe(fn: Callable[[], Any]) -> dict:
    try:
        return fn()
    except requests.RequestException as exc:
        log.warning("enrichment request failed: %s", exc)
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - enrichment must never break the API
        log.warning("enrichment failed: %s", exc)
        return {"error": str(exc)}


def vt_ip(ip: str) -> dict:
    if not config.VT_API_KEY:
        return {"skipped": "VirusTotal API key not configured"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config.VT_API_KEY}
    r = requests.get(url, headers=headers, timeout=TIMEOUT)
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    attrs = r.json().get("data", {}).get("attributes", {})
    return {
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": attrs.get("last_analysis_stats"),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def vt_domain(domain: str) -> dict:
    if not config.VT_API_KEY:
        return {"skipped": "VirusTotal API key not configured"}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": config.VT_API_KEY}
    r = requests.get(url, headers=headers, timeout=TIMEOUT)
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    attrs = r.json().get("data", {}).get("attributes", {})
    return {
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": attrs.get("last_analysis_stats"),
        "categories": attrs.get("categories"),
    }


def abuseipdb(ip: str) -> dict:
    if not config.ABUSEIPDB_API_KEY:
        return {"skipped": "AbuseIPDB API key not configured"}
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
        timeout=TIMEOUT,
    )
    if r.status_code != 200:
        return {"error": f"AbuseIPDB HTTP {r.status_code}"}
    d = r.json().get("data", {})
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "country_code": d.get("countryCode"),
        "isp": d.get("isp"),
        "is_whitelisted": d.get("isWhitelisted"),
    }


def enrich_ip(ip: str) -> dict[str, Any]:
    """Run all IP lookups; JSON-safe serialization for unknown values."""
    result: dict[str, Any] = {}
    for label, fn in (("vt_ip", vt_ip), ("abuseipdb", abuseipdb)):
        value = _safe(lambda fn=fn: fn(ip))
        result[label] = json.loads(json.dumps(value, default=str))
    return result


def enrich_domain(domain: str) -> dict[str, Any]:
    value = _safe(vt_domain)
    return {"vt_domain": json.loads(json.dumps(value, default=str))}