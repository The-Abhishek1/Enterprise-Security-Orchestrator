# src/workers/asset_differ.py
"""
Asset Differ — compares two snapshots and produces a list of changes with severity.
Called after every scan to determine what changed since the last snapshot.
"""
from datetime import datetime, timezone, timedelta
from typing   import Any, Dict, List, Optional


def diff_snapshots(
    previous: Optional[Dict[str, Any]],
    current:  Dict[str, Any],
    target:   str,
) -> List[Dict[str, Any]]:
    """
    Compare previous vs current snapshot.
    Returns list of change dicts: {changeType, severity, oldValue, newValue, description}
    """
    if not previous:
        # First scan — no diff, just note we've got a baseline
        return [{
            "changeType":  "baseline",
            "severity":    "info",
            "oldValue":    None,
            "newValue":    target,
            "description": f"Initial baseline established for {target}",
        }]

    changes: List[Dict] = []

    # ── Subdomain changes ─────────────────────────────────────────────────────
    prev_subs = set(previous.get("subdomains", []))
    curr_subs = set(current.get("subdomains", []))

    for sub in curr_subs - prev_subs:
        changes.append({
            "changeType":  "new_subdomain",
            "severity":    "high",
            "oldValue":    None,
            "newValue":    sub,
            "description": f"New subdomain discovered: {sub}",
        })
    for sub in prev_subs - curr_subs:
        changes.append({
            "changeType":  "subdomain_removed",
            "severity":    "low",
            "oldValue":    sub,
            "newValue":    None,
            "description": f"Subdomain no longer resolving: {sub}",
        })

    # ── Port changes ──────────────────────────────────────────────────────────
    prev_ports = {p["port"]: p for p in previous.get("openPorts", [])}
    curr_ports = {p["port"]: p for p in current.get("openPorts", [])}

    for port, info in curr_ports.items():
        if port not in prev_ports:
            svc = info.get("service", "") or info.get("product", "")
            # Some ports are high risk if newly opened
            severity = _port_severity(port, svc)
            changes.append({
                "changeType":  "port_opened",
                "severity":    severity,
                "oldValue":    None,
                "newValue":    str(port),
                "description": f"Port {port}/{info.get('protocol','tcp')} opened — {svc or 'unknown service'}",
            })

    for port, info in prev_ports.items():
        if port not in curr_ports:
            changes.append({
                "changeType":  "port_closed",
                "severity":    "low",
                "oldValue":    str(port),
                "newValue":    None,
                "description": f"Port {port} no longer open",
            })

    # ── SSL expiry changes ────────────────────────────────────────────────────
    curr_ssl = current.get("sslExpiry")
    if curr_ssl:
        try:
            expiry = datetime.fromisoformat(curr_ssl)
            now    = datetime.now(timezone.utc)
            days_left = (expiry - now).days
            if days_left <= 7:
                changes.append({
                    "changeType":  "ssl_expiry_critical",
                    "severity":    "critical",
                    "oldValue":    None,
                    "newValue":    curr_ssl,
                    "description": f"SSL certificate expires in {days_left} days ({expiry.strftime('%Y-%m-%d')})",
                })
            elif days_left <= 30:
                changes.append({
                    "changeType":  "ssl_expiry_warning",
                    "severity":    "high",
                    "oldValue":    None,
                    "newValue":    curr_ssl,
                    "description": f"SSL certificate expires in {days_left} days ({expiry.strftime('%Y-%m-%d')})",
                })
        except (ValueError, TypeError):
            pass

    # ── HTTP status changes ───────────────────────────────────────────────────
    prev_status = previous.get("httpStatus")
    curr_status = current.get("httpStatus")
    if prev_status and curr_status and prev_status != curr_status:
        severity = _http_status_severity(prev_status, curr_status)
        changes.append({
            "changeType":  "http_status_change",
            "severity":    severity,
            "oldValue":    str(prev_status),
            "newValue":    str(curr_status),
            "description": f"HTTP status changed: {prev_status} → {curr_status}",
        })

    # ── New CVEs ──────────────────────────────────────────────────────────────
    prev_cve_ids = {c["id"] for c in previous.get("cves", []) if c.get("id")}
    curr_cves    = current.get("cves", [])
    for cve in curr_cves:
        if cve.get("id") and cve["id"] not in prev_cve_ids:
            sev = cve.get("severity", "medium")
            changes.append({
                "changeType":  "new_cve",
                "severity":    sev if sev in ("critical", "high", "medium", "low") else "medium",
                "oldValue":    None,
                "newValue":    cve["id"],
                "description": f"New CVE detected: {cve['id']} ({cve.get('severity','?').upper()}) "
                               f"affecting {cve.get('product','?')} — {cve.get('description','')[:100]}",
            })

    # ── Tech/version changes ──────────────────────────────────────────────────
    prev_techs = {t["name"]: t.get("version", "") for t in previous.get("techs", [])}
    curr_techs = {t["name"]: t.get("version", "") for t in current.get("techs", [])}

    for name, version in curr_techs.items():
        if name not in prev_techs:
            changes.append({
                "changeType":  "new_tech",
                "severity":    "medium",
                "oldValue":    None,
                "newValue":    f"{name} {version}".strip(),
                "description": f"New technology detected: {name} {version}".strip(),
            })
        elif version and prev_techs[name] and version != prev_techs[name]:
            changes.append({
                "changeType":  "tech_version_change",
                "severity":    "low",
                "oldValue":    f"{name} {prev_techs[name]}",
                "newValue":    f"{name} {version}",
                "description": f"Technology version changed: {name} {prev_techs[name]} → {version}",
            })

    # ── DNS record changes ────────────────────────────────────────────────────
    prev_dns = previous.get("dnsRecords", {})
    curr_dns = current.get("dnsRecords", {})
    for rtype in ["A", "MX", "TXT", "CNAME"]:
        prev_recs = set(prev_dns.get(rtype, []))
        curr_recs = set(curr_dns.get(rtype, []))
        for rec in curr_recs - prev_recs:
            changes.append({
                "changeType":  "dns_record_added",
                "severity":    "medium" if rtype == "A" else "low",
                "oldValue":    None,
                "newValue":    rec,
                "description": f"DNS {rtype} record added: {rec}",
            })
        for rec in prev_recs - curr_recs:
            changes.append({
                "changeType":  "dns_record_removed",
                "severity":    "medium" if rtype == "A" else "low",
                "oldValue":    rec,
                "newValue":    None,
                "description": f"DNS {rtype} record removed: {rec}",
            })

    return changes


def _port_severity(port: int, service: str) -> str:
    """Assign severity to newly opened ports."""
    critical_ports = {23, 3389, 5900, 445, 135, 139}   # Telnet, RDP, VNC, SMB
    high_ports     = {21, 2375, 2376, 9200, 6379, 27017} # FTP, Docker, ES, Redis, Mongo
    if port in critical_ports:
        return "critical"
    if port in high_ports:
        return "high"
    if "telnet" in service.lower() or "vnc" in service.lower():
        return "critical"
    if port < 1024:
        return "medium"
    return "low"


def _http_status_severity(old: int, new: int) -> str:
    """Severity of HTTP status code change."""
    if old in range(200, 300) and new in (500, 502, 503):
        return "high"    # Was working, now broken
    if old in range(200, 300) and new == 403:
        return "medium"  # Access changed
    if old in range(200, 300) and new in (301, 302):
        return "low"     # Redirect added
    return "low"
