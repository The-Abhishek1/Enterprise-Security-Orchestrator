# src/api/routes/v1/attack_surface.py

"""Attack Surface Dashboard — aggregated security posture."""

from fastapi import APIRouter, Depends
from src.api.dependencies import get_current_user
from src.core.database import db_manager

router = APIRouter(prefix="/attack-surface", tags=["attack-surface"])


@router.get("/")
async def get_attack_surface(current_user: dict = Depends(get_current_user)):
    """Get full attack surface overview."""
    uid = current_user["sub"]
    pool = db_manager.pg_pool
    if not pool:
        return {"error": "Database not available"}

    async with pool.acquire() as c:
        # Unique targets scanned
        targets = await c.fetch(
            "SELECT DISTINCT target FROM scan_history WHERE user_id=$1 AND target IS NOT NULL", uid
        )
        # Total findings by severity
        sev = await c.fetch(
            "SELECT severity, COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY severity", uid
        )
        # Open ports
        ports = await c.fetch(
            """SELECT port, service, protocol, COUNT(*) as count
               FROM findings WHERE user_id=$1 AND port IS NOT NULL AND type='open_port'
               GROUP BY port, service, protocol ORDER BY count DESC LIMIT 20""", uid
        )
        # Top vulnerabilities
        vulns = await c.fetch(
            """SELECT type, severity, source, finding, COUNT(*) as count
               FROM findings WHERE user_id=$1 AND severity IN ('critical','high','medium')
               GROUP BY type, severity, source, finding ORDER BY
               CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 END, count DESC
               LIMIT 15""", uid
        )
        # Scan trend (last 30 scans)
        trends = await c.fetch(
            """SELECT process_id, target, status, findings_count, risk_level, risk_score,
                      created_at::date as scan_date, duration_seconds
               FROM scan_history WHERE user_id=$1
               ORDER BY created_at DESC LIMIT 30""", uid
        )
        # Total counts
        total_findings = await c.fetchval("SELECT COUNT(*) FROM findings WHERE user_id=$1", uid)
        total_scans = await c.fetchval("SELECT COUNT(*) FROM scan_history WHERE user_id=$1", uid)
        # Risk distribution per target
        risk_by_target = await c.fetch(
            """SELECT target, risk_level, risk_score, findings_count, MAX(created_at) as last_scan
               FROM scan_history WHERE user_id=$1 AND target IS NOT NULL
               GROUP BY target, risk_level, risk_score, findings_count
               ORDER BY risk_score DESC""", uid
        )

    return {
        "summary": {
            "total_assets": len(targets),
            "total_scans": total_scans,
            "total_findings": total_findings,
            "severity_breakdown": {r["severity"]: r["count"] for r in sev},
        },
        "open_ports": [dict(r) for r in ports],
        "top_vulnerabilities": [dict(r) for r in vulns],
        "scan_trends": [dict(r) for r in trends],
        "risk_by_target": [dict(r) for r in risk_by_target],
        "assets": [r["target"] for r in targets],
    }
