"""
metrics.py — Platform metrics and dashboard stats.

GET /metrics/platform       overall platform stats (admin)
GET /metrics/user           per-user scan stats
GET /metrics/tools          tool execution stats
GET /metrics/prometheus     Prometheus scrape endpoint
"""
from fastapi import APIRouter, Depends, Response
from typing import Optional
from datetime import datetime, timedelta

from src.api.dependencies import get_current_user, require_role
from src.core.database import db_manager
from src.utils.logging import logger

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/user")
async def user_metrics(
    days: int = 30,
    current_user: dict = Depends(get_current_user),
):
    """Per-user scan + finding metrics for dashboard."""
    uid  = current_user["sub"]
    pool = db_manager.pg_pool
    if not pool: return {"error": "Database unavailable"}

    since = datetime.utcnow() - timedelta(days=days)
    async with pool.acquire() as c:
        # Scan trend by day
        scan_trend = await c.fetch(
            """SELECT DATE(created_at) as day, COUNT(*) as scans,
                      SUM(findings_count) as findings,
                      AVG(risk_score) as avg_risk
               FROM scan_history WHERE user_id=$1 AND created_at>=$2
               GROUP BY DATE(created_at) ORDER BY day""",
            uid, since
        )
        # Totals
        totals = await c.fetchrow(
            """SELECT COUNT(*) as total_scans,
                      SUM(findings_count) as total_findings,
                      AVG(risk_score) as avg_risk_score,
                      MAX(risk_score) as max_risk_score,
                      SUM(duration_seconds) as total_scan_time
               FROM scan_history WHERE user_id=$1""", uid
        )
        # Findings by severity
        by_sev = await c.fetch(
            "SELECT severity, COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY severity",
            uid
        )
        # Most scanned targets
        top_targets = await c.fetch(
            """SELECT target, COUNT(*) as scans, MAX(risk_score) as max_risk
               FROM scan_history WHERE user_id=$1 AND target IS NOT NULL
               GROUP BY target ORDER BY scans DESC LIMIT 10""",
            uid
        )
        # Tools used
        tools_used = await c.fetch(
            """SELECT UNNEST(tools_used) as tool, COUNT(*) as count
               FROM scan_history WHERE user_id=$1 AND tools_used IS NOT NULL
               GROUP BY tool ORDER BY count DESC""",
            uid
        )
        # Risk over time
        risk_trend = await c.fetch(
            """SELECT DATE(created_at) as day,
                      SUM(CASE WHEN risk_level='critical' THEN 1 ELSE 0 END) as critical,
                      SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) as high,
                      SUM(CASE WHEN risk_level='medium' THEN 1 ELSE 0 END) as medium
               FROM scan_history WHERE user_id=$1 AND created_at>=$2
               GROUP BY DATE(created_at) ORDER BY day""",
            uid, since
        )

    return {
        "period_days":   days,
        "scan_trend":    [dict(r) for r in scan_trend],
        "risk_trend":    [dict(r) for r in risk_trend],
        "totals":        dict(totals) if totals else {},
        "by_severity":   {r["severity"]: r["count"] for r in by_sev},
        "top_targets":   [dict(r) for r in top_targets],
        "tools_used":    [dict(r) for r in tools_used],
    }


@router.get("/platform")
async def platform_metrics(current_user: dict = Depends(require_role("admin"))):
    """Admin: full platform metrics."""
    pool = db_manager.pg_pool
    if not pool: return {"error": "Database unavailable"}

    async with pool.acquire() as c:
        user_count     = await c.fetchval("SELECT COUNT(*) FROM users WHERE is_active=TRUE")
        scan_count     = await c.fetchval("SELECT COUNT(*) FROM scan_history")
        finding_count  = await c.fetchval("SELECT COUNT(*) FROM findings")
        cve_count      = await c.fetchval("SELECT COUNT(*) FROM cves") if await _table_exists(c, "cves") else 0
        scans_today    = await c.fetchval("SELECT COUNT(*) FROM scan_history WHERE created_at::date=NOW()::date")
        by_tier        = await c.fetch("SELECT tier, COUNT(*) as count FROM users GROUP BY tier")
        recent_scans   = await c.fetch(
            """SELECT process_id, user_id, target, status, risk_level, findings_count, created_at
               FROM scan_history ORDER BY created_at DESC LIMIT 20"""
        )
        top_risky      = await c.fetch(
            """SELECT target, MAX(risk_score) as max_risk, COUNT(*) as scan_count
               FROM scan_history WHERE target IS NOT NULL
               GROUP BY target ORDER BY max_risk DESC LIMIT 10"""
        )

    return {
        "users":         {"total": user_count, "by_tier": {r["tier"]: r["count"] for r in by_tier}},
        "scans":         {"total": scan_count, "today": scans_today},
        "findings":      {"total": finding_count},
        "cves":          {"total": cve_count},
        "recent_scans":  [dict(r) for r in recent_scans],
        "riskiest_targets": [dict(r) for r in top_risky],
    }


async def _table_exists(conn, table: str) -> bool:
    try:
        res = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name=$1)", table
        )
        return res
    except Exception:
        return False


@router.get("/prometheus")
async def prometheus_metrics(current_user: dict = Depends(get_current_user)):
    """Prometheus text format metrics for scraping."""
    pool = db_manager.pg_pool
    lines = ["# ESO Prometheus Metrics"]

    if pool:
        async with pool.acquire() as c:
            scan_total = await c.fetchval("SELECT COUNT(*) FROM scan_history") or 0
            find_total = await c.fetchval("SELECT COUNT(*) FROM findings") or 0
            user_total = await c.fetchval("SELECT COUNT(*) FROM users") or 0
            scans_today= await c.fetchval("SELECT COUNT(*) FROM scan_history WHERE created_at::date=NOW()::date") or 0

        lines += [
            f"eso_scans_total {scan_total}",
            f"eso_findings_total {find_total}",
            f"eso_users_total {user_total}",
            f"eso_scans_today {scans_today}",
        ]

    return Response(content="\n".join(lines) + "\n", media_type="text/plain")
