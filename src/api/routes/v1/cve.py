"""
cve.py — CVE database endpoints.

GET  /cves                list/search CVEs
GET  /cves/stats          severity counts, recent additions
GET  /cves/{cve_id}       single CVE detail
POST /cves/import         bulk import from NVD JSON feed
GET  /cves/scan/{pid}     CVEs matched in a specific scan
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
import json

from src.api.dependencies import get_current_user, require_role
from src.core.database import db_manager
from src.utils.logging import logger

router = APIRouter(prefix="/cves", tags=["cve"])


class CVEImportEntry(BaseModel):
    cve_id:       str
    description:  Optional[str]  = None
    cvss_score:   Optional[float] = 0.0
    severity:     Optional[str]  = "unknown"
    published_at: Optional[str]  = None
    references:   Optional[List[str]] = []
    cpe_list:     Optional[List[str]] = []


class CVEImportRequest(BaseModel):
    cves: List[CVEImportEntry]


# ── List / search ─────────────────────────────────────────────────────────────
@router.get("")
async def list_cves(
    severity:  Optional[str] = None,
    search:    Optional[str] = None,
    min_cvss:  float = Query(0.0, ge=0, le=10),
    has_exploit: Optional[bool] = None,
    limit:  int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")

    conditions = ["cvss_score >= $1"]
    params: list = [min_cvss]
    idx = 2

    if severity:
        conditions.append(f"severity=${idx}"); params.append(severity); idx+=1
    if search:
        safe = search.replace("%","").replace("_","")[:100]
        conditions.append(f"(cve_id ILIKE ${idx} OR description ILIKE ${idx})")
        params.append(f"%{safe}%"); idx+=1
    if has_exploit is not None:
        conditions.append(f"has_exploit=${idx}"); params.append(has_exploit); idx+=1

    where = " AND ".join(conditions)
    async with pool.acquire() as c:
        total = await c.fetchval(f"SELECT COUNT(*) FROM cves WHERE {where}", *params)
        rows  = await c.fetch(
            f"""SELECT cve_id,description,cvss_score,severity,published_at,
                       has_exploit,scan_count,last_seen_at
                FROM cves WHERE {where}
                ORDER BY cvss_score DESC, published_at DESC
                LIMIT ${idx} OFFSET ${idx+1}""",
            *(params + [limit, offset])
        )
    return {
        "cves":   [dict(r) for r in rows],
        "total":  total,
        "limit":  limit,
        "offset": offset,
    }


# ── Stats ─────────────────────────────────────────────────────────────────────
@router.get("/stats")
async def cve_stats(current_user: dict = Depends(get_current_user)):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        total      = await c.fetchval("SELECT COUNT(*) FROM cves")
        by_sev     = await c.fetch("SELECT severity,COUNT(*) as count FROM cves GROUP BY severity ORDER BY count DESC")
        with_exploit = await c.fetchval("SELECT COUNT(*) FROM cves WHERE has_exploit=TRUE")
        recent     = await c.fetch("SELECT cve_id,cvss_score,severity FROM cves ORDER BY published_at DESC LIMIT 10")
        top_scored = await c.fetch("SELECT cve_id,cvss_score,severity,description FROM cves ORDER BY cvss_score DESC LIMIT 10")
    return {
        "total":          total,
        "by_severity":    {r["severity"]: r["count"] for r in by_sev},
        "with_exploit":   with_exploit,
        "recent":         [dict(r) for r in recent],
        "top_critical":   [dict(r) for r in top_scored],
    }


# ── Single CVE ────────────────────────────────────────────────────────────────
@router.get("/{cve_id}")
async def get_cve(cve_id: str, current_user: dict = Depends(get_current_user)):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        row = await c.fetchrow("SELECT * FROM cves WHERE cve_id=$1", cve_id.upper())
    if not row: raise HTTPException(404, f"CVE {cve_id} not in local database")
    return dict(row)


# ── CVEs from a scan ──────────────────────────────────────────────────────────
@router.get("/scan/{process_id}")
async def cves_for_scan(process_id: str, current_user: dict = Depends(get_current_user)):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        # First verify user owns this scan
        owned = await c.fetchval(
            "SELECT 1 FROM scan_history WHERE process_id=$1 AND user_id=$2",
            process_id, current_user["sub"]
        )
        if not owned and current_user.get("role") != "admin":
            raise HTTPException(403, "Access denied")
        rows = await c.fetch(
            """SELECT m.cve_id, c.cvss_score, c.severity, c.description,
                      c.has_exploit, m.matched_at
               FROM scan_cve_matches m
               LEFT JOIN cves c ON m.cve_id=c.cve_id
               WHERE m.process_id=$1 ORDER BY c.cvss_score DESC NULLS LAST""",
            process_id
        )
    return {"cves": [dict(r) for r in rows], "process_id": process_id}


# ── Bulk import (admin only) ──────────────────────────────────────────────────
@router.post("/import")
async def import_cves(
    req: CVEImportRequest,
    current_user: dict = Depends(require_role("admin")),
):
    """Bulk import CVEs from NVD feed or manual entry."""
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")

    imported = 0
    errors   = 0
    async with pool.acquire() as c:
        for entry in req.cves:
            try:
                await c.execute(
                    """INSERT INTO cves
                       (cve_id,description,cvss_score,severity,published_at,references,cpe_list)
                       VALUES($1,$2,$3,$4,$5::timestamp,$6,$7)
                       ON CONFLICT (cve_id) DO UPDATE SET
                         description=EXCLUDED.description,
                         cvss_score=EXCLUDED.cvss_score,
                         severity=EXCLUDED.severity,
                         updated_at=NOW()""",
                    entry.cve_id.upper(), entry.description, entry.cvss_score,
                    entry.severity or _cvss_to_severity(entry.cvss_score or 0),
                    entry.published_at, entry.references or [], entry.cpe_list or []
                )
                imported += 1
            except Exception as e:
                logger.warning(f"CVE import error {entry.cve_id}: {e}")
                errors += 1

    return {"imported": imported, "errors": errors, "total": len(req.cves)}


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "none"
