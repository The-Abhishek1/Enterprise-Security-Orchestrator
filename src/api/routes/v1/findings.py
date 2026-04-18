"""
findings.py — Enterprise findings API.

GET  /findings                  list + filter (severity, source, type, port, search)
GET  /findings/stats            severity counts, top ports, top services  
GET  /findings/export/csv       download all as CSV
GET  /findings/export/json      download all as JSON
GET  /findings/scan/{pid}       all findings for one scan
GET  /findings/{id}             single finding
PATCH /findings/{id}            update (severity override, notes)
POST /findings/{id}/fp          mark false positive
POST /findings/{id}/verified    mark verified true positive
POST /findings/{id}/comment     add analyst note
GET  /findings/{id}/comments    list comments
POST /findings/{id}/ai          AI explain/remediate/poc
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import csv, io, json

from src.api.dependencies import get_current_user
from src.services.user_service import user_service
from src.services.ai_chat import ai_chat_service
from src.core.database import db_manager
from src.utils.logging import logger

router = APIRouter(prefix="/findings", tags=["findings"])


class CommentRequest(BaseModel):
    comment: str

class UpdateFindingRequest(BaseModel):
    severity_override: Optional[str] = None
    notes:             Optional[str] = None
    false_positive:    Optional[bool] = None
    validated:         Optional[bool] = None

class AIFindingRequest(BaseModel):
    chat_type: str = "explain"   # explain | remediate | poc | general
    question:  Optional[str] = None


# ── List ─────────────────────────────────────────────────────────────────────
@router.get("")
async def list_findings(
    severity:       Optional[str]  = None,
    source:         Optional[str]  = None,
    finding_type:   Optional[str]  = None,
    port:           Optional[int]  = None,
    search:         Optional[str]  = None,
    false_positive: Optional[bool] = None,
    limit:  int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    result = await user_service.search_findings(
        user_id=current_user["sub"], severity=severity, source=source,
        finding_type=finding_type, port=port, search=search,
        limit=limit, offset=offset,
    )
    findings = result["findings"]
    if false_positive is not None:
        findings = [f for f in findings if bool(f.get("false_positive")) == false_positive]
    return {**result, "findings": findings}


# ── Stats ─────────────────────────────────────────────────────────────────────
@router.get("/stats")
async def stats(current_user: dict = Depends(get_current_user)):
    return await user_service.get_finding_stats(current_user["sub"])


# ── Export CSV ────────────────────────────────────────────────────────────────
@router.get("/export/csv")
async def export_csv(
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    result = await user_service.search_findings(
        user_id=current_user["sub"], severity=severity, limit=5000, offset=0
    )
    out = io.StringIO()
    cols = ["finding_id","process_id","type","severity","source","port","protocol",
            "service","version","state","finding","cve_ids","risk_score",
            "validated","false_positive","mitigation","target","created_at"]
    w = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for f in result["findings"]:
        row = {c: f.get(c,"") for c in cols}
        row["severity"]  = f.get("validated_severity", f.get("severity",""))
        row["cve_ids"]   = ",".join(f.get("cve_ids",[]) or [])
        row["finding"]   = str(f.get("finding",""))[:300]
        row["mitigation"]= str(f.get("mitigation",""))[:200]
        row["created_at"]= str(f.get("created_at",""))
        w.writerow(row)
    out.seek(0)
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M')
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings_{ts}.csv"})


# ── Export JSON ───────────────────────────────────────────────────────────────
@router.get("/export/json")
async def export_json(current_user: dict = Depends(get_current_user)):
    result = await user_service.search_findings(
        user_id=current_user["sub"], limit=5000, offset=0
    )
    content = json.dumps(result["findings"], default=str, indent=2)
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M')
    return StreamingResponse(iter([content]), media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=findings_{ts}.json"})


# ── By scan ───────────────────────────────────────────────────────────────────
@router.get("/scan/{process_id}")
async def by_scan(process_id: str, current_user: dict = Depends(get_current_user)):
    findings = await user_service.get_findings(process_id, current_user["sub"])
    return {"findings": findings, "total": len(findings), "process_id": process_id}


# ── Single ────────────────────────────────────────────────────────────────────
@router.get("/{finding_id}")
async def get_finding(finding_id: str, current_user: dict = Depends(get_current_user)):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        row = await c.fetchrow(
            """SELECT f.*, s.target FROM findings f
               LEFT JOIN scan_history s ON f.process_id=s.process_id
               WHERE f.finding_id=$1 AND f.user_id=$2""",
            finding_id, current_user["sub"]
        )
    if not row: raise HTTPException(404, "Finding not found")
    return dict(row)


# ── Update ────────────────────────────────────────────────────────────────────
@router.patch("/{finding_id}")
async def update_finding(
    finding_id: str,
    req: UpdateFindingRequest,
    current_user: dict = Depends(get_current_user),
):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    updates = []
    params  = []
    idx     = 1
    if req.severity_override is not None:
        updates.append(f"severity=${idx}"); params.append(req.severity_override); idx+=1
    if req.notes is not None:
        updates.append(f"impact=${idx}"); params.append(req.notes); idx+=1
    if req.false_positive is not None:
        updates.append(f"false_positive=${idx}"); params.append(req.false_positive); idx+=1
    if req.validated is not None:
        updates.append(f"validated=${idx}"); params.append(req.validated); idx+=1
    if not updates:
        return {"status": "no_changes"}
    params += [finding_id, current_user["sub"]]
    async with pool.acquire() as c:
        res = await c.execute(
            f"UPDATE findings SET {', '.join(updates)} WHERE finding_id=${idx} AND user_id=${idx+1}",
            *params
        )
    if "UPDATE 0" in res: raise HTTPException(404, "Finding not found")
    return {"status": "updated", "finding_id": finding_id}


# ── False positive ────────────────────────────────────────────────────────────
@router.post("/{finding_id}/fp")
async def mark_fp(finding_id: str, current_user: dict = Depends(get_current_user)):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        res = await c.execute(
            "UPDATE findings SET false_positive=TRUE,validated=TRUE WHERE finding_id=$1 AND user_id=$2",
            finding_id, current_user["sub"]
        )
    if "UPDATE 0" in res: raise HTTPException(404, "Finding not found")
    return {"status": "marked_false_positive", "finding_id": finding_id}


# ── Verified ──────────────────────────────────────────────────────────────────
@router.post("/{finding_id}/verified")
async def mark_verified(finding_id: str, current_user: dict = Depends(get_current_user)):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        res = await c.execute(
            "UPDATE findings SET validated=TRUE,false_positive=FALSE WHERE finding_id=$1 AND user_id=$2",
            finding_id, current_user["sub"]
        )
    if "UPDATE 0" in res: raise HTTPException(404, "Finding not found")
    return {"status": "marked_verified", "finding_id": finding_id}


# ── Comment ───────────────────────────────────────────────────────────────────
@router.post("/{finding_id}/comment")
async def add_comment(
    finding_id: str,
    req: CommentRequest,
    current_user: dict = Depends(get_current_user),
):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        ok = await c.fetchval("SELECT 1 FROM findings WHERE finding_id=$1 AND user_id=$2",
                              finding_id, current_user["sub"])
        if not ok: raise HTTPException(404, "Finding not found")
        await c.execute(
            "INSERT INTO finding_comments(finding_id,user_id,comment) VALUES($1,$2,$3)",
            finding_id, current_user["sub"], req.comment
        )
    return {"status": "added", "finding_id": finding_id}


@router.get("/{finding_id}/comments")
async def list_comments(finding_id: str, current_user: dict = Depends(get_current_user)):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        rows = await c.fetch(
            "SELECT id,comment,created_at FROM finding_comments WHERE finding_id=$1 AND user_id=$2 ORDER BY created_at",
            finding_id, current_user["sub"]
        )
    return {"comments": [dict(r) for r in rows]}


# ── AI ────────────────────────────────────────────────────────────────────────
@router.post("/{finding_id}/ai")
async def ai_on_finding(
    finding_id: str,
    req: AIFindingRequest,
    current_user: dict = Depends(get_current_user),
):
    pool = db_manager.pg_pool
    if not pool: raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        row = await c.fetchrow(
            """SELECT f.*,s.target FROM findings f
               LEFT JOIN scan_history s ON f.process_id=s.process_id
               WHERE f.finding_id=$1 AND f.user_id=$2""",
            finding_id, current_user["sub"]
        )
    if not row: raise HTTPException(404, "Finding not found")
    return await ai_chat_service.ask(
        chat_type=req.chat_type, finding=dict(row),
        user_id=current_user["sub"], question=req.question,
        target=row.get("target",""),
    )
