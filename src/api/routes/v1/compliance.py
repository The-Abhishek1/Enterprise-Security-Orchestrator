# src/api/routes/v1/compliance.py
"""
Compliance Automation API — ESO side.

POST /compliance/assess          → run gap analysis for a framework
GET  /compliance/frameworks      → list supported frameworks
GET  /compliance/report/{fw}     → download PDF compliance report for latest scan
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import io

from src.api.dependencies import get_current_user
from src.core.database import db_manager
from src.utils.logging import logger
from src.workers.compliance_mapper import (
    FRAMEWORKS, map_findings_to_controls, gap_analysis_to_dict
)

router = APIRouter(prefix="/compliance", tags=["compliance"])


class AssessRequest(BaseModel):
    framework:      str              # soc2 | iso27001 | pcidss | nist | hipaa
    scan_ids:       List[str] = []   # specific process_ids to include (empty = all user scans)
    cloud_account_ids: List[str] = []  # XCloak cloud account IDs (empty = skip cloud)
    max_findings:   int = 500


@router.get("/frameworks")
async def list_frameworks():
    return {
        "frameworks": [
            {"id": k, "name": v[0], "controls": len(v[1])}
            for k, v in FRAMEWORKS.items()
        ]
    }


@router.post("/assess")
async def run_assessment(
    req: AssessRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Run compliance gap analysis.
    Pulls scan findings from ESO DB + cloud findings passed in request,
    maps them to framework controls, returns full gap analysis.
    """
    fw = req.framework.lower()
    if fw not in FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework '{fw}'. Supported: {', '.join(FRAMEWORKS)}")

    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")

    user_id = current_user["sub"]

    # ── Load scan findings ────────────────────────────────────────────────────
    async with pool.acquire() as c:
        if req.scan_ids:
            placeholders = ", ".join(f"${i+2}" for i in range(len(req.scan_ids)))
            rows = await c.fetch(
                f"""SELECT f.finding_id, f.type, f.severity, f.source,
                           f.finding, f.service, f.template, f.port,
                           f.false_positive, f.validated
                    FROM findings f
                    WHERE f.user_id = $1 AND f.process_id IN ({placeholders})
                    AND f.false_positive = FALSE
                    ORDER BY CASE f.severity
                      WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                      WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5
                    END
                    LIMIT ${ len(req.scan_ids) + 2 }""",
                user_id, *req.scan_ids, req.max_findings,
            )
        else:
            rows = await c.fetch(
                """SELECT f.finding_id, f.type, f.severity, f.source,
                          f.finding, f.service, f.template, f.port,
                          f.false_positive, f.validated
                   FROM findings f
                   WHERE f.user_id = $1 AND f.false_positive = FALSE
                   ORDER BY CASE f.severity
                     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                     WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5
                   END
                   LIMIT $2""",
                user_id, req.max_findings,
            )

    findings = [dict(r) for r in rows]
    logger.info(f"[compliance] {fw}: {len(findings)} findings for user {user_id}")

    # ── Cloud findings are passed in from XCloak via request body ─────────────
    # XCloak fetches them from Prisma and sends in the request (avoids ESO needing Prisma access)
    cloud_findings: List[Dict[str, Any]] = []

    # Run gap analysis
    gap = map_findings_to_controls(findings, cloud_findings, fw)
    result = gap_analysis_to_dict(gap)
    result["scan_count"]   = len(req.scan_ids) if req.scan_ids else "all"
    result["finding_count"] = len(findings)

    return result


@router.post("/assess-with-cloud")
async def run_assessment_with_cloud(
    req_body: Dict[str, Any],
    current_user: dict = Depends(get_current_user),
):
    """
    Same as /assess but accepts cloud_findings inline.
    XCloak calls this with cloud findings from Prisma already included.
    """
    fw = req_body.get("framework", "iso27001").lower()
    if fw not in FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework '{fw}'")

    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")

    user_id = current_user["sub"]
    max_findings = req_body.get("max_findings", 500)

    # Load scan findings from ESO DB
    async with pool.acquire() as c:
        rows = await c.fetch(
            """SELECT f.finding_id, f.type, f.severity, f.source,
                      f.finding, f.service, f.template, f.port,
                      f.false_positive, f.validated
               FROM findings f
               WHERE f.user_id = $1 AND f.false_positive = FALSE
               ORDER BY CASE f.severity
                 WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                 WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5
               END
               LIMIT $2""",
            user_id, max_findings,
        )

    findings = [dict(r) for r in rows]
    cloud_findings = req_body.get("cloud_findings", [])

    gap = map_findings_to_controls(findings, cloud_findings, fw)
    result = gap_analysis_to_dict(gap)
    result["finding_count"] = len(findings)
    result["cloud_finding_count"] = len(cloud_findings)

    logger.info(
        f"[compliance] {fw}: {len(findings)} scan + {len(cloud_findings)} cloud findings → "
        f"pass={gap.passing} fail={gap.failing} n/a={gap.not_assessed}"
    )
    return result


@router.get("/report/{framework}")
async def download_compliance_report(
    framework: str,
    scan_id: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    """
    Download a compliance-mapped PDF for the user's latest (or specified) scan.
    Delegates to the existing compliance_report service.
    """
    from src.services.compliance_report import compliance_generator, FRAMEWORKS as PDF_FRAMEWORKS

    fw = framework.lower()
    if fw not in PDF_FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework '{fw}'. Supported: {', '.join(PDF_FRAMEWORKS)}")

    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")

    user_id = current_user["sub"]

    async with pool.acquire() as c:
        if scan_id:
            scan_row = await c.fetchrow(
                "SELECT * FROM scan_history WHERE process_id=$1 AND user_id=$2",
                scan_id, user_id,
            )
        else:
            scan_row = await c.fetchrow(
                """SELECT * FROM scan_history WHERE user_id=$1 AND status IN ('completed','done')
                   ORDER BY completed_at DESC NULLS LAST LIMIT 1""",
                user_id,
            )

        if not scan_row:
            raise HTTPException(404, "No completed scan found")

        finding_rows = await c.fetch(
            """SELECT type, severity, port, service, version, finding, impact
               FROM findings WHERE process_id=$1 ORDER BY
               CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
               WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END""",
            scan_row["process_id"],
        )

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings = []
    for r in finding_rows:
        f = dict(r)
        sev = f.get("severity", "info")
        f["validated_severity"] = sev
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        findings.append(f)

    scan_data = dict(scan_row)
    scan_data["findings"] = findings
    scan_data["risk_summary"] = {
        "overall_risk":   scan_data.get("risk_level", "none"),
        "overall_score":  scan_data.get("risk_score", 0.0),
        "critical_count": sev_counts["critical"],
        "high_count":     sev_counts["high"],
        "medium_count":   sev_counts["medium"],
        "low_count":      sev_counts["low"],
    }
    tools = scan_data.get("tools_used") or []
    if isinstance(tools, str):
        try: tools = json.loads(tools)
        except: tools = []
    scan_data["tools_used"] = tools
    scan_data["duration"] = scan_data.get("duration_seconds", 0)

    pdf_bytes = compliance_generator.generate(scan_data, framework=fw)
    if not pdf_bytes:
        raise HTTPException(500, "PDF generation failed — reportlab not installed")

    fw_label = PDF_FRAMEWORKS[fw][0].replace(" ", "-").replace(":", "").replace(".", "")
    target   = str(scan_data.get("target", "scan")).replace("/", "-").replace(".", "_")[:30]
    filename = f"xcloak-{fw_label}-{target}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
