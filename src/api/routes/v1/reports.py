"""
reports.py — Report generation endpoints.

GET  /reports/pdf/{process_id}           → download standard pentest PDF
GET  /reports/compliance/{process_id}    → download compliance-mapped PDF (enterprise)

Uses scan_history table (the actual table name in schema.py).
Findings fetched from findings table separately.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
import io, json

from src.api.dependencies import get_current_user
from src.services.pdf_report import pdf_generator
from src.services.compliance_report import compliance_generator, FRAMEWORKS
from src.utils.logging import logger

router = APIRouter(prefix="/reports", tags=["reports"])


def _require_tier(current_user: dict, minimum: str):
    RANK = {"free": 0, "pro": 1, "enterprise": 2, "admin": 3}
    user_tier = current_user.get("tier", "free")
    if current_user.get("role") == "admin":
        return
    if RANK.get(user_tier, 0) < RANK.get(minimum, 0):
        raise HTTPException(403, f"{minimum.capitalize()} tier required for this feature")


async def _load_scan(process_id: str, user_id: str) -> dict:
    """Load scan from scan_history + findings tables."""
    from src.core.database import db_manager
    if not db_manager.pg_pool:
        raise HTTPException(503, "Database unavailable")

    async with db_manager.pg_pool.acquire() as c:
        # scan_history is the actual table name
        row = await c.fetchrow(
            """SELECT process_id, target, goal, status,
                      findings_count, risk_score, risk_level,
                      tools_used, llm_calls, duration_seconds,
                      report, created_at, user_id,
                      total_tasks, dynamic_tasks
               FROM scan_history
               WHERE process_id = $1 AND user_id = $2""",
            process_id, user_id,
        )
        if not row:
            raise HTTPException(404, f"Scan {process_id} not found")

        data = dict(row)

        # Build risk_summary from flat columns
        data["risk_summary"] = {
            "overall_risk":    data.get("risk_level", "none"),
            "overall_score":   data.get("risk_score", 0.0),
            "critical_count":  0,
            "high_count":      0,
            "medium_count":    0,
            "low_count":       0,
            "info_count":      0,
        }

        # Fetch findings from findings table
        finding_rows = await c.fetch(
            """SELECT type, severity, port, service, version,
                      finding, impact, raw_data, target,
                      validated, false_positive
               FROM findings
               WHERE process_id = $1
               ORDER BY
                 CASE severity
                   WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                   WHEN 'medium'   THEN 3 WHEN 'low'   THEN 4
                   ELSE 5
                 END""",
            process_id,
        )
        findings = []
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in finding_rows:
            f = dict(r)
            if isinstance(f.get("raw_data"), str):
                try:
                    f["raw_data"] = json.loads(f["raw_data"])
                except Exception:
                    pass
            sev = f.get("severity", "info")
            f["validated_severity"] = sev
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            findings.append(f)

        data["findings"] = findings
        data["risk_summary"].update({
            "critical_count": sev_counts["critical"],
            "high_count":     sev_counts["high"],
            "medium_count":   sev_counts["medium"],
            "low_count":      sev_counts["low"],
            "info_count":     sev_counts.get("info", 0),
        })

        # tools_used is TEXT[] in postgres — comes back as a list already
        if isinstance(data.get("tools_used"), list):
            pass
        elif isinstance(data.get("tools_used"), str):
            try:
                data["tools_used"] = json.loads(data["tools_used"])
            except Exception:
                data["tools_used"] = []

    return data


@router.get("/pdf/{process_id}")
async def download_pdf(
    process_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Download standard pentest PDF. Requires pro tier."""
    _require_tier(current_user, "pro")
    scan_data = await _load_scan(process_id, current_user["sub"])

    if scan_data.get("status") not in ("completed", "done"):
        raise HTTPException(400, "Scan must be completed before generating PDF")

    pdf_bytes = pdf_generator.generate(scan_data)
    if not pdf_bytes:
        raise HTTPException(500, "PDF generation failed — reportlab not installed on server")

    target = str(scan_data.get("target", "scan")).replace("/", "-").replace(".", "_")
    filename = f"xcloak-report-{target}-{process_id[:8]}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/compliance/{process_id}")
@router.post("/compliance/{process_id}")
async def download_compliance_pdf(
    process_id: str,
    framework: str = Query(default="iso27001"),
    current_user: dict = Depends(get_current_user),
):
    """Download compliance-mapped PDF. Requires enterprise tier."""
    _require_tier(current_user, "enterprise")

    fw = framework.lower()
    if fw not in FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework '{fw}'. Use: {', '.join(FRAMEWORKS.keys())}")

    scan_data = await _load_scan(process_id, current_user["sub"])
    if scan_data.get("status") not in ("completed", "done"):
        raise HTTPException(400, "Scan must be completed before generating report")

    pdf_bytes = compliance_generator.generate(scan_data, framework=fw)
    if not pdf_bytes:
        raise HTTPException(500, "PDF generation failed — reportlab not installed")

    fw_name = FRAMEWORKS[fw][0].replace(" ", "-").replace(":", "").replace(".", "")
    target = str(scan_data.get("target", "scan")).replace("/", "-").replace(".", "_")
    filename = f"xcloak-{fw_name}-{target}-{process_id[:8]}.pdf"
    logger.info(f"📋 Compliance PDF ({fw}) downloaded by {current_user['sub']}")
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/frameworks")
async def list_frameworks():
    return {"frameworks": [{"id": k, "name": v[0]} for k, v in FRAMEWORKS.items()]}
