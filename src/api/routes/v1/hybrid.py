"""
Hybrid execution routes — correctly mapped to actual scheduler/response models.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import Response
from typing import Optional
from datetime import datetime
import uuid

from src.api.models.request import HybridExecutionRequest
from src.api.models.response import (
    HybridExecutionResponse,
    ExecutionStatusResponse,
    ExecutionListResponse,
    ExecutionStatus,
)
from src.api.dependencies import get_current_user, get_tenant_id, get_request_id
from src.utils.logging import logger
from src.services.audit import audit_logger
from src.services.target_validator import target_validator

router = APIRouter(prefix="/hybrid", tags=["hybrid-execution"])

# Maps request str priority → int priority for Execution model
PRIORITY_MAP = {"low": 0, "medium": 5, "high": 10, "critical": 20}


def get_scheduler(request: Request):
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(503, "Scheduler not initialized")
    return scheduler


# ─────────────────────────────────────────────────────────────
# POST /hybrid/execute
# ─────────────────────────────────────────────────────────────
@router.post("/execute", response_model=HybridExecutionResponse, status_code=202)
async def execute_goal(
    request: Request,
    execution_request: HybridExecutionRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
    request_id: str = Depends(get_request_id),
):
    user_id = current_user.get("sub", "unknown")
    tier    = current_user.get("tier", "free")
    role    = current_user.get("role", "user")

    # ── 1. Target validation ──────────────────────────────
    if execution_request.target:
        validation = target_validator.validate(execution_request.target)
        if not validation["allowed"]:
            await audit_logger.log(
                action="scan_blocked", user_id=user_id, tenant_id=tenant_id,
                resource_type="scan",
                details={"target": execution_request.target, "reason": validation["reason"]},
                status="denied",
            )
            raise HTTPException(403, f"Target not allowed: {validation['reason']}")

    # ── 2. Quota check (skip for admin) ───────────────────
    scheduler = get_scheduler(request)
    qm = scheduler.quota_manager

    if role != "admin":
        daily = await qm.check_daily_quota(user_id, tier)
        if not daily["allowed"]:
            raise HTTPException(429, {
                "error": "Daily scan limit reached",
                "reason": daily["reason"],
                "used": daily["used"],
                "limit": daily["limit"],
                "upgrade_url": "/settings",
            })

        concurrent = await qm.check_concurrent(user_id, tier)
        if not concurrent["allowed"]:
            raise HTTPException(429, {
                "error": "Too many concurrent scans",
                "reason": concurrent["reason"],
                "active": concurrent["active"],
                "limit": concurrent["limit"],
            })

    # ── 3. Convert priority str → int ────────────────────
    raw_priority = execution_request.priority
    if hasattr(raw_priority, "value"):
        raw_priority = raw_priority.value
    int_priority = PRIORITY_MAP.get(str(raw_priority).lower(), 5)

    # ── 4. Pre-generate process_id ────────────────────────
    process_id = f"proc_{uuid.uuid4().hex[:12]}"
    now = datetime.utcnow()

    # ── 5. Schedule execution ─────────────────────────────
    try:
        result = await scheduler.schedule_execution(
            goal=execution_request.goal,
            target=execution_request.target,
            user_id=user_id,
            tenant_id=tenant_id,
            priority=int_priority,
            parameters=execution_request.parameters,
            process_id=process_id,
        )
        if isinstance(result, dict):
            process_id = result.get("process_id", process_id)
    except Exception as e:
        logger.error(f"Failed to schedule execution: {e}")
        raise HTTPException(500, f"Failed to schedule scan: {str(e)}")

    # ── 6. Increment quota counters ───────────────────────
    await qm.increment_daily(user_id)
    qm.increment_active(user_id)

    logger.info(f"📋 Scan queued: {process_id} | user={user_id} | tier={tier} | target={execution_request.target}")

    # ── 7. Return correctly shaped response ───────────────
    return HybridExecutionResponse(
        process_id=process_id,
        status=ExecutionStatus.PENDING,
        goal=execution_request.goal,
        target=execution_request.target,
        created_at=now,
        message="Scan queued successfully",
    )


# ─────────────────────────────────────────────────────────────
# GET /hybrid/status/{process_id}
# ─────────────────────────────────────────────────────────────
@router.get("/status/{process_id}", response_model=ExecutionStatusResponse)
async def get_status(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    scheduler = get_scheduler(request)
    user_id   = current_user.get("sub")
    role      = current_user.get("role", "user")

    data = await scheduler.get_execution_status(process_id)
    if not data:
        raise HTTPException(404, f"Execution {process_id} not found")

    # Non-admin: only own scans
    exec_obj = scheduler.executions.get(process_id)
    if role != "admin" and exec_obj and exec_obj.user_id != user_id:
        raise HTTPException(403, "Access denied")

    return _status_dict_to_response(data)


# ─────────────────────────────────────────────────────────────
# GET /hybrid/list
# ─────────────────────────────────────────────────────────────
@router.get("/list", response_model=ExecutionListResponse)
async def list_executions(
    request: Request,
    current_user: dict = Depends(get_current_user),
    limit: int = Query(50, le=200),
    page: int = Query(1, ge=1),
):
    scheduler = get_scheduler(request)
    user_id   = current_user.get("sub")
    role      = current_user.get("role", "user")

    # lifecycle_manager returns list of dicts
    all_execs = scheduler.list_executions(
        user_id=None if role == "admin" else user_id,
        limit=limit,
    )

    return ExecutionListResponse(
        executions=[_lifecycle_dict_to_execution_response(e) for e in all_execs],
        total=len(all_execs),
        page=page,
        page_size=limit,
        has_more=False,
    )


# ─────────────────────────────────────────────────────────────
# GET /hybrid/proposals/{process_id}
# ─────────────────────────────────────────────────────────────
@router.get("/proposals/{process_id}")
async def get_proposals(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    scheduler = get_scheduler(request)
    data = await scheduler.get_execution_status(process_id)
    if not data:
        raise HTTPException(404, "Execution not found")
    return {
        "process_id":        process_id,
        "awaiting_approval": data.get("awaiting_approval", False),
        "proposals":         data.get("pending_proposals", []),
    }


# ─────────────────────────────────────────────────────────────
# POST /hybrid/approve/{process_id}
# ─────────────────────────────────────────────────────────────
@router.post("/approve/{process_id}")
async def approve_proposals(
    process_id: str,
    request: Request,
    body: dict,
    current_user: dict = Depends(get_current_user),
):
    scheduler = get_scheduler(request)
    execution = scheduler.executions.get(process_id)
    if not execution:
        raise HTTPException(404, "Execution not found")

    approved = body.get("approved", [])
    execution.metadata["approval_decision"] = approved
    execution.metadata["awaiting_approval"] = False

    # Signal waiting coroutine if event exists
    approval_event = scheduler.execution_tasks.get(f"{process_id}_approval")
    if approval_event and hasattr(approval_event, "set"):
        approval_event.set()

    return {"status": "ok", "approved": approved, "process_id": process_id}


# ─────────────────────────────────────────────────────────────
# GET /hybrid/report/{process_id}/pdf
# ─────────────────────────────────────────────────────────────
@router.get("/report/{process_id}/pdf")
async def get_pdf_report(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    tier = current_user.get("tier", "free")
    role = current_user.get("role", "user")

    if role != "admin" and tier not in ("pro", "enterprise", "admin"):
        raise HTTPException(403, "PDF reports require Pro tier or above.")

    scheduler = get_scheduler(request)
    data = await scheduler.get_execution_status(process_id)
    if not data or not data.get("report"):
        raise HTTPException(404, "Report not available yet")

    try:
        from src.services.pdf_report import generate_pdf
        pdf_bytes = await generate_pdf(data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="scan_{process_id}.pdf"'},
        )
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {e}")


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def _safe_status(s: str) -> ExecutionStatus:
    try:
        return ExecutionStatus(s)
    except Exception:
        return ExecutionStatus.PENDING


def _status_dict_to_response(d: dict) -> ExecutionStatusResponse:
    """Convert get_execution_status() dict → ExecutionStatusResponse."""
    total = d.get("total_tasks", 0)
    done  = d.get("completed_tasks", 0)
    prog  = d.get("progress", (done / total * 100) if total > 0 else 0)

    return ExecutionStatusResponse(
        process_id      = d.get("process_id", ""),
        status          = _safe_status(d.get("status", "pending")),
        progress        = float(prog),
        current_task    = d.get("current_task"),
        completed_tasks = int(done),
        total_tasks     = int(total),
        started_at      = d.get("started_at"),
        updated_at      = d.get("updated_at"),
        completed_at    = d.get("completed_at"),
        error           = d.get("error"),
        # Extra fields for the frontend (not in base model but passed through)
    )


def _lifecycle_dict_to_execution_response(d: dict) -> HybridExecutionResponse:
    """Convert lifecycle_manager list dict → HybridExecutionResponse."""
    return HybridExecutionResponse(
        process_id = d.get("process_id", ""),
        status     = _safe_status(d.get("status", "pending")),
        goal       = d.get("goal", ""),
        target     = d.get("target"),
        created_at = d.get("created_at") or datetime.utcnow(),
        updated_at = d.get("updated_at"),
        message    = None,
    )
