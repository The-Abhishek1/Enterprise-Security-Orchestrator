from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import Response
from typing import Optional, List
from datetime import datetime
import uuid
import asyncio

from src.api.models.request import HybridExecutionRequest
from src.api.models.response import (
    HybridExecutionResponse,
    ExecutionStatusResponse,
    ExecutionListResponse,
    ExecutionStatus
)
from src.api.dependencies import get_current_user, get_tenant_id, get_request_id
from src.utils.logging import logger
from src.services.audit import audit_logger
from src.services.target_validator import target_validator

router = APIRouter(prefix="/hybrid", tags=["hybrid-execution"])


def get_scheduler(request: Request):
    """Get scheduler instance from app state"""
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        logger.error("Scheduler not found in app state")
        raise HTTPException(
            status_code=503,
            detail="Scheduler not initialized yet"
        )
    return scheduler


@router.post(
    "/execute",
    response_model=HybridExecutionResponse,
    status_code=202,
    summary="Execute a security goal"
)
async def execute_goal(
    request: Request,
    execution_request: HybridExecutionRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id),
    request_id: str = Depends(get_request_id)
):
    """
    Execute a security goal - Returns immediately with process_id
    The actual execution happens in the background
    """
    
    logger.info(f"🔥 Execution requested: {execution_request.goal[:50]}...")
    
    # === TARGET VALIDATION ===
    if execution_request.target:
        validation = target_validator.validate(execution_request.target)
        if not validation["allowed"]:
            await audit_logger.log(
                action="scan_blocked",
                user_id=current_user.get("sub", "unknown"),
                tenant_id=tenant_id,
                resource_type="scan",
                details={"target": execution_request.target, "reason": validation["reason"]},
                status="denied"
            )
            raise HTTPException(
                status_code=403,
                detail=f"Target not allowed: {validation['reason']}"
            )
    
    # Get scheduler
    scheduler = get_scheduler(request)
    
    # Create process ID
    process_id = f"proc_{uuid.uuid4().hex[:12]}"
    
    logger.info(f"📋 Created process_id: {process_id}")
    
    # Map priority string to integer
    priority_map = {
        "low": 0,
        "medium": 5,
        "high": 10,
        "critical": 20
    }
    priority_int = priority_map.get(execution_request.priority.value, 5)
    
    # Start background task
    asyncio.create_task(
        scheduler.schedule_execution(
            goal=execution_request.goal,
            target=execution_request.target,
            user_id=current_user.get("sub"),
            tenant_id=tenant_id,
            budget_limit=execution_request.budget_limit,
            priority=priority_int,  # Pass integer
            parameters={
                "request_id": request_id,
                "tags": execution_request.tags,
                "mode": execution_request.mode.value,
                "timeout": execution_request.timeout,
                "original_priority": execution_request.priority.value,
                **execution_request.parameters
            },
            process_id=process_id
        )
    ).add_done_callback(
        lambda task: logger.error(f"❌ Background task failed for {process_id}: {task.exception()}") 
        if task.exception() else logger.info(f"🚀 Background task completed for {process_id}")
    )
    
    logger.info(f"✅ Returning 202 for process_id: {process_id}")
    
    # Create response
    return HybridExecutionResponse(
        process_id=process_id,
        status=ExecutionStatus.PENDING,
        goal=execution_request.goal,
        target=execution_request.target,
        created_at=datetime.utcnow()
    )

@router.get("/status/{process_id}")
async def get_execution_status(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id)
):
    """Get execution status with findings, report, and proposals"""
    
    scheduler = get_scheduler(request)
    
    try:
        status = await scheduler.get_execution_status(process_id)
        
        if not status:
            raise HTTPException(
                status_code=404,
                detail=f"Execution {process_id} not found"
            )
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting execution status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/list", response_model=ExecutionListResponse)
async def list_executions(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[ExecutionStatus] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id)
):
    """List executions"""
    
    scheduler = get_scheduler(request)
    
    # Get executions from scheduler
    executions = scheduler.list_executions(
        user_id=current_user.get("sub"),
        tenant_id=tenant_id,
        status=status.value if status else None,
        limit=100
    )
    
    # Convert to response format
    response_executions = []
    for exec_data in executions:
        try:
            response_executions.append(
                HybridExecutionResponse(
                    process_id=exec_data["process_id"],
                    status=ExecutionStatus(exec_data["status"]),
                    goal=exec_data.get("goal", ""),
                    target=exec_data.get("target"),
                    created_at=datetime.fromisoformat(exec_data["created_at"]),
                    updated_at=datetime.fromisoformat(exec_data["updated_at"]) if exec_data.get("updated_at") else None
                )
            )
        except Exception as e:
            logger.warning(f"Error parsing execution data: {e}")
    
    # Sort by created_at descending
    response_executions.sort(key=lambda x: x.created_at, reverse=True)
    
    # Apply pagination
    start = (page - 1) * page_size
    end = start + page_size
    paginated_executions = response_executions[start:end]
    
    return ExecutionListResponse(
        executions=paginated_executions,
        total=len(response_executions),
        page=page,
        page_size=page_size,
        has_more=end < len(response_executions)
    )


@router.post("/cancel/{process_id}", status_code=204)
async def cancel_execution(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id)
):
    """Cancel execution"""
    
    scheduler = get_scheduler(request)
    
    cancelled = await scheduler.cancel_execution(process_id)
    
    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail=f"Execution {process_id} not found or cannot be cancelled"
        )
    
    logger.info(f"Execution cancelled: {process_id}")
    return None


@router.get("/proposals/{process_id}")
async def get_proposals(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Get pending task proposals for user approval"""
    
    scheduler = get_scheduler(request)
    
    # Check if execution exists
    status = await scheduler.get_execution_status(process_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Execution {process_id} not found")
    
    # Get proposals from execution controller
    controller = scheduler.execution_controller
    if not controller:
        raise HTTPException(status_code=503, detail="Execution controller not initialized")
    
    proposals = controller.get_pending_proposals(process_id)
    
    # Also check execution metadata
    execution = scheduler.executions.get(process_id)
    awaiting = execution.metadata.get("awaiting_approval", False) if execution else False
    stored_proposals = execution.metadata.get("pending_proposals", []) if execution else []
    
    return {
        "process_id": process_id,
        "status": status.get("status", "unknown"),
        "awaiting_approval": awaiting,
        "proposals": stored_proposals if awaiting else [],
        "message": "POST /approve/{process_id} with {\"approved\": [\"task_name1\", ...]} or {\"approved\": []} to reject all"
    }


@router.post("/approve/{process_id}")
async def approve_proposals(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Approve or reject proposed tasks"""
    
    scheduler = get_scheduler(request)
    
    # Get request body
    body = await request.json()
    approved_names = body.get("approved", [])
    
    controller = scheduler.execution_controller
    if not controller:
        raise HTTPException(status_code=503, detail="Execution controller not initialized")
    
    # Check there are pending proposals
    pending = controller.get_pending_proposals(process_id)
    if not pending:
        raise HTTPException(status_code=404, detail=f"No pending proposals for {process_id}")
    
    if approved_names:
        controller.approve_proposals(process_id, approved_names)
        return {
            "process_id": process_id,
            "action": "approved",
            "approved_tasks": approved_names,
            "message": f"Approved {len(approved_names)} tasks — execution resuming"
        }
    else:
        controller.reject_all_proposals(process_id)
        return {
            "process_id": process_id,
            "action": "rejected",
            "message": "All proposals rejected — continuing with original plan"
        }


@router.get("/report/{process_id}/pdf")
async def download_pdf_report(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Download pentest report as PDF."""
    
    scheduler = get_scheduler(request)
    
    status = await scheduler.get_execution_status(process_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Execution {process_id} not found")
    
    if status.get("status") != "completed":
        raise HTTPException(status_code=400, detail=f"Scan not completed yet (status: {status.get('status')})")
    
    report = status.get("report")
    if not report:
        raise HTTPException(status_code=404, detail="No report available for this scan")
    
    from src.services.pdf_report import pdf_generator
    
    # Build scan data for PDF
    scan_data = {
        "process_id": process_id,
        "target": status.get("target", "Unknown"),
        "goal": status.get("goal", ""),
        "risk_summary": status.get("risk_summary", {}),
        "risk_level": status.get("risk_summary", {}).get("overall_risk", "none"),
        "risk_score": status.get("risk_summary", {}).get("overall_score", 0),
        "duration_seconds": status.get("duration", 0),
        "total_tasks": status.get("total_tasks", 0),
        "dynamic_tasks": status.get("dynamic_tasks", 0),
        "findings_count": status.get("findings_count", 0),
        "llm_calls": status.get("llm_calls", 0),
        "tools_used": status.get("tools_used", []),
        "report": report,
    }
    
    pdf_bytes = pdf_generator.generate(scan_data)
    
    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="PDF generation failed — reportlab may not be installed")
    
    target_clean = status.get("target", "scan").replace(".", "_").replace("/", "_")
    filename = f"pentest_report_{target_clean}_{process_id[-8:]}.pdf"
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )