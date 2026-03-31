# src/api/routes/v1/schedules.py

"""
Scan Templates + Scheduled Scans API.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from src.api.dependencies import get_current_user
from src.services.schedule_service import schedule_service
from src.utils.logging import logger

router = APIRouter(prefix="/schedules", tags=["schedules"])


# ========================================================
# Models
# ========================================================

class CreateTemplateRequest(BaseModel):
    name: str
    target: str
    goal: str
    description: Optional[str] = None
    parameters: Optional[dict] = None
    tags: Optional[List[str]] = None

class UpdateTemplateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target: Optional[str] = None
    goal: Optional[str] = None
    parameters: Optional[dict] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None

class CreateScheduleRequest(BaseModel):
    template_id: str
    cron_expression: str  # "hourly", "daily", "weekly", "4h", "12h", "7d", or cron syntax
    max_runs: Optional[int] = None


# ========================================================
# Templates
# ========================================================

@router.post("/templates")
async def create_template(req: CreateTemplateRequest, current_user: dict = Depends(get_current_user)):
    """Create a reusable scan template."""
    return await schedule_service.create_template(
        user_id=current_user["sub"],
        name=req.name, target=req.target, goal=req.goal,
        description=req.description, parameters=req.parameters,
        tags=req.tags, tenant_id=current_user.get("tenant_id", "default")
    )


@router.get("/templates")
async def list_templates(current_user: dict = Depends(get_current_user)):
    """List all scan templates."""
    templates = await schedule_service.list_templates(current_user["sub"])
    return {"templates": templates, "total": len(templates)}


@router.get("/templates/{template_id}")
async def get_template(template_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific template."""
    tmpl = await schedule_service.get_template(template_id, current_user["sub"])
    if not tmpl:
        raise HTTPException(404, "Template not found")
    return tmpl


@router.put("/templates/{template_id}")
async def update_template(template_id: str, req: UpdateTemplateRequest, current_user: dict = Depends(get_current_user)):
    """Update a template."""
    updates = req.dict(exclude_none=True)
    if not updates:
        raise HTTPException(400, "No fields to update")
    ok = await schedule_service.update_template(template_id, current_user["sub"], updates)
    if not ok:
        raise HTTPException(404, "Template not found")
    return {"message": "Template updated", "template_id": template_id}


@router.delete("/templates/{template_id}")
async def delete_template(template_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a template."""
    ok = await schedule_service.delete_template(template_id, current_user["sub"])
    if not ok:
        raise HTTPException(404, "Template not found")
    return {"message": "Template deleted", "template_id": template_id}


# ========================================================
# Scheduled Scans
# ========================================================

@router.post("/")
async def create_schedule(req: CreateScheduleRequest, current_user: dict = Depends(get_current_user)):
    """
    Create a scheduled scan.
    
    cron_expression supports:
    - Shortcuts: "hourly", "daily", "weekly", "monthly"
    - Intervals: "4h", "12h", "30m", "7d"
    - Cron syntax: "0 */6 * * *" (every 6 hours)
    """
    try:
        return await schedule_service.create_schedule(
            user_id=current_user["sub"],
            template_id=req.template_id,
            cron_expression=req.cron_expression,
            max_runs=req.max_runs,
            tenant_id=current_user.get("tenant_id", "default")
        )
    except Exception as e:
        raise HTTPException(400, str(e))


@router.get("/")
async def list_schedules(current_user: dict = Depends(get_current_user)):
    """List all scheduled scans with template details."""
    schedules = await schedule_service.list_schedules(current_user["sub"])
    return {"schedules": schedules, "total": len(schedules)}


@router.put("/{schedule_id}/toggle")
async def toggle_schedule(schedule_id: str, active: bool = True, current_user: dict = Depends(get_current_user)):
    """Enable/disable a scheduled scan."""
    ok = await schedule_service.toggle_schedule(schedule_id, current_user["sub"], active)
    if not ok:
        raise HTTPException(404, "Schedule not found")
    return {"message": f"Schedule {'enabled' if active else 'paused'}", "schedule_id": schedule_id}


@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a scheduled scan."""
    ok = await schedule_service.delete_schedule(schedule_id, current_user["sub"])
    if not ok:
        raise HTTPException(404, "Schedule not found")
    return {"message": "Schedule deleted", "schedule_id": schedule_id}
