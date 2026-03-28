# src/api/routes/v1/agents.py
from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any, Optional

from src.api.dependencies import get_current_user, get_tenant_id
from src.utils.logging import logger

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("/status")
async def get_agent_status(
    request: Request,
    agent_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id)
) -> Dict[str, Any]:
    """Get agent status"""
    
    orchestrator = getattr(request.app.state, "orchestrator", None)
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    status = await orchestrator.get_agent_status(agent_type)
    
    return {
        "tenant_id": tenant_id,
        "status": status
    }