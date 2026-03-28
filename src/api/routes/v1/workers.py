# src/api/routes/v1/workers.py
from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any, Optional

from src.api.dependencies import get_current_user, get_tenant_id
from src.utils.logging import logger

router = APIRouter(prefix="/workers", tags=["workers"])


@router.get("/stats")
async def get_worker_stats(
    request: Request,
    tool_name: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id)
) -> Dict[str, Any]:
    """Get worker pool statistics"""
    
    worker_pool = getattr(request.app.state, "worker_pool", None)
    if not worker_pool:
        raise HTTPException(status_code=503, detail="Worker pool not initialized")
    
    if tool_name:
        stats = await worker_pool.get_pool_stats(tool_name)
    else:
        # Get stats for all tools
        stats = {}
        for tool in worker_pool.worker_pools.keys():
            stats[tool] = await worker_pool.get_pool_stats(tool)
    
    return {
        "tenant_id": tenant_id,
        "stats": stats
    }


@router.get("/tools")
async def list_tools(
    request: Request,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id)
) -> Dict[str, Any]:
    """List all available tools"""
    
    tool_registry = getattr(request.app.state, "tool_router", None)
    if not tool_registry:
        raise HTTPException(status_code=503, detail="Tool router not initialized")
    
    tools = await tool_registry.tool_registry.get_all_tools()
    
    return {
        "tenant_id": tenant_id,
        "total_tools": len(tools),
        "tools": tools
    }