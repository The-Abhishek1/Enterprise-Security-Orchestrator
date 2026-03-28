# src/api/routes/v1/memory.py
from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any

from src.api.dependencies import get_current_user, get_tenant_id
from src.utils.logging import logger

router = APIRouter(prefix="/memory", tags=["memory"])


@router.get("/stats")
async def get_memory_stats(
    request: Request,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id)
) -> Dict[str, Any]:
    """Get memory system statistics"""
    
    memory_service = getattr(request.app.state, "memory_service", None)
    if not memory_service:
        raise HTTPException(status_code=503, detail="Memory service not initialized")
    
    stats = await memory_service.get_stats()
    
    # Add tenant info
    stats["tenant_id"] = tenant_id
    stats["user_id"] = current_user.get("sub")
    
    return stats


@router.get("/execution/{process_id}/graph")
async def get_execution_graph(
    process_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(get_tenant_id)
) -> Dict[str, Any]:
    """Get execution graph for visualization"""
    
    memory_service = getattr(request.app.state, "memory_service", None)
    if not memory_service:
        raise HTTPException(status_code=503, detail="Memory service not initialized")
    
    graph = await memory_service.get_execution_graph(process_id)
    
    if not graph:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    return graph