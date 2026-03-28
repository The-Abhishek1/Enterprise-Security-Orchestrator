# src/api/routes/v1/debug.py
from fastapi import APIRouter, Request, HTTPException
from typing import Dict, Any
import asyncio
import aiohttp

from src.utils.logging import logger

router = APIRouter(prefix="/debug", tags=["debug"])


@router.get("/llm/status")
async def check_llm_status(request: Request) -> Dict[str, Any]:
    """Check LLM status"""
    
    planner = getattr(request.app.state, "planner_agent", None)
    if not planner or not planner.llm_client:
        return {"status": "unavailable", "reason": "Planner agent not initialized"}
    
    client = planner.llm_client
    
    result = {
        "provider": client.__class__.__name__,
        "model": client.model_name,
        "status": "unknown"
    }
    
    # Test connection
    try:
        start = asyncio.get_event_loop().time()
        response = await client.generate("Say 'OK' if you can hear me.", "Respond with only the word OK.")
        duration = asyncio.get_event_loop().time() - start
        
        result["status"] = "healthy" if "OK" in response else "unhealthy"
        result["response"] = response
        result["response_time"] = f"{duration:.2f}s"
    except asyncio.TimeoutError:
        result["status"] = "timeout"
        result["error"] = "LLM request timed out"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result


@router.get("/execution/{process_id}/plan")
async def get_execution_plan(
    process_id: str,
    request: Request
) -> Dict[str, Any]:
    """Get execution plan"""
    
    scheduler = getattr(request.app.state, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    
    execution = scheduler.executions.get(process_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    return {
        "process_id": process_id,
        "status": execution.status.value if hasattr(execution.status, 'value') else str(execution.status),
        "dag": execution.dag,
        "total_tasks": execution.total_tasks,
        "completed_tasks": execution.completed_tasks,
        "failed_tasks": execution.failed_tasks,
        "estimated_cost": execution.estimated_cost,
        "actual_cost": execution.actual_cost
    }

@router.get("/execution/{process_id}/raw-output")
async def get_execution_raw_output(
    process_id: str,
    request: Request
):
    """Get raw output from execution containers"""
    
    scheduler = getattr(request.app.state, "scheduler", None)
    if not scheduler:
        return {"error": "Scheduler not initialized"}
    
    execution = scheduler.executions.get(process_id)
    if not execution:
        return {"error": "Execution not found"}
    
    # Get worker pool
    worker_pool = getattr(request.app.state, "worker_pool", None)
    if not worker_pool:
        return {"error": "Worker pool not initialized"}
    
    results = {}
    
    # Get all worker containers for this execution
    for tool_name, workers in worker_pool.worker_pools.items():
        for worker in workers:
            if worker.get("current_task"):
                # Get logs from container
                logs = await worker_pool.container_manager.get_container_logs(
                    worker["container_id"],
                    tail=200
                )
                results[worker["worker_id"]] = {
                    "tool": tool_name,
                    "container_id": worker["container_id"],
                    "logs": logs
                }
    
    return {
        "process_id": process_id,
        "execution_status": str(execution.status),
        "workers": results
    }