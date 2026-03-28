# src/api/routes/v1/stream.py - Add real-time output streaming

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse
import asyncio
import json
from typing import AsyncGenerator
from datetime import datetime

router = APIRouter(prefix="/stream", tags=["streaming"])


@router.get("/output/{process_id}")
async def stream_execution_output(
    process_id: str,
    request: Request
):
    """Stream real-time tool output for an execution"""
    
    async def output_generator() -> AsyncGenerator[str, None]:
        scheduler = getattr(request.app.state, "scheduler", None)
        memory_bus = getattr(request.app.state, "memory_bus", None)
        
        if not scheduler or not memory_bus:
            yield f"event: error\ndata: {json.dumps({'error': 'System not ready'})}\n\n"
            return
        
        last_output = ""
        
        while True:
            if await request.is_disconnected():
                break
            
            # Subscribe to execution output topic
            topic = f"execution:{process_id}:output"
            messages = await memory_bus.get_topic_history(topic, limit=10)
            
            for msg in messages:
                if msg.get("output") != last_output:
                    yield f"event: output\ndata: {json.dumps(msg)}\n\n"
                    last_output = msg.get("output")
            
            # Check if execution completed
            status = await scheduler.get_execution_status(process_id)
            if status and status.get("status") in ["completed", "failed", "cancelled"]:
                yield f"event: complete\ndata: {json.dumps(status)}\n\n"
                break
            
            await asyncio.sleep(1)
    
    return StreamingResponse(
        output_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.get("/findings/{process_id}")
async def stream_findings(
    process_id: str,
    request: Request
):
    """Stream findings as they are discovered"""
    
    async def findings_generator() -> AsyncGenerator[str, None]:
        memory_bus = getattr(request.app.state, "memory_bus", None)
        
        if not memory_bus:
            yield f"event: error\ndata: {json.dumps({'error': 'Memory bus not ready'})}\n\n"
            return
        
        seen_findings = set()
        
        while True:
            if await request.is_disconnected():
                break
            
            # Get findings from all agents
            for agent in ["recon", "scanner"]:
                topic = f"agent:{agent}:findings"
                messages = await memory_bus.get_topic_history(topic, limit=5)
                
                for msg in messages:
                    for finding in msg.get("findings", []):
                        finding_id = f"{finding.get('type')}-{finding.get('port')}-{finding.get('service')}"
                        if finding_id not in seen_findings:
                            yield f"event: finding\ndata: {json.dumps(finding)}\n\n"
                            seen_findings.add(finding_id)
            
            await asyncio.sleep(2)
    
    return StreamingResponse(
        findings_generator(),
        media_type="text/event-stream"
    )