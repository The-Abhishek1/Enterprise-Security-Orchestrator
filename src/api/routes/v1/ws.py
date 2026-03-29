# src/api/routes/v1/ws.py

"""
WebSocket endpoint for real-time scan events.
Connect: ws://localhost:8000/api/v1/ws/scan/{process_id}
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import json

from src.services.event_bus import event_bus
from src.utils.logging import logger

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scan/{process_id}")
async def scan_websocket(ws: WebSocket, process_id: str):
    """
    Stream real-time scan events via WebSocket.

    Event types sent to client:
      planning        — LLM is creating the task DAG
      plan_created    — DAG created with N tasks
      level_start     — Starting level N with tools [...]
      task_start      — Tool X starting execution
      task_output     — Live stdout/stderr line from tool
      task_complete   — Tool X finished with N findings
      analysis_start  — LLM analysis beginning
      analysis_done   — Analysis results (validated, removed)
      risk_update     — Risk score updated
      proposal        — AI proposes new tasks
      approval_needed — Execution paused, waiting for user
      approval_done   — User approved/rejected
      report_start    — Generating final report
      report_done     — Report ready
      complete        — Scan finished
      error           — Something went wrong
    """
    await ws.accept()
    logger.info(f"🔌 WebSocket connected: {process_id}")

    # Send event history (replay for late joiners)
    history = event_bus.get_history(process_id)
    for event in history:
        try:
            await ws.send_text(event.to_json())
        except Exception:
            return

    # Subscribe to live events
    queue = event_bus.subscribe(process_id)

    try:
        while True:
            event = await queue.get()
            await ws.send_text(event.to_json())

            # Close after terminal events
            if event.type in ('complete', 'error', 'failed'):
                break
    except WebSocketDisconnect:
        logger.info(f"🔌 WebSocket disconnected: {process_id}")
    except Exception as e:
        logger.warning(f"🔌 WebSocket error: {e}")
    finally:
        event_bus.unsubscribe(process_id, queue)
