# src/api/routes/v1/ws.py

"""
WebSocket endpoint for real-time scan events.
Connect: ws://localhost:8000/api/v1/ws/scan/{process_id}
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from src.services.event_bus import event_bus
from src.utils.logging import logger

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scan/{process_id}")
async def scan_websocket(ws: WebSocket, process_id: str):
    await ws.accept()
    logger.info(f"🔌 WebSocket connected: {process_id}")

    # Subscribe FIRST — so we don't miss events during history replay
    queue = event_bus.subscribe(process_id)

    # Replay history
    history = event_bus.get_history(process_id)
    history_count = len(history)
    for event in history:
        try:
            await ws.send_text(event.to_json())
        except Exception:
            event_bus.unsubscribe(process_id, queue)
            return

    # Drain any events that arrived during replay (they're already in history)
    skipped = 0
    while not queue.empty() and skipped < history_count:
        try:
            queue.get_nowait()
            skipped += 1
        except:
            break

    # Now stream live events — no duplicates
    try:
        while True:
            event = await queue.get()
            await ws.send_text(event.to_json())
            if event.type in ('complete', 'error', 'failed'):
                break
    except WebSocketDisconnect:
        logger.info(f"🔌 WebSocket disconnected: {process_id}")
    except Exception as e:
        logger.warning(f"🔌 WebSocket error: {e}")
    finally:
        event_bus.unsubscribe(process_id, queue)
