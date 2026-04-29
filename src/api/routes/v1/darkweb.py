# src/api/routes/v1/darkweb.py
"""
Dark Web Monitoring — ESO side.
POST /darkweb/check        → one-shot check for a single identifier
POST /darkweb/monitor      → register identifier for periodic monitoring + callback
"""
import asyncio
from fastapi  import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing   import Dict, List, Optional

from src.api.dependencies import get_current_user
from src.core.config      import get_settings
from src.utils.logging    import logger

router = APIRouter(prefix="/darkweb", tags=["darkweb"])


class CheckRequest(BaseModel):
    identifier:  str           # email or domain
    id_type:     str           # "email" | "domain"
    api_keys:    Dict[str, str] = {}   # {"hibp": "...", "intelx": "..."}


class MonitorRequest(BaseModel):
    monitor_id:   str          # XCloak DB id for this monitor entry
    identifier:   str
    id_type:      str
    api_keys:     Dict[str, str] = {}
    callback_url: str


@router.post("/check")
async def one_shot_check(req: CheckRequest, current_user: dict = Depends(get_current_user)):
    """Synchronous breach check — runs immediately and returns results."""
    if req.id_type not in ("email", "domain"):
        raise HTTPException(400, "id_type must be 'email' or 'domain'")
    try:
        from src.workers.breach_checker import check_identifier
        exposures = await check_identifier(req.identifier, req.id_type, req.api_keys)
        return {"ok": True, "identifier": req.identifier, "exposures": exposures}
    except Exception as e:
        logger.error(f"[darkweb] check error: {e}", exc_info=True)
        raise HTTPException(500, str(e))


@router.post("/monitor")
async def trigger_monitor_check(req: MonitorRequest, request: Request):
    """
    Async check triggered by XCloak's scheduler.
    Runs check then POSTs results back to XCloak via callback.
    """
    _check_internal(request)
    asyncio.create_task(_run_and_callback(req))
    return {"ok": True, "monitor_id": req.monitor_id}


async def _run_and_callback(req: MonitorRequest):
    try:
        from src.workers.breach_checker import check_identifier
        exposures = await check_identifier(req.identifier, req.id_type, req.api_keys)
        await _callback(req.callback_url, req.monitor_id, exposures)
        logger.info(f"[darkweb] Monitor {req.monitor_id}: {len(exposures)} exposures")
    except Exception as e:
        logger.error(f"[darkweb] Monitor {req.monitor_id} error: {e}", exc_info=True)
        await _callback(req.callback_url, req.monitor_id, [], error=str(e))


async def _callback(url: str, monitor_id: str, exposures: list, error: str = ""):
    import httpx
    payload = {"monitorId": monitor_id, "exposures": exposures}
    if error:
        payload["error"] = error
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.patch(
                url, json=payload,
                headers={"X-Internal-Secret": get_settings().internal_email_secret},
            )
            if not r.is_success:
                logger.warning(f"[darkweb] callback failed {r.status_code}: {r.text[:200]}")
    except Exception as e:
        logger.error(f"[darkweb] callback error: {e}")


def _check_internal(request: Request):
    expected = get_settings().internal_email_secret
    secret   = request.headers.get("X-Internal-Secret", "")
    if not secret or secret != expected:
        raise HTTPException(403, "Internal endpoint")
