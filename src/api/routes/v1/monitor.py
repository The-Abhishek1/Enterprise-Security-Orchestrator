# src/api/routes/v1/monitor.py
"""
Continuous Attack Surface Monitoring (CASM) — ESO side.
Receives scan jobs from XCloak, runs discovery tools, diffs against previous snapshot,
calls back to XCloak with results.
"""
import asyncio
from fastapi    import APIRouter, HTTPException, Request
from pydantic   import BaseModel
from typing     import Optional

from src.utils.logging import logger
from src.core.config   import get_settings

router = APIRouter(prefix="/monitor", tags=["monitor"])


class MonitorScanRequest(BaseModel):
    asset_id:     str
    target:       str           # domain, IP, or CIDR
    type:         str           # "domain" | "ip" | "cidr"
    user_alias:   str
    callback_url: str
    # Previous snapshot passed from XCloak for diffing (optional — first scan won't have one)
    previous_snapshot: Optional[dict] = None


def _check_internal(request: Request):
    expected = get_settings().internal_email_secret
    secret   = request.headers.get("X-Internal-Secret", "")
    if not secret or secret != expected:
        raise HTTPException(403, "Forbidden — internal endpoint")


@router.post("/scan")
async def trigger_scan(req: MonitorScanRequest, request: Request):
    """XCloak calls this to start a monitoring scan. Returns immediately."""
    _check_internal(request)
    logger.info(f"[monitor] Scan queued: {req.target} ({req.type}) asset={req.asset_id}")
    asyncio.create_task(_run_scan(req))
    return {"ok": True, "asset_id": req.asset_id}


@router.get("/health")
async def health(request: Request):
    _check_internal(request)
    return {"ok": True, "tools": _get_available_tools()}


def _get_available_tools():
    import shutil, sys, os
    tools = {}
    venv_bin = os.path.dirname(sys.executable)
    for t in ["nmap", "subfinder", "whatweb"]:
        path = os.path.join(venv_bin, t)
        tools[t] = os.path.isfile(path) or bool(shutil.which(t))
    return tools


async def _run_scan(req: MonitorScanRequest):
    """Full CASM scan pipeline."""
    from src.workers.asset_scanner import run_asset_scan
    from src.workers.asset_differ  import diff_snapshots

    try:
        # Run all discovery tools in parallel
        snapshot = await run_asset_scan(req.target, req.type)

        # Diff against previous to find changes
        changes = diff_snapshots(req.previous_snapshot, snapshot, req.target)

        # Callback to XCloak
        await _callback(req.callback_url, req.asset_id, snapshot, changes)

        logger.info(
            f"[monitor] Scan complete: {req.target} — "
            f"{len(changes)} changes detected"
        )
    except Exception as e:
        logger.error(f"[monitor] Scan failed for {req.target}: {e}", exc_info=True)
        await _callback(req.callback_url, req.asset_id, None, [], error=str(e))


async def _callback(
    callback_url: str,
    asset_id:     str,
    snapshot:     Optional[dict],
    changes:      list,
    error:        Optional[str] = None,
):
    import httpx
    settings = get_settings()
    payload  = {"assetId": asset_id, "snapshot": snapshot, "changes": changes}
    if error:
        payload["error"] = error

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.patch(
                callback_url,
                json=payload,
                headers={"X-Internal-Secret": settings.internal_email_secret},
            )
            if not res.is_success:
                logger.warning(f"[monitor] callback failed ({res.status_code}): {res.text[:200]}")
    except Exception as e:
        logger.error(f"[monitor] callback error: {e}")
