# src/api/routes/v1/ai_scanner.py
"""
Prompt Injection Scanner — tests AI endpoints for injection vulnerabilities.
Receives scan jobs from XCloak, runs adversarial prompts, returns findings.
"""
import asyncio
import uuid
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from src.utils.logging import logger
from src.core.config import get_settings

router = APIRouter(prefix="/ai-scanner", tags=["ai-scanner"])


class AIScanRequest(BaseModel):
    scan_id:       str
    target_url:    str          # e.g. https://api.openai.com/v1/chat/completions
    api_key:       str
    model:         str          # e.g. gpt-4, claude-3, etc.
    system_prompt: Optional[str] = None
    categories:    Optional[List[str]] = None  # subset of attack categories, or None = all
    max_prompts:   Optional[int] = 50
    user_alias:    str
    callback_url:  str          # XCloak scan-update endpoint


class AIScanStatusRequest(BaseModel):
    scan_id: str


def _check_internal(request: Request):
    expected = get_settings().internal_email_secret
    secret   = request.headers.get("X-Internal-Secret", "")
    if not secret or secret != expected:
        raise HTTPException(403, "Forbidden — internal endpoint")


@router.post("/scan")
async def start_scan(req: AIScanRequest, request: Request):
    """
    XCloak calls this to start a prompt injection scan.
    Returns immediately — scan runs in background.
    """
    _check_internal(request)
    logger.info(f"[ai-scanner] Scan queued: {req.target_url} (scan={req.scan_id})")

    asyncio.create_task(_run_scan(req))
    return {"ok": True, "scan_id": req.scan_id, "message": "scan queued"}


@router.get("/categories")
async def list_categories(request: Request):
    """Return available attack categories."""
    _check_internal(request)
    from src.workers.prompt_injector import ATTACK_CATEGORIES
    return {"categories": list(ATTACK_CATEGORIES.keys())}


async def _run_scan(req: AIScanRequest):
    """Full prompt injection scan pipeline."""
    from src.workers.prompt_injector import run_injection_scan
    import httpx

    # Notify XCloak: running
    await _callback(req.callback_url, req.scan_id, "running", get_settings())

    try:
        findings = await run_injection_scan(
            target_url=req.target_url,
            api_key=req.api_key,
            model=req.model,
            system_prompt=req.system_prompt,
            categories=req.categories,
            max_prompts=req.max_prompts,
        )

        await _callback(
            req.callback_url, req.scan_id, "completed", get_settings(),
            findings=findings,
        )
        logger.info(
            f"[ai-scanner] Scan complete: {req.scan_id} — "
            f"{len(findings)} findings "
            f"({sum(1 for f in findings if f.get('severity') == 'critical')} critical)"
        )

    except Exception as e:
        logger.error(f"[ai-scanner] Scan failed: {req.scan_id} — {e}", exc_info=True)
        await _callback(req.callback_url, req.scan_id, "failed", get_settings(), error=str(e))


async def _callback(
    callback_url: str,
    scan_id: str,
    status: str,
    settings,
    findings: Optional[List[Dict]] = None,
    error: Optional[str] = None,
):
    import httpx
    payload: Dict[str, Any] = {"scanId": scan_id, "status": status, "scanType": "ai"}

    if findings is not None:
        payload["findings"]  = len(findings)
        payload["criticals"] = sum(1 for f in findings if f.get("severity") == "critical")
        payload["highs"]     = sum(1 for f in findings if f.get("severity") == "high")
        payload["result"]    = {"findings": findings}
    if error:
        payload["error"] = error

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.patch(
                callback_url,
                json=payload,
                headers={"X-Internal-Secret": settings.internal_email_secret},
            )
            if not res.is_success:
                logger.warning(f"[ai-scanner] callback failed ({res.status_code}): {res.text[:200]}")
    except Exception as e:
        logger.error(f"[ai-scanner] callback error: {e}")
