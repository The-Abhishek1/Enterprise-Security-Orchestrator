# src/api/routes/v1/api_security.py
"""
API Security Testing — ESO side.
POST /api-security/parse   → parse spec, return endpoint list
POST /api-security/scan    → start async scan, return scan_id
GET  /api-security/scan/{scan_id} → poll results
"""
import asyncio, uuid
from fastapi  import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing   import Any, Dict, List

from src.api.dependencies import get_current_user
from src.utils.logging    import logger

router = APIRouter(prefix="/api-security", tags=["api-security"])
_SCANS: Dict[str, Dict] = {}   # simple in-memory store; replace with Redis for multi-worker


class ParseRequest(BaseModel):
    spec_json: str
    base_url_override: str = ""


class ScanRequest(BaseModel):
    spec_json:   str
    base_url:    str = ""
    auth_config: Dict[str, Any] = {}
    max_workers: int = 5
    timeout:     int = 10


@router.post("/parse")
async def parse_spec(req: ParseRequest, current_user: dict = Depends(get_current_user)):
    try:
        from src.workers.spec_parser import parse_spec as _parse, endpoint_to_dict
        endpoints = _parse(req.spec_json, req.base_url_override)
        return {"ok": True, "count": len(endpoints),
                "endpoints": [endpoint_to_dict(ep) for ep in endpoints]}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error(f"[api-security] parse: {e}", exc_info=True)
        raise HTTPException(500, f"Parse failed: {e}")


@router.post("/scan")
async def start_scan(req: ScanRequest, current_user: dict = Depends(get_current_user)):
    try:
        from src.workers.spec_parser import parse_spec as _parse, endpoint_to_dict
        endpoints = _parse(req.spec_json, req.base_url)
    except ValueError as e:
        raise HTTPException(400, str(e))

    scan_id = f"apisec_{uuid.uuid4().hex[:12]}"
    _SCANS[scan_id] = {
        "scan_id": scan_id, "user_id": current_user["sub"],
        "status": "running", "progress": 0,
        "endpoints": [endpoint_to_dict(ep) for ep in endpoints],
        "findings": [], "error": None,
    }
    asyncio.create_task(_run(scan_id, endpoints, req.auth_config, req.base_url,
                             req.max_workers, req.timeout))
    logger.info(f"[api-security] Scan {scan_id} queued — {len(endpoints)} endpoints")
    return {"ok": True, "scan_id": scan_id, "endpoints": len(endpoints)}


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = _SCANS.get(scan_id)
    if not scan:             raise HTTPException(404, f"Scan {scan_id} not found")
    if scan["user_id"] != current_user["sub"]: raise HTTPException(403, "Forbidden")
    return scan


async def _run(scan_id, endpoints, auth_config, base_url, max_workers, timeout):
    try:
        from src.workers.api_tester import run_api_tests
        findings = await run_api_tests(endpoints, auth_config, base_url, max_workers, timeout)
        _SCANS[scan_id].update({"findings": findings, "status": "complete", "progress": 100})
        logger.info(f"[api-security] Scan {scan_id} done — {len(findings)} findings")
    except Exception as e:
        logger.error(f"[api-security] Scan {scan_id} error: {e}", exc_info=True)
        _SCANS[scan_id].update({"status": "error", "error": str(e)})
