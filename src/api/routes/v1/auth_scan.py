# src/api/routes/v1/auth_scan.py
"""
Authenticated Web Scanning — ESO side.
POST /auth-scan/start  → start scan, return scan_id
GET  /auth-scan/{id}   → poll status + results
"""
import asyncio, uuid
from fastapi  import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing   import Any, Dict, List, Optional

from src.api.dependencies import get_current_user
from src.utils.logging    import logger

router = APIRouter(prefix="/auth-scan", tags=["auth-scan"])
_SCANS: Dict[str, Dict] = {}   # scan_id → scan state


class AuthScanRequest(BaseModel):
    target_url:  str
    auth_config: Dict[str, Any]  # {"type": "form|cookie|token|none", ...}
    max_pages:   int = 20


@router.post("/start")
async def start_scan(req: AuthScanRequest, current_user: dict = Depends(get_current_user)):
    scan_id = f"authscan_{uuid.uuid4().hex[:10]}"
    _SCANS[scan_id] = {
        "scan_id": scan_id, "user_id": current_user["sub"],
        "status": "running", "phase": "authenticating",
        "progress": 0, "target_url": req.target_url,
        "auth_result": None, "sitemap": [], "forms": [],
        "findings": [], "xhr_calls": [], "error": None,
    }
    asyncio.create_task(_run(scan_id, req))
    logger.info(f"[auth-scan] {scan_id} started → {req.target_url}")
    return {"ok": True, "scan_id": scan_id}


@router.get("/{scan_id}")
async def get_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = _SCANS.get(scan_id)
    if not scan:             raise HTTPException(404, f"Scan {scan_id} not found")
    if scan["user_id"] != current_user["sub"]: raise HTTPException(403, "Forbidden")
    return scan


async def _run(scan_id: str, req: AuthScanRequest):
    scan = _SCANS[scan_id]
    try:
        from playwright.async_api import async_playwright
        from src.workers.auth_handler          import build_auth_context
        from src.workers.authenticated_crawler import crawl_authenticated
        from src.workers.web_vuln_tester       import run_web_tests

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-dev-shm-usage",
                "--disable-gpu", "--disable-extensions",
            ])
            try:
                # Phase 1: Authenticate
                scan["phase"] = "authenticating"; scan["progress"] = 10
                ctx, auth_result = await build_auth_context(pw, browser, req.auth_config, req.target_url)
                scan["auth_result"] = auth_result

                if not auth_result.get("ok") and req.auth_config.get("type") != "none":
                    scan.update({"status": "error", "error": f"Authentication failed: {auth_result.get('error','')}"})
                    return

                # Phase 2: Crawl
                scan["phase"] = "crawling"; scan["progress"] = 25

                async def progress_cb(pct, msg):
                    scan["progress"] = 25 + int(pct * 0.4)
                    scan["phase"]    = msg[:60]

                crawl_data = await crawl_authenticated(ctx, req.target_url, req.max_pages, progress_cb)
                scan["sitemap"]   = crawl_data["urls"]
                scan["forms"]     = crawl_data["forms"]
                scan["xhr_calls"] = crawl_data["xhr_calls"]
                scan["progress"]  = 65

                # Phase 3: Vuln tests
                scan["phase"] = "testing"
                findings = await run_web_tests(
                    ctx,
                    crawl_data["urls"],
                    crawl_data["forms"],
                    crawl_data["xhr_calls"],
                    req.target_url,
                )
                scan["findings"] = findings
                await ctx.close()

            finally:
                await browser.close()

        scan.update({"status": "complete", "progress": 100, "phase": "done"})
        logger.info(f"[auth-scan] {scan_id} done — {len(scan['findings'])} findings, {len(scan['sitemap'])} pages")

    except ImportError as e:
        logger.error(f"[auth-scan] Playwright not installed: {e}")
        scan.update({"status": "error", "error": "Playwright not installed. Run: pip install playwright && playwright install chromium"})
    except Exception as e:
        logger.error(f"[auth-scan] {scan_id} error: {e}", exc_info=True)
        scan.update({"status": "error", "error": str(e)})
