# src/api/routes/v1/github.py
"""
ESO GitHub SAST endpoint.
Receives scan jobs from XCloak webhook, runs SAST, posts PR comments, saves results.
"""
import asyncio
from fastapi      import APIRouter, Request, HTTPException
from pydantic     import BaseModel
from typing       import Optional
from src.utils.logging import logger
from src.core.config   import get_settings

router = APIRouter(prefix="/github", tags=["github"])

class ScanRequest(BaseModel):
    scanId:        str
    repoFullName:  str
    cloneUrl:      str
    commitSha:     str
    branch:        str
    prNumber:      Optional[int] = None
    userAlias:     str
    accessToken:   str


def _check_internal(request: Request):
    # Use settings object — os.getenv() doesn't see pydantic-loaded env vars
    expected = get_settings().internal_email_secret
    secret   = request.headers.get("X-Internal-Secret", "")
    if not secret or secret != expected:
        raise HTTPException(403, "Forbidden — internal endpoint")


@router.post("/scan")
async def trigger_scan(req: ScanRequest, request: Request):
    """
    Called by XCloak after a push/PR webhook or manual scan trigger.
    Runs SAST in the background and returns immediately.
    """
    _check_internal(request)
    logger.info(f"[github] Scan queued: {req.repoFullName} @ {req.commitSha[:8]} (scan={req.scanId})")

    # Fire and forget — respond immediately so XCloak webhook returns fast
    asyncio.create_task(_run_scan(req))
    return {"ok": True, "scanId": req.scanId, "message": "scan queued"}


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    """Get scan status — called by XCloak frontend for debugging."""
    _check_internal(request)
    return {"scan_id": scan_id, "note": "results stored in XCloak Prisma"}


async def _run_scan(req: ScanRequest):
    """Full SAST pipeline — runs in background task."""
    from src.workers.sast_scanner    import run_sast
    from src.workers.github_reporter import post_pr_comments, update_scan_status

    await update_scan_status(req.scanId, "running")

    try:
        logger.info(f"[github] Starting SAST for {req.repoFullName}")
        findings = await run_sast(
            clone_url=req.cloneUrl,
            commit_sha=req.commitSha,
            access_token=req.accessToken,
            repo_full_name=req.repoFullName,
        )

        if req.prNumber:
            await post_pr_comments(
                repo_full_name=req.repoFullName,
                pr_number=req.prNumber,
                commit_sha=req.commitSha,
                findings=findings,
                access_token=req.accessToken,
            )

        await update_scan_status(
            scan_id=req.scanId,
            status="completed",
            findings=findings,
        )
        logger.info(
            f"[github] Scan complete: {req.repoFullName} — "
            f"{len(findings)} findings "
            f"({sum(1 for f in findings if f.get('severity') == 'critical')} critical)"
        )

    except Exception as e:
        logger.error(f"[github] Scan failed for {req.repoFullName}: {e}", exc_info=True)
        await update_scan_status(req.scanId, "failed", error=str(e))
