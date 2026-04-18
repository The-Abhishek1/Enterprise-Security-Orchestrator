"""
admin.py — Admin routes for ESO.
ADDED: GET /admin/payments — payment history for admin panel.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from src.api.dependencies import get_current_user
from src.core.database import db_manager
from src.utils.logging import logger

router = APIRouter(prefix="/admin", tags=["admin"])

VALID_TIERS = ["free", "pro", "enterprise", "admin"]


def admin_only(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return current_user


class TierUpgradeRequest(BaseModel):
    user_id: str
    tier: str

class UserStatusRequest(BaseModel):
    user_id: str
    is_active: bool

class ResetQuotaRequest(BaseModel):
    user_id: str


@router.get("/users")
async def list_users(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(admin_only)
):
    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        rows = await c.fetch(
            """SELECT user_id, email, username, role, tier, is_active, is_verified,
                      scans_today, total_scans, created_at
               FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2""",
            limit, offset
        )
        total = await c.fetchval("SELECT COUNT(*) FROM users")
    return {"users": [dict(r) for r in rows], "total": total}


@router.post("/users/tier")
async def set_user_tier(
    body: TierUpgradeRequest,
    request: Request,
    current_user: dict = Depends(admin_only)
):
    if body.tier not in VALID_TIERS:
        raise HTTPException(400, f"Invalid tier. Valid: {VALID_TIERS}")
    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")

    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler and hasattr(scheduler, "quota_manager"):
        ok = await scheduler.quota_manager.set_user_tier(body.user_id, body.tier)
        if not ok:
            raise HTTPException(404, "User not found")
    else:
        async with pool.acquire() as c:
            result = await c.execute(
                "UPDATE users SET tier=$1, role=$2, updated_at=NOW() WHERE user_id=$3",
                body.tier,
                "admin" if body.tier == "admin" else body.tier,
                body.user_id
            )
        if result == "UPDATE 0":
            raise HTTPException(404, "User not found")

    logger.info(f"Admin {current_user['sub']} set {body.user_id} → tier={body.tier}")
    return {"ok": True, "user_id": body.user_id, "tier": body.tier}


@router.post("/users/status")
async def set_user_status(
    body: UserStatusRequest,
    current_user: dict = Depends(admin_only)
):
    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        result = await c.execute(
            "UPDATE users SET is_active=$1, updated_at=NOW() WHERE user_id=$2",
            body.is_active, body.user_id
        )
    if result == "UPDATE 0":
        raise HTTPException(404, "User not found")
    return {"ok": True, "user_id": body.user_id, "is_active": body.is_active}


@router.post("/users/reset-quota")
async def reset_user_quota(
    body: ResetQuotaRequest,
    current_user: dict = Depends(admin_only)
):
    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        await c.execute(
            "UPDATE users SET scans_today=0, scans_today_reset=NOW() WHERE user_id=$1",
            body.user_id
        )
    return {"ok": True, "user_id": body.user_id, "reset": True}


@router.get("/stats")
async def system_stats(current_user: dict = Depends(admin_only)):
    pool = db_manager.pg_pool
    if not pool:
        return {"error": "Database unavailable"}
    async with pool.acquire() as c:
        users_by_tier  = await c.fetch("SELECT tier, COUNT(*) as count FROM users GROUP BY tier")
        scans_today    = await c.fetchval("SELECT COUNT(*) FROM scan_history WHERE created_at > NOW() - INTERVAL '24h'")
        total_scans    = await c.fetchval("SELECT COUNT(*) FROM scan_history")
        total_findings = await c.fetchval("SELECT COUNT(*) FROM findings")
        total_users    = await c.fetchval("SELECT COUNT(*) FROM users")
        recent_scans   = await c.fetch(
            """SELECT sh.process_id, sh.target, sh.status, sh.risk_level,
                      sh.findings_count, u.username, sh.created_at
               FROM scan_history sh JOIN users u ON sh.user_id=u.user_id
               ORDER BY sh.created_at DESC LIMIT 10"""
        )
    return {
        "users": {
            "total": total_users,
            "by_tier": {r["tier"]: r["count"] for r in users_by_tier},
        },
        "scans": {
            "total": total_scans,
            "last_24h": scans_today,
        },
        "findings": {"total": total_findings},
        "recent_scans": [dict(r) for r in recent_scans],
    }


@router.get("/tiers")
async def get_tier_configs(current_user: dict = Depends(admin_only)):
    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        rows = await c.fetch("SELECT * FROM tier_config ORDER BY scans_per_day")
    return {"tiers": [dict(r) for r in rows]}


@router.get("/scans")
async def all_scans(
    limit: int = 50,
    current_user: dict = Depends(admin_only)
):
    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")
    async with pool.acquire() as c:
        rows = await c.fetch(
            """SELECT sh.*, u.username, u.tier
               FROM scan_history sh JOIN users u ON sh.user_id=u.user_id
               ORDER BY sh.created_at DESC LIMIT $1""",
            limit
        )
    return {"scans": [dict(r) for r in rows], "total": len(rows)}


# ── NEW: Payment history endpoint for admin panel ─────────────────────────────
@router.get("/payments")
async def list_payments(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
    current_user: dict = Depends(admin_only)
):
    """All payment transactions — shown in admin panel payments tab."""
    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")

    try:
        async with pool.acquire() as c:
            # Check if payments table exists
            exists = await c.fetchval(
                "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='payments')"
            )
            if not exists:
                return {"payments": [], "total": 0, "note": "payments table not yet created"}

            where_clause = "WHERE p.status = $3" if status else ""
            params = [limit, offset, status] if status else [limit, offset]

            rows = await c.fetch(
                f"""SELECT p.payment_id, p.order_id, p.user_id, p.tier,
                           p.amount, p.status, p.paid_at,
                           u.username, u.email
                    FROM payments p
                    LEFT JOIN users u ON p.user_id = u.user_id
                    {where_clause}
                    ORDER BY p.paid_at DESC NULLS LAST
                    LIMIT $1 OFFSET $2""",
                *params
            )
            total_params = [status] if status else []
            where_total  = "WHERE status = $1" if status else ""
            total = await c.fetchval(
                f"SELECT COUNT(*) FROM payments {where_total}",
                *total_params
            )

        return {
            "payments": [dict(r) for r in rows],
            "total":    total,
        }

    except Exception as e:
        logger.error(f"Admin payments query failed: {e}")
        # Return empty gracefully rather than 500 — payments table may not exist yet
        return {"payments": [], "total": 0, "error": str(e)}
