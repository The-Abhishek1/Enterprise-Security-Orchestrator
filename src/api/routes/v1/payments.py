"""
payments.py - Razorpay integration for XCloak tier upgrades.

Root-cause fix: RAZORPAY_KEY_ID/SECRET are now declared in pydantic Settings
so pydantic-settings loads them from .env automatically.
os.getenv() does NOT read .env unless python-dotenv is explicitly called.
"""
import hashlib
import hmac
import uuid

import aiohttp
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from src.api.dependencies import get_current_user
from src.core.config import get_settings
from src.services.user_service import user_service
from src.utils.logging import logger

router = APIRouter(prefix="/payments", tags=["payments"])

RZP_BASE_URL = "https://api.razorpay.com/v1"

TIER_PRICES = {
    "pro": {
        "amount": 99900,
        "currency": "INR",
        "description": "XCloak Pro - 20 scans/day, AI analysis, PDF reports",
    },
    "enterprise": {
        "amount": 499900,
        "currency": "INR",
        "description": "XCloak Enterprise - 100 scans/day, all tools, teams",
    },
}

TIER_RANK = {"free": 0, "pro": 1, "enterprise": 2, "admin": 3}


def _get_key_id():
    return get_settings().razorpay_key_id.strip(" '\"")


def _get_key_secret():
    return get_settings().razorpay_key_secret.strip(" '\"")


class CreateOrderRequest(BaseModel):
    tier: str


class VerifyPaymentRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    tier: str


async def _rzp_post(path: str, payload: dict) -> dict:
    key_id = _get_key_id()
    key_secret = _get_key_secret()

    if not key_id or not key_secret:
        logger.error(
            "Razorpay keys missing. key_id=%r, secret_len=%d. "
            "Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to .env",
            key_id, len(key_secret)
        )
        raise HTTPException(
            500,
            "Razorpay credentials not configured. "
            "Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in .env"
        )

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{RZP_BASE_URL}{path}",
                json=payload,
                auth=aiohttp.BasicAuth(key_id, key_secret),
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json()
                if resp.status not in (200, 201):
                    error_msg = data.get("error", {}).get("description", "Razorpay error")
                    logger.error("Razorpay API %d: %s", resp.status, data)
                    raise HTTPException(502, f"Payment gateway error: {error_msg}")
                return data
    except HTTPException:
        raise
    except aiohttp.ClientError as e:
        logger.error("Razorpay connection failed: %s", e)
        raise HTTPException(502, f"Could not reach Razorpay: {e}")


def _verify_signature(order_id: str, payment_id: str, signature: str) -> bool:
    payload_str = f"{order_id}|{payment_id}"
    expected = hmac.new(
        _get_key_secret().encode("utf-8"),
        payload_str.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/create-order")
async def create_order(
    req: CreateOrderRequest,
    current_user: dict = Depends(get_current_user),
):
    tier = req.tier.lower().strip()
    if tier not in TIER_PRICES:
        raise HTTPException(400, f"Invalid tier '{tier}'. Choose: pro, enterprise")

    plan = TIER_PRICES[tier]
    current_tier = current_user.get("tier", "free")

    if TIER_RANK.get(current_tier, 0) >= TIER_RANK.get(tier, 0):
        raise HTTPException(400, f"You are already on the {current_tier} plan")

    receipt = f"xcloak_{current_user['sub'][:12]}_{tier}_{uuid.uuid4().hex[:8]}"

    order = await _rzp_post("/orders", {
        "amount": plan["amount"],
        "currency": plan["currency"],
        "receipt": receipt,
        "notes": {
            "user_id": current_user["sub"],
            "username": current_user.get("username", ""),
            "tier": tier,
        },
    })

    logger.info("Payment order %s created — user %s -> %s", order["id"], current_user["sub"], tier)

    return {
        "order_id": order["id"],
        "amount": plan["amount"],
        "currency": plan["currency"],
        "description": plan["description"],
        "key_id": _get_key_id(),
        "tier": tier,
    }


@router.post("/verify")
async def verify_payment(
    req: VerifyPaymentRequest,
    current_user: dict = Depends(get_current_user),
):
    tier = req.tier.lower().strip()
    if tier not in TIER_PRICES:
        raise HTTPException(400, "Invalid tier")

    if not _verify_signature(req.razorpay_order_id, req.razorpay_payment_id, req.razorpay_signature):
        logger.warning("Invalid payment signature for user %s", current_user["sub"])
        raise HTTPException(400, "Payment signature verification failed")

    user_id = current_user["sub"]
    success = await user_service.update_tier(user_id, tier)
    if not success:
        raise HTTPException(500, "Failed to upgrade tier - contact support")

    try:
        from src.core.database import db_manager
        if db_manager.pg_pool:
            async with db_manager.pg_pool.acquire() as c:
                await c.execute(
                    """INSERT INTO payments
                       (payment_id, order_id, user_id, tier, amount, status, paid_at)
                       VALUES ($1, $2, $3, $4, $5, 'captured', NOW())
                       ON CONFLICT (payment_id) DO NOTHING""",
                    req.razorpay_payment_id,
                    req.razorpay_order_id,
                    user_id,
                    tier,
                    TIER_PRICES[tier]["amount"],
                )
    except Exception as e:
        logger.warning("Payment log insert failed (non-critical): %s", e)

    logger.info("Payment verified - user %s upgraded to %s", user_id, tier)

    # Send payment confirmation email
    try:
        from src.services.email_service import send_payment_confirmed
        async with pool.acquire() as conn:
            u = await conn.fetchrow("SELECT email, username FROM users WHERE user_id=$1", user_id)
        if u and u["email"]:
            await send_payment_confirmed(
                u["email"], u["username"], tier,
                TIER_PRICES[tier]["amount"], req.razorpay_payment_id
            )
    except Exception as e:
        logger.warning("Payment email failed (non-critical): %s", e)

    return {
        "success": True,
        "tier": tier,
        "message": f"Upgraded to {tier.capitalize()} successfully!",
        "payment_id": req.razorpay_payment_id,
    }


@router.get("/status")
async def payment_status(current_user: dict = Depends(get_current_user)):
    user_id = current_user["sub"]
    current_tier = current_user.get("tier", "free")
    cur_rank = TIER_RANK.get(current_tier, 0)

    payments = []
    try:
        from src.core.database import db_manager
        if db_manager.pg_pool:
            async with db_manager.pg_pool.acquire() as c:
                rows = await c.fetch(
                    "SELECT payment_id, order_id, tier, amount, status, paid_at "
                    "FROM payments WHERE user_id = $1 ORDER BY paid_at DESC LIMIT 5",
                    user_id,
                )
                payments = [dict(r) for r in rows]
    except Exception:
        pass

    upgrades = [
        {
            "tier": t,
            "amount": info["amount"],
            "currency": info["currency"],
            "amount_inr": info["amount"] // 100,
            "description": info["description"],
        }
        for t, info in TIER_PRICES.items()
        if TIER_RANK.get(t, 0) > cur_rank
    ]

    return {
        "current_tier": current_tier,
        "available_upgrades": upgrades,
        "payment_history": payments,
    }
