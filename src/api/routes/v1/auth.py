"""
auth.py — hardened authentication routes.

Fixes vs original:
- login() returns tier in user object AND in JWT payload
- register() validates email/username/password strictly
- Brute-force lockout errors surfaced as 429 (not 401)
- /me fetches fresh tier from DB on every call
- JWT expiry extended (configured in dependencies.py)
- All scan/finding queries are user-isolated
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime, timedelta
import re

from src.api.dependencies import get_current_user, auth_service
from src.services.user_service import user_service
from src.utils.logging import logger
from src.core.database import db_manager

router = APIRouter(prefix="/auth", tags=["authentication"])


# ── request models ─────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email:    str
    username: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        v = v.strip().lower()
        if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError("Invalid email format")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_\-\.]{3,32}$', v):
            raise ValueError("Username: 3-32 chars, letters/numbers/_ - .")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    email:    str
    password: str

class CreateAPIKeyRequest(BaseModel):
    name:         str
    permissions:  Optional[List[str]] = None
    expires_days: Optional[int]       = None


# ── register ────────────────────────────────────────────────────────────────
@router.post("/register")
async def register(req: RegisterRequest):
    try:
        user = await user_service.register(
            email=req.email, username=req.username, password=req.password
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        if "already exists" in str(e).lower():
            raise HTTPException(409, "Email or username already taken")
        logger.error(f"Registration failed: {e}")
        raise HTTPException(500, "Registration failed")

    # Send welcome email (non-blocking)
    try:
        from src.services.email_service import send_welcome
        await send_welcome(req.email, req.username)
    except Exception as e:
        logger.warning("Welcome email failed (non-critical): %s", e)

    token_data = {
        "sub":       user["user_id"],
        "email":     user["email"],
        "role":      user["role"],
        "tier":      user["tier"],          # ← tier in JWT
        "tenant_id": user.get("tenant_id", "default"),
    }
    return {
        "user":          user,
        "access_token":  auth_service.create_access_token(token_data),
        "refresh_token": auth_service.create_refresh_token(token_data),
        "token_type":    "bearer",
    }


# ── login ───────────────────────────────────────────────────────────────────
@router.post("/login")
async def login(req: LoginRequest):
    try:
        user = await user_service.login(
            email=req.email.strip().lower(), password=req.password
        )
    except Exception as e:
        msg = str(e)
        if "locked" in msg:
            raise HTTPException(429, msg)
        if "disabled" in msg:
            raise HTTPException(403, msg)
        raise HTTPException(500, "Login error")

    if not user:
        raise HTTPException(401, "Invalid email or password")

    token_data = {
        "sub":       user["user_id"],
        "email":     user["email"],
        "role":      user["role"],
        "tier":      user["tier"],          # ← tier in JWT
        "tenant_id": user.get("tenant_id", "default"),
    }
    return {
        "user":          user,
        "access_token":  auth_service.create_access_token(token_data),
        "refresh_token": auth_service.create_refresh_token(token_data),
        "token_type":    "bearer",
    }


# ── refresh ─────────────────────────────────────────────────────────────────
@router.post("/refresh")
async def refresh_token(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Refresh token required")
    token = auth_header[7:]
    try:
        payload = auth_service.verify_token(token, token_type="refresh")
    except Exception:
        raise HTTPException(401, "Invalid or expired refresh token")

    # Fetch fresh user from DB to get current tier/role
    user = await user_service.get_user(payload.get("sub", ""))
    if not user or not user.get("is_active", True):
        raise HTTPException(401, "User not found or deactivated")

    token_data = {
        "sub":       user["user_id"],
        "email":     user["email"],
        "role":      user["role"],
        "tier":      user.get("tier", "free"),
        "tenant_id": user.get("tenant_id", "default"),
    }
    return {
        "access_token": auth_service.create_access_token(token_data),
        "token_type":   "bearer",
    }


# ── /me — always fresh from DB ──────────────────────────────────────────────
@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Returns the freshest user data from DB — always reflects current tier."""
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid session")

    db_user = await user_service.get_user(user_id)
    if db_user:
        # Normalize: admin role gets admin tier
        if db_user.get("role") == "admin" and db_user.get("tier", "free") == "free":
            db_user["tier"] = "admin"
        # Always include "sub" alias so frontend auth reads user.sub correctly
        db_user.setdefault("sub", db_user.get("user_id", user_id))
        return db_user

    return current_user


# ── API Keys ─────────────────────────────────────────────────────────────────
@router.post("/api-keys")
async def create_api_key(req: CreateAPIKeyRequest, current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("sub")
    role    = current_user.get("role", "user")
    tier    = current_user.get("tier", "free")

    if role != "admin" and tier not in ("pro", "enterprise", "admin"):
        raise HTTPException(403, "API key access requires Pro tier or above.")

    try:
        result = await user_service.create_api_key(
            user_id=user_id, name=req.name,
            permissions=req.permissions, expires_days=req.expires_days,
        )
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error(f"API key creation failed: {e}")
        raise HTTPException(500, "Failed to create API key")


@router.get("/api-keys")
async def list_api_keys(current_user: dict = Depends(get_current_user)):
    keys = await user_service.list_api_keys(current_user["sub"])
    return {"keys": keys}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: dict = Depends(get_current_user)):
    revoked = await user_service.revoke_api_key(key_id, current_user["sub"])
    if not revoked:
        raise HTTPException(404, "API key not found or already revoked")
    return {"status": "revoked"}


# ── Scan history (user-isolated) ─────────────────────────────────────────────
@router.get("/scans")
async def list_scans(
    limit: int = 20, offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    user_id = current_user.get("sub")
    scans   = await user_service.get_scans(user_id, limit, offset)
    total   = await user_service.get_scan_count(user_id)
    return {"scans": scans, "total": total, "limit": limit, "offset": offset}


@router.get("/scans/{process_id}")
async def get_scan(process_id: str, current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("sub")
    role    = current_user.get("role", "user")
    # Admins can see any scan; users only their own
    scan = await user_service.get_scan(process_id, user_id if role != "admin" else None)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


# ── Findings (user-isolated) ──────────────────────────────────────────────────
@router.get("/findings")
async def list_findings(
    severity: Optional[str] = None, source: Optional[str] = None,
    search: Optional[str] = None, port: Optional[int] = None,
    limit: int = 50, offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    return await user_service.search_findings(
        user_id=current_user["sub"],
        severity=severity, source=source, port=port,
        search=search, limit=limit, offset=offset,
    )


@router.get("/findings/stats")
async def finding_stats(current_user: dict = Depends(get_current_user)):
    return await user_service.get_finding_stats(current_user["sub"])


@router.get("/findings/{process_id}")
async def get_findings_for_scan(process_id: str, current_user: dict = Depends(get_current_user)):
    return {"findings": await user_service.get_findings(process_id, current_user["sub"])}


# ── forgot password ──────────────────────────────────────────────────────────
@router.post("/forgot-password")
async def forgot_password(request: Request):
    """Send password reset email. Always returns 200 to prevent enumeration."""
    import os, hmac, hashlib, secrets as sec
    from datetime import datetime, timedelta

    try:
        body = await request.json()
        email = (body.get("email") or "").strip().lower()
        if not email:
            return {"ok": True, "message": "If that email exists, a reset link will be sent."}

        pool = db_manager.pg_pool
        if not pool:
            return {"ok": True}

        async with pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT user_id, username, email FROM users WHERE email=$1", email
            )

        if user:
            token = sec.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            expires = datetime.utcnow() + timedelta(minutes=30)

            async with pool.acquire() as conn:
                await conn.execute(
                    """UPDATE users SET reset_token=$1, reset_token_expires=$2 WHERE user_id=$3""",
                    token_hash, expires, user["user_id"]
                )

            from src.core.config import get_settings as _gs; app_url = _gs().xcloak_url
            reset_url = f"{app_url}/reset-password?token={token}&email={email}"

            # Send email directly via SMTP
            try:
                from src.services.email_service import send_password_reset
                await send_password_reset(email, user["username"], reset_url)
            except Exception as e:
                logger.warning("Email send failed (non-critical): %s", e)

    except Exception as e:
        logger.error("forgot_password error: %s", e)

    return {"ok": True, "message": "If that email exists, a reset link has been sent."}


@router.post("/reset-password")
async def reset_password(request: Request):
    """Verify reset token and update password."""
    import hashlib
    from datetime import datetime

    body = await request.json()
    email    = (body.get("email") or "").strip().lower()
    token    = (body.get("token") or "").strip()
    new_pass = (body.get("password") or "").strip()

    if not all([email, token, new_pass]) or len(new_pass) < 8:
        raise HTTPException(400, "email, token, and password (min 8 chars) required")

    pool = db_manager.pg_pool
    if not pool:
        raise HTTPException(503, "Database unavailable")

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            """SELECT user_id, username, reset_token, reset_token_expires
               FROM users WHERE email=$1""",
            email
        )

    if not user or user["reset_token"] != token_hash:
        raise HTTPException(400, "Invalid or expired reset link")

    if user["reset_token_expires"] and user["reset_token_expires"] < datetime.utcnow():
        raise HTTPException(400, "Reset link has expired — request a new one")

    # Hash new password and clear token
    new_hash = await user_service.hash_password(new_pass)
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE users SET password_hash=$1, reset_token=NULL, reset_token_expires=NULL
               WHERE user_id=$2""",
            new_hash, user["user_id"]
        )

    return {"ok": True, "message": "Password updated successfully"}

