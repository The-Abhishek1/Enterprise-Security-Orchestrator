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
from datetime import datetime
import re

from src.api.dependencies import get_current_user, auth_service
from src.services.user_service import user_service
from src.utils.logging import logger

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


@router.get("/findings/{process_id}")
async def get_findings_for_scan(process_id: str, current_user: dict = Depends(get_current_user)):
    return {"findings": await user_service.get_findings(process_id, current_user["sub"])}


@router.get("/findings/stats")
async def finding_stats(current_user: dict = Depends(get_current_user)):
    return await user_service.get_finding_stats(current_user["sub"])
