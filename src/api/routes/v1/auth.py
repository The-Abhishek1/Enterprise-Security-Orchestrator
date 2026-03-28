# src/api/routes/v1/auth.py

"""
Authentication routes — register, login, token refresh, API keys, scan history.
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

from src.api.dependencies import get_current_user, auth_service
from src.services.user_service import user_service
from src.utils.logging import logger

router = APIRouter(prefix="/auth", tags=["authentication"])


# ========================================================
# Request/Response models
# ========================================================

class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class CreateAPIKeyRequest(BaseModel):
    name: str
    permissions: Optional[List[str]] = None
    expires_days: Optional[int] = None

class RevokeAPIKeyRequest(BaseModel):
    key_id: str


# ========================================================
# Registration & Login
# ========================================================

@router.post("/register")
async def register(req: RegisterRequest):
    """Register a new user account."""
    
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    
    if len(req.username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    
    try:
        user = await user_service.register(
            email=req.email,
            username=req.username,
            password=req.password
        )
        
        # Generate tokens
        token_data = {"sub": user["user_id"], "email": user["email"], "role": user["role"]}
        access_token = auth_service.create_access_token(token_data)
        refresh_token = auth_service.create_refresh_token(token_data)
        
        return {
            "user": user,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
        
    except Exception as e:
        if "already exists" in str(e):
            raise HTTPException(409, str(e))
        logger.error(f"Registration failed: {e}")
        raise HTTPException(500, "Registration failed")


@router.post("/login")
async def login(req: LoginRequest):
    """Login and get JWT tokens."""
    
    user = await user_service.login(req.email, req.password)
    
    if not user:
        raise HTTPException(401, "Invalid email or password")
    
    token_data = {
        "sub": user["user_id"],
        "email": user["email"],
        "role": user["role"],
        "tenant_id": user["tenant_id"]
    }
    access_token = auth_service.create_access_token(token_data)
    refresh_token = auth_service.create_refresh_token(token_data)
    
    return {
        "user": user,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh")
async def refresh_token(request: Request):
    """Refresh access token using refresh token."""
    
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Refresh token required")
    
    token = auth_header.replace("Bearer ", "")
    
    try:
        payload = auth_service.verify_token(token, token_type="refresh")
        
        new_token_data = {
            "sub": payload["sub"],
            "email": payload.get("email", ""),
            "role": payload.get("role", "user"),
            "tenant_id": payload.get("tenant_id", "default")
        }
        
        access_token = auth_service.create_access_token(new_token_data)
        
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
    except Exception as e:
        raise HTTPException(401, f"Invalid refresh token: {e}")


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile."""
    
    user = await user_service.get_user(current_user["sub"])
    if not user:
        # Dev mode fallback
        return current_user
    
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "username": user["username"],
        "role": user["role"],
        "tenant_id": user["tenant_id"],
        "created_at": user["created_at"]
    }


# ========================================================
# API Keys
# ========================================================

@router.post("/api-keys")
async def create_api_key(req: CreateAPIKeyRequest, current_user: dict = Depends(get_current_user)):
    """Create a new API key. The key is shown ONCE — save it."""
    
    result = await user_service.create_api_key(
        user_id=current_user["sub"],
        name=req.name,
        permissions=req.permissions,
        expires_days=req.expires_days
    )
    
    return result


@router.get("/api-keys")
async def list_api_keys(current_user: dict = Depends(get_current_user)):
    """List your API keys (keys are masked)."""
    
    keys = await user_service.list_api_keys(current_user["sub"])
    return {"api_keys": keys}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: dict = Depends(get_current_user)):
    """Revoke an API key."""
    
    revoked = await user_service.revoke_api_key(key_id, current_user["sub"])
    
    if not revoked:
        raise HTTPException(404, "API key not found")
    
    return {"message": "API key revoked", "key_id": key_id}


# ========================================================
# Scan History
# ========================================================

@router.get("/scans")
async def list_scans(
    limit: int = 20,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """List your scan history."""
    
    scans = await user_service.get_scans(current_user["sub"], limit, offset)
    total = await user_service.get_scan_count(current_user["sub"])
    
    return {
        "scans": scans,
        "total": total,
        "limit": limit,
        "offset": offset
    }


@router.get("/scans/{process_id}")
async def get_scan(process_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific scan with full report."""
    
    scan = await user_service.get_scan(process_id, current_user["sub"])
    
    if not scan:
        raise HTTPException(404, "Scan not found")
    
    return scan
