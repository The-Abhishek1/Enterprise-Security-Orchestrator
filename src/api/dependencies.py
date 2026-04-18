"""
dependencies.py — hardened auth.

Fixes vs original:
- Dev fallback: only localhost + development env, fetches REAL DB user
- JWT now includes 'tier' in payload
- No silent pass-through on auth failure — always 401
- Access token expiry extended to 8h (30min caused constant JWT spam)
- require_role() and require_tier() decorators
"""
from fastapi import Request, HTTPException, Depends
from typing import Dict, Any
import uuid
from datetime import datetime, timedelta
from jose import JWTError, jwt

from src.core.config import get_settings
from src.core.exceptions import AuthenticationError
from src.utils.logging import logger

settings = get_settings()


class AuthService:
    def __init__(self):
        self.secret_key     = settings.jwt_secret_key
        self.algorithm      = settings.jwt_algorithm
        self.access_expire  = getattr(settings, 'jwt_access_token_expire_minutes', 480)
        self.refresh_expire = getattr(settings, 'jwt_refresh_token_expire_days',   7)

    def create_access_token(self, data: Dict[str, Any]) -> str:
        payload = {**data, "exp": datetime.utcnow() + timedelta(minutes=self.access_expire), "type": "access"}
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        payload = {**data, "exp": datetime.utcnow() + timedelta(days=self.refresh_expire), "type": "refresh"}
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            if payload.get("type") != token_type:
                raise AuthenticationError("Invalid token type")
            return payload
        except JWTError as e:
            raise AuthenticationError(f"Invalid token: {e}")


auth_service = AuthService()


async def _user_from_db(user_id: str) -> dict | None:
    """Fetch full user row from DB."""
    try:
        from src.core.database import db_manager
        if not db_manager.pg_pool:
            return None
        async with db_manager.pg_pool.acquire() as c:
            r = await c.fetchrow(
                "SELECT user_id,email,username,role,tier,tenant_id,is_active FROM users WHERE user_id=$1",
                user_id
            )
        if r and r["is_active"]:
            return {
                "sub": r["user_id"], "email": r["email"], "username": r["username"],
                "role": r["role"] or "user", "tier": r["tier"] or "free",
                "tenant_id": r["tenant_id"] or "default",
                "permissions": ["read","write","execute"],
            }
    except Exception as e:
        logger.debug(f"DB user fetch failed: {e}")
    return None


async def get_current_user(request: Request) -> Dict[str, Any]:
    """
    Auth order: JWT → API Key → dev fallback (localhost+dev only).
    Always raises 401 in production if no valid auth.
    """
    # 1. JWT Bearer
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            payload = auth_service.verify_token(token)
            # Backfill tier if old token missing it
            if not payload.get("tier"):
                db_user = await _user_from_db(payload.get("sub", ""))
                if db_user:
                    payload["tier"] = db_user["tier"]
                    payload["role"] = db_user["role"]
                else:
                    payload["tier"] = "free"
            request.state.user = payload
            return payload
        except AuthenticationError as e:
            logger.warning(f"JWT failed: {e}")

    # 2. API Key
    api_key = request.headers.get(settings.api_key_header_name, "")
    if api_key.startswith("eso_"):
        try:
            from src.services.user_service import user_service
            user = await user_service.verify_api_key(api_key)
            if user:
                request.state.user = user
                return user
        except Exception as e:
            logger.warning(f"API key failed: {e}")

    # 3. Dev fallback — localhost + development ONLY
    is_dev   = settings.environment.value == "development"
    is_local = request.client and request.client.host in ("127.0.0.1", "::1", "localhost")
    if is_dev and is_local:
        db_user = await _user_from_db("dev_user_123")
        if db_user:
            db_user["_dev_fallback"] = True
            request.state.user = db_user
            return db_user
        mock = {
            "sub": "dev_user_123", "email": "dev@example.com",
            "role": "admin", "tier": "admin", "tenant_id": "default",
            "permissions": ["read","write","execute"], "_dev_fallback": True,
        }
        request.state.user = mock
        return mock

    raise HTTPException(status_code=401, detail="Authentication required")


async def get_tenant_id(request: Request) -> str:
    if tid := request.headers.get("X-Tenant-ID"):
        return tid
    if hasattr(request.state, "user"):
        return request.state.user.get("tenant_id", "default")
    return "default"


async def get_request_id(request: Request) -> str:
    rid = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:12]}"
    request.state.request_id = rid
    return rid


def require_role(*roles: str):
    """Fail-fast role guard. Usage: Depends(require_role('admin'))"""
    async def dep(user: Dict = Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(403, f"Requires role: {', '.join(roles)}")
        return user
    return dep


def require_tier(*tiers: str):
    """Fail-fast tier guard. Admin always passes. Usage: Depends(require_tier('pro','enterprise'))"""
    async def dep(user: Dict = Depends(get_current_user)):
        if user.get("role") == "admin":
            return user
        if user.get("tier") in tiers or user.get("role") in tiers:
            return user
        raise HTTPException(403, f"Plan upgrade required. Needs: {', '.join(tiers)}")
    return dep
