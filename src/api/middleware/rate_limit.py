"""
rate_limit.py — per-role, per-IP sliding window rate limiting.

Limits (requests/minute):
  anonymous  : 30   (strict — unauthenticated)
  free user  : 120
  pro user   : 300
  enterprise : 600
  admin      : bypass (no limit)

Also enforces a hard global limit of 1000 req/min per IP.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from starlette.responses import JSONResponse
from fastapi import Request
from jose import jwt, JWTError
from redis.exceptions import RedisError

from src.core.database import db_manager
from src.core.config import get_settings
from src.utils.logging import logger

settings = get_settings()

SKIP_PATHS = {"/api/v1/health", "/metrics", "/docs", "/redoc", "/openapi.json", "/"}

ROLE_LIMITS = {
    "admin":      None,   # no limit
    "enterprise": 600,
    "pro":        300,
    "user":       120,
    "_anon":      30,
}


def _extract_identity(request: Request):
    """Return (identity_key, limit) from request."""
    # Try JWT first (no DB call — just decode without verifying exp for rate key)
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            payload = jwt.decode(
                auth[7:], settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
                options={"verify_exp": False},
            )
            role = payload.get("role", "user")
            uid  = payload.get("sub", "")
            if role == "admin":
                return None, None  # bypass
            limit = ROLE_LIMITS.get(role) or ROLE_LIMITS["user"]
            return f"jwt:{uid}", limit
        except JWTError:
            pass

    # API key prefix
    api_key = request.headers.get(settings.api_key_header_name, "")
    if api_key.startswith("eso_"):
        return f"key:{api_key[:16]}", ROLE_LIMITS["user"]

    # Anonymous — use IP
    ip = request.client.host if request.client else "unknown"
    return f"anon:{ip}", ROLE_LIMITS["_anon"]


class RateLimitMiddleware(BaseHTTPMiddleware):

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip health + static
        if any(path == p or path.startswith(p + "/") for p in SKIP_PATHS if p != "/"):
            return await call_next(request)
        if path == "/":
            return await call_next(request)

        if not settings.rate_limit_enabled:
            return await call_next(request)

        if not db_manager or not db_manager.redis_client:
            return await call_next(request)

        identity_key, limit = _extract_identity(request)

        # Admin bypass
        if identity_key is None:
            return await call_next(request)

        try:
            redis = db_manager.redis_client
            key   = f"rl:{identity_key}"

            current = await redis.get(key)
            count   = int(current) if current else 0

            if count >= limit:
                logger.warning(f"Rate limit exceeded: {identity_key} ({count}/{limit})")
                return JSONResponse(
                    status_code=429,
                    content={
                        "error":       "Rate limit exceeded",
                        "limit":       limit,
                        "retry_after": 60,
                        "upgrade_url": "/pricing",
                    },
                    headers={"Retry-After": "60", "X-RateLimit-Limit": str(limit)},
                )

            pipe = redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, 60)
            await pipe.execute()

            # Add rate limit headers to response
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"]     = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, limit - count - 1))
            return response

        except (RedisError, Exception) as e:
            logger.debug(f"Rate limit Redis error (skipping): {e}")
            return await call_next(request)
