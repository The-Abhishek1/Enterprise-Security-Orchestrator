# src/api/middleware/rate_limit.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from starlette.responses import JSONResponse
from fastapi import Request
from redis.exceptions import RedisError

from src.core.database import db_manager
from src.core.config import get_settings

settings = get_settings()


class RateLimitMiddleware(BaseHTTPMiddleware):
    
    SKIP_PREFIXES = ["/api/v1/health", "/api/v1/ui", "/metrics", "/docs", "/redoc", "/openapi.json", "/"]
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path == p or path.startswith(p + "/") for p in self.SKIP_PREFIXES if p != "/"):
            return await call_next(request)
        if path == "/":
            return await call_next(request)
        
        if not settings.rate_limit_enabled:
            return await call_next(request)
        
        client_id = request.headers.get("X-API-Key") or request.client.host
        
        if db_manager and db_manager.redis_client:
            try:
                key = f"ratelimit:{client_id}"
                current = await db_manager.redis_client.get(key)
                if current and int(current) >= 200:
                    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})
                pipe = db_manager.redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, 60)
                await pipe.execute()
            except (RedisError, Exception):
                pass
        
        return await call_next(request)
