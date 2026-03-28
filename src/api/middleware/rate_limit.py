# src/api/middleware/rate_limit.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request, HTTPException
import time
from redis.exceptions import RedisError

from src.core.database import db_manager
from src.core.config import get_settings

settings = get_settings()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to rate limit requests"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for certain paths
        if request.url.path in ["/api/v1/health", "/metrics", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        if not settings.rate_limit_enabled:
            return await call_next(request)
        
        # Get client identifier
        client_id = request.headers.get("X-API-Key") or request.client.host
        
        if db_manager and db_manager.redis_client:
            try:
                # Check rate limit in Redis
                key = f"ratelimit:{client_id}"
                current = await db_manager.redis_client.get(key)
                
                limit = 100  # Default limit
                
                if current and int(current) >= limit:
                    raise HTTPException(
                        status_code=429,
                        detail="Rate limit exceeded. Please try again later."
                    )
                
                # Increment counter
                pipe = db_manager.redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, 60)  # 60 second window
                await pipe.execute()
                
            except RedisError as e:
                # Log but don't block the request if Redis fails
                import logging
                logging.getLogger(__name__).warning(f"Rate limiting failed: {e}")
        
        return await call_next(request)