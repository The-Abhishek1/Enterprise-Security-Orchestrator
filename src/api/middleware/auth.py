# src/api/middleware/auth.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request
from src.api.dependencies import get_current_user
from src.utils.logging import logger


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware to authenticate requests"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next):
        # Skip auth for public endpoints
        public_paths = ["/", "/docs", "/redoc", "/openapi.json", "/api/v1/health"]
        if any(request.url.path.startswith(path) for path in public_paths):
            return await call_next(request)
        
        # Only try to authenticate if user not already set by dependency
        if not hasattr(request.state, "user"):
            try:
                # Try to authenticate
                user = await get_current_user(request)
                request.state.user = user
            except Exception as e:
                logger.debug(f"Authentication failed: {e}")
                # Continue without user - the endpoint will handle auth
        
        return await call_next(request)