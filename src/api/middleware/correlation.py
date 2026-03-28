# src/api/middleware/correlation.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request
import uuid


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Middleware to add correlation ID to requests"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next):
        # Get correlation ID from header or generate new one
        correlation_id = request.headers.get("X-Correlation-ID")
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        
        request.state.correlation_id = correlation_id
        
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        
        return response