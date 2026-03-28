# src/api/middleware/audit.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request, Response
import time
import json

from src.services.audit import audit_logger
from src.utils.logging import logger


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware to audit all requests"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next):
        # Skip audit for health checks and metrics
        if request.url.path in ["/api/v1/health", "/api/v1/health/ready", "/api/v1/health/live", "/metrics"]:
            return await call_next(request)
        
        # Clone the request body for audit (without consuming it)
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                # Get the body without consuming it
                body_bytes = await request.body()
                if body_bytes:
                    # Try to decode as JSON for logging
                    try:
                        body = json.loads(body_bytes)
                    except:
                        body = body_bytes.decode("utf-8", errors="ignore")[:500]
                    
                    # CRITICAL: Reset the request body so FastAPI can read it again
                    async def receive():
                        return {"type": "http.request", "body": body_bytes}
                    request._receive = receive
            except Exception as e:
                logger.debug(f"Could not read request body for audit: {e}")
                body = None
        
        start_time = time.time()
        
        # Process request
        response = await call_next(request)
        
        duration = time.time() - start_time
        
        # Log to audit (fire and forget - don't await)
        import asyncio
        asyncio.create_task(
            audit_logger.log(
                action=f"{request.method} {request.url.path}",
                user_id=getattr(request.state, "user", {}).get("sub", "anonymous"),
                tenant_id=request.headers.get("X-Tenant-ID", "default"),
                resource_type="api",
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "query_params": str(request.query_params),
                    "body_preview": body if body else None,
                    "status_code": response.status_code,
                    "duration_seconds": duration,
                    "ip": request.client.host if request.client else None,
                    "user_agent": request.headers.get("user-agent")
                },
                status="success" if response.status_code < 400 else "error"
            )
        )
        
        return response