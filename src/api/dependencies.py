# src/api/dependencies.py
from fastapi import Request, HTTPException, Depends
from typing import Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
from jose import JWTError, jwt

from src.core.config import get_settings
from src.core.exceptions import AuthenticationError, AuthorizationError
from src.utils.logging import logger

settings = get_settings()


class AuthService:
    """Authentication and authorization service"""
    
    def __init__(self):
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire = settings.jwt_access_token_expire_minutes
        self.refresh_token_expire = settings.jwt_refresh_token_expire_days
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire)
        to_encode.update({"exp": expire, "type": "access"})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire)
        to_encode.update({"exp": expire, "type": "refresh"})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            if payload.get("type") != token_type:
                raise AuthenticationError(f"Invalid token type")
            return payload
        except JWTError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Verify API key — delegates to user_service for DB lookup (sync wrapper)."""
        # This is called from the async get_current_user below
        # The actual DB check happens in the async path
        if api_key and api_key.startswith("eso_"):
            return {"_pending_api_key": api_key}
        return None


auth_service = AuthService()


class RateLimiter:
    """Rate limiter using Redis"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def check_rate_limit(
        self,
        key: str,
        limit: int = 100,
        window: int = 60
    ) -> bool:
        """Check if request is within rate limit"""
        
        if not settings.rate_limit_enabled:
            return True
        
        current = await self.redis.get(f"ratelimit:{key}")
        
        if current and int(current) >= limit:
            return False
        
        pipe = self.redis.pipeline()
        pipe.incr(f"ratelimit:{key}")
        pipe.expire(f"ratelimit:{key}", window)
        await pipe.execute()
        
        return True


async def get_current_user(
    request: Request,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """Get current authenticated user from JWT or API key."""
    
    # Check for JWT token in Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
        try:
            payload = auth_service.verify_token(token)
            request.state.user = payload
            return payload
        except Exception as e:
            logger.warning(f"JWT verification failed: {e}")
    
    # Check for API key in header
    api_key_header = request.headers.get(settings.api_key_header_name)
    if api_key_header and api_key_header.startswith("eso_"):
        try:
            from src.services.user_service import user_service
            user = await user_service.verify_api_key(api_key_header)
            if user:
                request.state.user = user
                return user
        except Exception as e:
            logger.warning(f"API key verification failed: {e}")
    
    # For development, return mock user
    if settings.environment.value == "development":
        mock_user = {
            "sub": "dev_user_123",
            "email": "dev@example.com",
            "tenant_id": "default",
            "permissions": ["read", "write", "execute"],
            "roles": ["admin"]
        }
        request.state.user = mock_user
        return mock_user
    
    raise AuthenticationError("No valid authentication provided")


async def get_tenant_id(request: Request) -> str:
    """Get tenant ID from request"""
    
    # Check header
    tenant_id = request.headers.get("X-Tenant-ID")
    if tenant_id:
        return tenant_id
    
    # Check from user
    if hasattr(request.state, "user"):
        return request.state.user.get("tenant_id", "default")
    
    return "default"


async def get_request_id(request: Request) -> str:
    """Get or generate request ID"""
    
    request_id = request.headers.get("X-Request-ID")
    if not request_id:
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        request.state.request_id = request_id
    return request_id


def require_permission(permission: str):
    """Decorator to require specific permission"""
    
    async def dependency(current_user: Dict = Depends(get_current_user)):
        if permission not in current_user.get("permissions", []):
            raise AuthorizationError(f"Permission required: {permission}")
        return current_user
    
    return dependency