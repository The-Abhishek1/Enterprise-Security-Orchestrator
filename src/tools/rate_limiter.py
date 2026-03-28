# src/tools/rate_limiter.py
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import asyncio
import time

from src.core.config import get_settings
from src.core.exceptions import RateLimitExceededError
from src.utils.logging import logger

settings = get_settings()


class TokenBucket:
    """Token bucket algorithm for rate limiting"""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """Consume tokens from bucket"""
        
        async with self.lock:
            # Refill tokens
            now = time.time()
            time_passed = now - self.last_refill
            self.tokens = min(
                self.capacity,
                self.tokens + time_passed * self.rate
            )
            self.last_refill = now
            
            # Check if we can consume
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False


class ToolRateLimiter:
    """
    Enterprise Rate Limiter for Tools
    
    Features:
    - Per-user, per-tenant, per-tool limits
    - Token bucket algorithm
    - Distributed rate limiting with Redis (optional)
    """
    
    def __init__(self):
        self.redis = None
        self._connect_redis()
        
        # Local rate limiters (for development)
        self.local_limiters: Dict[str, TokenBucket] = {}
        
        # Rate limit configurations
        self.limits: Dict[str, Dict] = {}
        
        logger.info("✅ Tool Rate Limiter initialized")
    
    def _connect_redis(self):
        """Connect to Redis for distributed rate limiting"""
        try:
            from src.core.database import db_manager
            self.redis = db_manager.redis_client
            if self.redis:
                logger.info("✅ Rate limiter using Redis")
        except Exception as e:
            logger.warning(f"Redis not available for rate limiting: {e}")
    
    async def configure_limit(
        self,
        key: str,
        rate: float,
        capacity: int,
        scope: str = "global"
    ):
        """Configure rate limit"""
        
        self.limits[key] = {
            "rate": rate,
            "capacity": capacity,
            "scope": scope
        }
    
    async def check_limits(
        self,
        user_id: str,
        tenant_id: str,
        tools: List[Dict]
    ):
        """Check all applicable rate limits"""
        
        for tool in tools:
            tool_name = tool["name"]
            
            # Check global tool limit
            await self._check_limit(
                key=f"tool:global:{tool_name}",
                user_id=user_id,
                tenant_id=tenant_id,
                tool=tool
            )
            
            # Check tenant tool limit
            await self._check_limit(
                key=f"tool:tenant:{tenant_id}:{tool_name}",
                user_id=user_id,
                tenant_id=tenant_id,
                tool=tool
            )
            
            # Check user tool limit
            await self._check_limit(
                key=f"tool:user:{user_id}:{tool_name}",
                user_id=user_id,
                tenant_id=tenant_id,
                tool=tool
            )
    
    async def _check_limit(
        self,
        key: str,
        user_id: str,
        tenant_id: str,
        tool: Dict
    ):
        """Check a specific rate limit"""
        
        # Get limit configuration
        limit_config = await self._get_limit_config(key, tool)
        if not limit_config:
            return
        
        # Check limit
        if self.redis:
            # Distributed rate limiting with Redis
            allowed = await self._check_redis_limit(
                key=key,
                rate=limit_config["rate"],
                capacity=limit_config["capacity"]
            )
        else:
            # Local rate limiting
            allowed = await self._check_local_limit(
                key=key,
                rate=limit_config["rate"],
                capacity=limit_config["capacity"]
            )
        
        if not allowed:
            raise RateLimitExceededError(
                message=f"Rate limit exceeded for {key}",
                retry_after=int(1 / limit_config["rate"]) if limit_config["rate"] > 0 else 60
            )
    
    async def _get_limit_config(self, key: str, tool: Dict) -> Optional[Dict]:
        """Get rate limit configuration"""
        
        # Check if configured
        if key in self.limits:
            return self.limits[key]
        
        # Use tool defaults
        tool_limits = tool.get("rate_limits", {})
        
        # Determine limit based on key pattern
        if "global" in key:
            limit_str = tool_limits.get("global", "100/minute")
        elif "tenant" in key:
            limit_str = tool_limits.get("tenant", "50/minute")
        elif "user" in key:
            limit_str = tool_limits.get("user", "10/minute")
        else:
            limit_str = "100/minute"
        
        # Parse limit string
        return self._parse_limit(limit_str)
    
    def _parse_limit(self, limit_str: str) -> Dict:
        """Parse limit string like '100/minute'"""
        
        try:
            count, period = limit_str.split("/")
            count = int(count)
            
            # Convert period to seconds
            period_seconds = {
                "second": 1,
                "minute": 60,
                "hour": 3600,
                "day": 86400
            }.get(period, 60)
            
            # Calculate rate (tokens per second) and capacity
            rate = count / period_seconds
            capacity = count  # Allow full burst
            
            return {
                "rate": rate,
                "capacity": capacity
            }
        except:
            # Default
            return {
                "rate": 100 / 60,  # 100 per minute
                "capacity": 100
            }
    
    async def _check_redis_limit(
        self,
        key: str,
        rate: float,
        capacity: int
    ) -> bool:
        """Check rate limit using Redis with token bucket"""
        
        redis_key = f"ratelimit:{key}"
        now = time.time()
        
        # Get current bucket state
        bucket = await self.redis.hgetall(redis_key)
        
        if bucket:
            tokens = float(bucket.get(b'tokens', capacity))
            last_refill = float(bucket.get(b'last_refill', now))
        else:
            tokens = capacity
            last_refill = now
        
        # Refill tokens
        time_passed = now - last_refill
        tokens = min(capacity, tokens + time_passed * rate)
        
        # Check if we can consume
        if tokens >= 1:
            tokens -= 1
            # Store updated bucket
            await self.redis.hmset(redis_key, {
                "tokens": tokens,
                "last_refill": now
            })
            await self.redis.expire(redis_key, 3600)  # 1 hour TTL
            return True
        
        return False
    
    async def _check_local_limit(
        self,
        key: str,
        rate: float,
        capacity: int
    ) -> bool:
        """Check rate limit using local token bucket"""
        
        if key not in self.local_limiters:
            self.local_limiters[key] = TokenBucket(rate, capacity)
        
        return await self.local_limiters[key].consume()
    
    async def get_remaining(self, key: str) -> int:
        """Get remaining tokens for key"""
        
        if self.redis:
            bucket = await self.redis.hgetall(f"ratelimit:{key}")
            if bucket:
                return int(float(bucket.get(b'tokens', 0)))
        
        return 0
    
    async def reset_limit(self, key: str):
        """Reset rate limit for key"""
        
        if self.redis:
            await self.redis.delete(f"ratelimit:{key}")
        else:
            self.local_limiters.pop(key, None)