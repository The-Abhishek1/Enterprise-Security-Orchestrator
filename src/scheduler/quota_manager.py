# src/scheduler/quota_manager.py
from typing import Dict, List, Any
from src.utils.logging import logger

class QuotaManager:
    """
    Enterprise Quota Manager
    
    Manages:
    - Concurrent execution limits
    - Rate limits per user/tenant
    - Resource quotas
    - Fair usage enforcement
    """
    
    def __init__(self):
        self.quotas: Dict[str, Dict] = {}
        self.current_usage: Dict[str, int] = {}
        
        logger.info("✅ Quota Manager initialized")
    
    async def check_quota(
        self,
        tenant_id: str,
        user_id: str,
        quota_type: str = "concurrent_executions"
    ) -> bool:
        """Check if user/tenant is within quota"""
        
        # Check tenant quota
        tenant_key = f"tenant:{tenant_id}:{quota_type}"
        tenant_quota = self.quotas.get(tenant_key, {}).get("limit", 5)  # Default 5
        
        tenant_usage = self.current_usage.get(f"tenant:{tenant_id}", 0)
        
        if tenant_usage >= tenant_quota:
            logger.warning(f"Tenant {tenant_id} quota exceeded: {tenant_usage}/{tenant_quota}")
            return False
        
        # Check user quota
        user_key = f"user:{user_id}:{quota_type}"
        user_quota = self.quotas.get(user_key, {}).get("limit", 2)  # Default 2
        
        user_usage = self.current_usage.get(f"user:{user_id}", 0)
        
        if user_usage >= user_quota:
            logger.warning(f"User {user_id} quota exceeded: {user_usage}/{user_quota}")
            return False
        
        return True
    
    async def increment_usage(self, tenant_id: str, user_id: str):
        """Increment usage counters"""
        
        self.current_usage[f"tenant:{tenant_id}"] = self.current_usage.get(f"tenant:{tenant_id}", 0) + 1
        self.current_usage[f"user:{user_id}"] = self.current_usage.get(f"user:{user_id}", 0) + 1
    
    async def decrement_usage(self, tenant_id: str, user_id: str):
        """Decrement usage counters"""
        
        tenant_key = f"tenant:{tenant_id}"
        if tenant_key in self.current_usage:
            self.current_usage[tenant_key] = max(0, self.current_usage[tenant_key] - 1)
        
        user_key = f"user:{user_id}"
        if user_key in self.current_usage:
            self.current_usage[user_key] = max(0, self.current_usage[user_key] - 1)
    
    async def set_quota(
        self,
        entity_type: str,
        entity_id: str,
        quota_type: str,
        limit: int
    ):
        """Set quota for entity"""
        
        key = f"{entity_type}:{entity_id}:{quota_type}"
        
        self.quotas[key] = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "quota_type": quota_type,
            "limit": limit,
            "created_at": datetime.utcnow()
        }
        
        logger.info(f"Set quota {quota_type}={limit} for {entity_type} {entity_id}")
    
    async def get_usage(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        """Get current usage for entity"""
        
        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "concurrent_executions": self.current_usage.get(f"{entity_type}:{entity_id}", 0),
            "quotas": {
                k: v for k, v in self.quotas.items()
                if k.startswith(f"{entity_type}:{entity_id}")
            }
        }