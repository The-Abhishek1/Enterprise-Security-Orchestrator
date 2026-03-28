# src/scheduler/budget_tracker.py
from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta
from decimal import Decimal

from src.utils.logging import logger
from src.core.exceptions import BudgetExceededError


class BudgetTracker:
    """
    Enterprise Budget Tracker
    
    Features:
    - Real-time cost tracking
    - Budget enforcement
    - Cost estimation
    - Multi-level budgets (user, tenant, execution)
    - Budget alerts
    """
    
    def __init__(self):
        # Budgets: key = f"{level}:{id}"
        self.budgets: Dict[str, Dict] = {}
        
        # Usage tracking: key = f"{level}:{id}"
        self.usage: Dict[str, List[Dict]] = {}
        
        # Cost rates per tool (can be loaded from config)
        self.tool_rates = {
            "nmap": 0.01,      # $0.01 per minute
            "nuclei": 0.02,
            "sqlmap": 0.05,
            "gobuster": 0.01,
            "nikto": 0.01
        }
        
        logger.info("✅ Budget Tracker initialized")
    
    async def initialize_budget(
        self,
        process_id: str,
        user_id: str,
        tenant_id: str,
        limit: float,
        period: str = "execution"
    ) -> None:
        """Initialize budget for execution"""
        
        key = f"execution:{process_id}"
        
        self.budgets[key] = {
            "process_id": process_id,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "limit": limit,
            "period": period,
            "spent": 0.0,
            "created_at": datetime.utcnow(),
            "alerts_sent": []
        }
        
        logger.info(
            f"Budget initialized for {process_id}: ${limit}",
            extra={
                "process_id": process_id,
                "user_id": user_id,
                "tenant_id": tenant_id,
                "limit": limit
            }
        )
    
    async def check_budget(self, process_id: str, estimated_cost: float) -> bool:
        """Check if estimated cost is within budget"""
        
        key = f"execution:{process_id}"
        budget = self.budgets.get(key)
        
        if not budget:
            return True  # No budget limit
        
        if budget["spent"] + estimated_cost > budget["limit"]:
            logger.warning(
                f"Budget exceeded for {process_id}: "
                f"spent=${budget['spent']:.2f}, estimated=${estimated_cost:.2f}, limit=${budget['limit']:.2f}"
            )
            
            # Send alert
            await self._send_budget_alert(
                process_id,
                budget["spent"] + estimated_cost,
                budget["limit"]
            )
            
            return False
        
        return True
    
    async def add_cost(
        self,
        process_id: str,
        cost: float,
        details: Optional[Dict] = None
    ) -> None:
        """Add cost to execution"""
        
        key = f"execution:{process_id}"
        budget = self.budgets.get(key)
        
        if budget:
            budget["spent"] += cost
            budget["updated_at"] = datetime.utcnow().isoformat()
            
            # Check thresholds
            usage_percent = (budget["spent"] / budget["limit"]) * 100 if budget["limit"] > 0 else 0
            
            thresholds = [50, 80, 90, 95, 100]
            for threshold in thresholds:
                if usage_percent >= threshold and threshold not in budget["alerts_sent"]:
                    await self._send_budget_threshold_alert(
                        process_id,
                        usage_percent,
                        budget["spent"],
                        budget["limit"]
                    )
                    budget["alerts_sent"].append(threshold)
        
        # Track usage for analytics
        usage_key = f"usage:{process_id}"
        if usage_key not in self.usage:
            self.usage[usage_key] = []
        
        self.usage[usage_key].append({
            "timestamp": datetime.utcnow().isoformat(),
            "process_id": process_id,
            "cost": cost,
            "details": details or {}
        })
        
        # Limit history
        if len(self.usage[usage_key]) > 1000:
            self.usage[usage_key] = self.usage[usage_key][-1000:]
    
    async def estimate_cost(
        self,
        tool_name: str,
        duration_minutes: float,
        params: Optional[Dict] = None
    ) -> float:
        """Estimate cost for tool execution"""
        
        base_rate = self.tool_rates.get(tool_name, 0.01)
        
        # Apply modifiers based on parameters
        modifier = 1.0
        
        if params:
            # Priority modifier
            priority = params.get("priority", "normal")
            if priority == "high":
                modifier *= 1.5
            elif priority == "critical":
                modifier *= 2.0
            
            # Scope modifier
            scope = params.get("scope", "normal")
            if scope == "deep":
                modifier *= 1.5
            elif scope == "full":
                modifier *= 2.0
        
        estimated_cost = base_rate * duration_minutes * modifier
        
        return round(estimated_cost, 4)
    
    async def set_user_budget(
        self,
        user_id: str,
        tenant_id: str,
        limit: float,
        period: str = "monthly"
    ) -> None:
        """Set budget for user"""
        
        key = f"user:{user_id}"
        
        self.budgets[key] = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "limit": limit,
            "period": period,
            "spent": 0.0,
            "created_at": datetime.utcnow(),
            "alerts_sent": []
        }
        
        logger.info(f"Set {period} budget of ${limit} for user {user_id}")
    
    async def set_tenant_budget(
        self,
        tenant_id: str,
        limit: float,
        period: str = "monthly"
    ) -> None:
        """Set budget for tenant"""
        
        key = f"tenant:{tenant_id}"
        
        self.budgets[key] = {
            "tenant_id": tenant_id,
            "limit": limit,
            "period": period,
            "spent": 0.0,
            "created_at": datetime.utcnow(),
            "alerts_sent": []
        }
        
        logger.info(f"Set {period} budget of ${limit} for tenant {tenant_id}")
    
    async def get_execution_cost(self, process_id: str) -> float:
        """Get total cost for execution"""
        
        usage_key = f"usage:{process_id}"
        usage = self.usage.get(usage_key, [])
        
        return sum(item["cost"] for item in usage)
    
    async def get_user_usage(
        self,
        user_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get usage statistics for user"""
        
        total_cost = 0.0
        executions = []
        
        for usage_key, usage_list in self.usage.items():
            for usage in usage_list:
                # This would need proper filtering in production
                total_cost += usage["cost"]
        
        return {
            "user_id": user_id,
            "total_cost": total_cost,
            "execution_count": len(executions),
            "period_start": start_time.isoformat() if start_time else None,
            "period_end": end_time.isoformat() if end_time else None
        }
    
    async def _send_budget_alert(self, process_id: str, projected: float, limit: float):
        """Send budget exceeded alert"""
        
        logger.warning(
            f"🚨 BUDGET ALERT: Execution {process_id} would exceed budget",
            extra={
                "process_id": process_id,
                "projected": projected,
                "limit": limit
            }
        )
        
        # In production, send email/webhook
    
    async def _send_budget_threshold_alert(
        self,
        process_id: str,
        percentage: float,
        spent: float,
        limit: float
    ):
        """Send budget threshold alert"""
        
        logger.info(
            f"💰 Budget threshold reached: {percentage:.0f}%",
            extra={
                "process_id": process_id,
                "percentage": percentage,
                "spent": spent,
                "limit": limit
            }
        )


