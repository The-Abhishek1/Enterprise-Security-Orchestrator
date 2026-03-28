# src/tools/cost_tracker.py
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
from decimal import Decimal

from src.core.config import get_settings
from src.utils.logging import logger

settings = get_settings()


class ToolCostTracker:
    """
    Enterprise Tool Cost Tracker
    
    Features:
    - Real-time cost tracking
    - Budget enforcement
    - Cost estimation
    - Billing integration
    - Cost analytics
    """
    
    def __init__(self):
        # Active budgets
        self.budgets: Dict[str, Dict] = {}
        
        # Usage tracking
        self.usage: Dict[str, List[Dict]] = {}
        
        # Cost rates per tool (per minute)
        self.tool_rates = {
            "nmap": 0.01,
            "nuclei": 0.02,
            "sqlmap": 0.05,
            "gobuster": 0.01,
            "nikto": 0.01
        }
        
        logger.info("✅ Tool Cost Tracker initialized")
    
    async def estimate_cost(
        self,
        tool_name: str,
        params: Dict[str, Any]
    ) -> float:
        """Estimate cost for tool execution"""
        
        base_rate = self.tool_rates.get(tool_name, 0.01)
        
        # Estimate duration based on parameters
        estimated_minutes = self._estimate_duration(tool_name, params)
        
        # Apply any modifiers
        modifiers = self._get_cost_modifiers(tool_name, params)
        
        estimated_cost = base_rate * estimated_minutes * modifiers
        
        return round(estimated_cost, 4)
    
    def _estimate_duration(self, tool_name: str, params: Dict[str, Any]) -> float:
        """Estimate execution duration in minutes"""
        
        # Default estimations
        if tool_name == "nmap":
            ports = params.get("ports", "1000")
            if isinstance(ports, str):
                port_count = len(ports.split(','))
            else:
                port_count = 1000
            return max(1, port_count * 0.01)
        
        elif tool_name == "nuclei":
            templates = params.get("templates", [])
            if isinstance(templates, list):
                template_count = len(templates)
            else:
                template_count = 10
            return max(2, template_count * 0.2)
        
        elif tool_name == "sqlmap":
            level = params.get("level", 1)
            return max(5, level * 2)
        
        elif tool_name == "gobuster":
            threads = params.get("threads", 10)
            return max(1, threads * 0.05)
        
        return 1
    
    def _get_cost_modifiers(self, tool_name: str, params: Dict[str, Any]) -> float:
        """Get cost modifiers based on parameters"""
        
        modifiers = 1.0
        
        # Priority modifier
        priority = params.get("priority", "normal")
        if priority == "high":
            modifiers *= 1.5
        elif priority == "critical":
            modifiers *= 2.0
        
        # Scope modifier
        scope = params.get("scope", "normal")
        if scope == "deep":
            modifiers *= 1.5
        elif scope == "full":
            modifiers *= 2.0
        
        return modifiers
    
    async def check_budget(
        self,
        user_id: str,
        tenant_id: str,
        estimated_cost: float,
        execution_id: str
    ) -> bool:
        """Check if execution is within budget"""
        
        # Check user budget
        user_budget = self.budgets.get(f"user:{user_id}")
        if user_budget:
            user_used = await self._get_user_usage(user_id)
            if user_used + estimated_cost > user_budget["limit"]:
                logger.warning(f"User {user_id} budget exceeded")
                return False
        
        # Check tenant budget
        tenant_budget = self.budgets.get(f"tenant:{tenant_id}")
        if tenant_budget:
            tenant_used = await self._get_tenant_usage(tenant_id)
            if tenant_used + estimated_cost > tenant_budget["limit"]:
                logger.warning(f"Tenant {tenant_id} budget exceeded")
                return False
        
        return True
    
    async def track_usage(
        self,
        user_id: str,
        tenant_id: str,
        tool_name: str,
        duration: float,
        execution_id: str
    ):
        """Track tool usage and cost"""
        
        cost = self.tool_rates.get(tool_name, 0.01) * (duration / 60)
        
        usage_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "tenant_id": tenant_id,
            "tool": tool_name,
            "duration_seconds": duration,
            "cost": cost,
            "execution_id": execution_id
        }
        
        # Store usage
        key = f"{tenant_id}:{user_id}"
        if key not in self.usage:
            self.usage[key] = []
        
        self.usage[key].append(usage_record)
        
        # Limit history
        if len(self.usage[key]) > 10000:
            self.usage[key] = self.usage[key][-10000:]
        
        logger.debug(
            f"Tracked usage: {tool_name} - ${cost:.4f}",
            extra={
                "user_id": user_id,
                "tenant_id": tenant_id,
                "cost": cost
            }
        )
        
        # Check budget thresholds
        await self._check_budget_thresholds(user_id, tenant_id, cost)
    
    async def set_budget(
        self,
        entity_type: str,
        entity_id: str,
        limit: float,
        period: str = "monthly"
    ):
        """Set budget for user or tenant"""
        
        key = f"{entity_type}:{entity_id}"
        
        self.budgets[key] = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "limit": limit,
            "period": period,
            "start_date": datetime.utcnow().isoformat(),
            "alerts_sent": []
        }
        
        logger.info(f"Set {period} budget of ${limit} for {key}")
    
    async def _get_user_usage(self, user_id: str, period: str = "monthly") -> float:
        """Get total usage for user in period"""
        
        total = 0.0
        cutoff = self._get_period_cutoff(period)
        
        for key, records in self.usage.items():
            if user_id in key:
                for record in records:
                    record_time = datetime.fromisoformat(record["timestamp"])
                    if record_time >= cutoff:
                        total += record["cost"]
        
        return total
    
    async def _get_tenant_usage(self, tenant_id: str, period: str = "monthly") -> float:
        """Get total usage for tenant in period"""
        
        total = 0.0
        cutoff = self._get_period_cutoff(period)
        
        for key, records in self.usage.items():
            if key.startswith(tenant_id):
                for record in records:
                    record_time = datetime.fromisoformat(record["timestamp"])
                    if record_time >= cutoff:
                        total += record["cost"]
        
        return total
    
    def _get_period_cutoff(self, period: str) -> datetime:
        """Get cutoff date for period"""
        
        now = datetime.utcnow()
        
        if period == "daily":
            return now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == "weekly":
            return now - timedelta(days=now.weekday())
        elif period == "monthly":
            return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        elif period == "yearly":
            return now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            return now - timedelta(days=30)
    
    async def _check_budget_thresholds(
        self,
        user_id: str,
        tenant_id: str,
        cost: float
    ):
        """Check if budget thresholds are exceeded"""
        
        thresholds = [0.5, 0.8, 0.9, 0.95, 1.0]
        
        # Check user budget
        user_budget = self.budgets.get(f"user:{user_id}")
        if user_budget:
            user_used = await self._get_user_usage(user_id, user_budget["period"])
            user_percentage = user_used / user_budget["limit"] if user_budget["limit"] > 0 else 0
            
            for threshold in thresholds:
                if user_percentage >= threshold and threshold not in user_budget["alerts_sent"]:
                    await self._send_budget_alert(
                        entity_type="user",
                        entity_id=user_id,
                        threshold=threshold,
                        used=user_used,
                        limit=user_budget["limit"]
                    )
                    user_budget["alerts_sent"].append(threshold)
        
        # Check tenant budget
        tenant_budget = self.budgets.get(f"tenant:{tenant_id}")
        if tenant_budget:
            tenant_used = await self._get_tenant_usage(tenant_id, tenant_budget["period"])
            tenant_percentage = tenant_used / tenant_budget["limit"] if tenant_budget["limit"] > 0 else 0
            
            for threshold in thresholds:
                if tenant_percentage >= threshold and threshold not in tenant_budget["alerts_sent"]:
                    await self._send_budget_alert(
                        entity_type="tenant",
                        entity_id=tenant_id,
                        threshold=threshold,
                        used=tenant_used,
                        limit=tenant_budget["limit"]
                    )
                    tenant_budget["alerts_sent"].append(threshold)
    
    async def _send_budget_alert(
        self,
        entity_type: str,
        entity_id: str,
        threshold: float,
        used: float,
        limit: float
    ):
        """Send budget alert"""
        
        logger.warning(
            f"💰 Budget alert for {entity_type} {entity_id}: {threshold*100:.0f}% used",
            extra={
                "entity_type": entity_type,
                "entity_id": entity_id,
                "threshold": threshold,
                "used": used,
                "limit": limit
            }
        )
        
        # In production, send email/webhook
    
    async def get_usage_report(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Get usage report for period"""
        
        report = {
            "tenant_id": tenant_id,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "total_cost": 0.0,
            "by_tool": {},
            "by_user": {},
            "executions": 0
        }
        
        for key, records in self.usage.items():
            if key.startswith(tenant_id):
                for record in records:
                    record_time = datetime.fromisoformat(record["timestamp"])
                    if start_time <= record_time <= end_time:
                        report["total_cost"] += record["cost"]
                        report["executions"] += 1
                        
                        # By tool
                        tool = record["tool"]
                        if tool not in report["by_tool"]:
                            report["by_tool"][tool] = 0
                        report["by_tool"][tool] += record["cost"]
                        
                        # By user
                        user = record["user_id"]
                        if user not in report["by_user"]:
                            report["by_user"][user] = 0
                        report["by_user"][user] += record["cost"]
        
        return report