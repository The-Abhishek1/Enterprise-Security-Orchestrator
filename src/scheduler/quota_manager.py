"""
Quota Manager — tier-aware daily scan limits, concurrent scan limits,
tool access control, feature gates. All backed by PostgreSQL.
"""
from typing import Dict, Optional
from datetime import datetime, date
from src.utils.logging import logger
from src.core.database import db_manager

# Hardcoded fallback if DB tier_config not available
TIER_DEFAULTS = {
    "free":       {"scans_per_day": 3,    "max_concurrent": 1,  "allowed_tools": ["nmap"],
                   "proposals_enabled": False, "scheduling_enabled": False, "teams_enabled": False,
                   "pdf_reports_enabled": False, "ai_analysis_enabled": False, "api_access_enabled": False,
                   "attack_surface_enabled": False, "max_scan_duration": 300},
    "pro":        {"scans_per_day": 20,   "max_concurrent": 2,  "allowed_tools": ["nmap","nuclei","whatweb","nikto","gobuster"],
                   "proposals_enabled": True, "scheduling_enabled": True, "teams_enabled": False,
                   "pdf_reports_enabled": True, "ai_analysis_enabled": True, "api_access_enabled": True,
                   "attack_surface_enabled": True, "max_scan_duration": 900},
    "enterprise": {"scans_per_day": 100,  "max_concurrent": 5,  "allowed_tools": ["nmap","nuclei","whatweb","nikto","gobuster","ffuf","sqlmap"],
                   "proposals_enabled": True, "scheduling_enabled": True, "teams_enabled": True,
                   "pdf_reports_enabled": True, "ai_analysis_enabled": True, "api_access_enabled": True,
                   "attack_surface_enabled": True, "max_scan_duration": 1800},
    "admin":      {"scans_per_day": 9999, "max_concurrent": 10, "allowed_tools": ["nmap","nuclei","whatweb","nikto","gobuster","ffuf","sqlmap"],
                   "proposals_enabled": True, "scheduling_enabled": True, "teams_enabled": True,
                   "pdf_reports_enabled": True, "ai_analysis_enabled": True, "api_access_enabled": True,
                   "attack_surface_enabled": True, "max_scan_duration": 3600},
}


class QuotaManager:
    def __init__(self):
        self._tier_cache: Dict[str, Dict] = {}
        self.active_scans: Dict[str, int] = {}   # user_id -> count
        logger.info("✅ Quota Manager initialized")

    # ─── Tier config ──────────────────────────────────────
    async def get_tier_config(self, tier: str) -> Dict:
        if tier in self._tier_cache:
            return self._tier_cache[tier]
        pool = db_manager.pg_pool
        if pool:
            try:
                async with pool.acquire() as c:
                    r = await c.fetchrow("SELECT * FROM tier_config WHERE tier=$1", tier)
                if r:
                    cfg = dict(r)
                    self._tier_cache[tier] = cfg
                    return cfg
            except Exception:
                pass
        return TIER_DEFAULTS.get(tier, TIER_DEFAULTS["free"])

    # ─── Daily scan quota ─────────────────────────────────
    async def check_daily_quota(self, user_id: str, tier: str) -> Dict:
        """Returns {allowed: bool, used: int, limit: int, reason: str}"""
        cfg   = await self.get_tier_config(tier)
        limit = cfg["scans_per_day"]
        pool  = db_manager.pg_pool

        if not pool:
            return {"allowed": True, "used": 0, "limit": limit, "reason": ""}

        try:
            async with pool.acquire() as c:
                r = await c.fetchrow(
                    "SELECT scans_today, scans_today_reset FROM users WHERE user_id=$1", user_id
                )
            if not r:
                return {"allowed": True, "used": 0, "limit": limit, "reason": ""}

            # Reset daily counter if it's a new day
            reset_date = r["scans_today_reset"].date() if r["scans_today_reset"] else date.today()
            if reset_date < date.today():
                async with pool.acquire() as c:
                    await c.execute(
                        "UPDATE users SET scans_today=0, scans_today_reset=NOW() WHERE user_id=$1",
                        user_id
                    )
                used = 0
            else:
                used = r["scans_today"] or 0

            allowed = used < limit
            return {
                "allowed": allowed,
                "used": used,
                "limit": limit,
                "reason": f"Daily limit reached ({used}/{limit}). Upgrade your tier for more scans." if not allowed else ""
            }
        except Exception as e:
            logger.warning(f"Quota check error: {e}")
            return {"allowed": True, "used": 0, "limit": limit, "reason": ""}

    async def increment_daily(self, user_id: str):
        pool = db_manager.pg_pool
        if pool:
            try:
                async with pool.acquire() as c:
                    await c.execute(
                        "UPDATE users SET scans_today=scans_today+1, total_scans=total_scans+1, updated_at=NOW() WHERE user_id=$1",
                        user_id
                    )
            except Exception as e:
                logger.warning(f"Daily increment error: {e}")

    # ─── Concurrent scan limit ────────────────────────────
    async def check_concurrent(self, user_id: str, tier: str) -> Dict:
        cfg    = await self.get_tier_config(tier)
        limit  = cfg["max_concurrent"]
        active = self.active_scans.get(user_id, 0)
        allowed = active < limit
        return {
            "allowed": allowed,
            "active": active,
            "limit": limit,
            "reason": f"Max concurrent scans reached ({active}/{limit})." if not allowed else ""
        }

    def increment_active(self, user_id: str):
        self.active_scans[user_id] = self.active_scans.get(user_id, 0) + 1

    def decrement_active(self, user_id: str):
        self.active_scans[user_id] = max(0, self.active_scans.get(user_id, 0) - 1)

    # ─── Tool access check ────────────────────────────────
    async def check_tool_access(self, user_id: str, tier: str, tools: list) -> Dict:
        cfg     = await self.get_tier_config(tier)
        allowed = cfg["allowed_tools"]
        blocked = [t for t in tools if t not in allowed]
        return {
            "allowed": len(blocked) == 0,
            "blocked_tools": blocked,
            "allowed_tools": allowed,
            "reason": f"Tools not available on {tier} tier: {', '.join(blocked)}. Upgrade to access." if blocked else ""
        }

    # ─── Feature gate check ───────────────────────────────
    async def check_feature(self, tier: str, feature: str) -> bool:
        cfg = await self.get_tier_config(tier)
        return cfg.get(f"{feature}_enabled", False)

    # ─── Full quota check (combines all) ──────────────────
    async def check_all(self, user_id: str, tier: str, requested_tools: Optional[list] = None) -> Dict:
        daily      = await self.check_daily_quota(user_id, tier)
        concurrent = await self.check_concurrent(user_id, tier)
        tool_check = await self.check_tool_access(user_id, tier, requested_tools or []) if requested_tools else {"allowed": True, "blocked_tools": [], "reason": ""}

        cfg = await self.get_tier_config(tier)
        allowed = daily["allowed"] and concurrent["allowed"] and tool_check["allowed"]
        reason  = daily["reason"] or concurrent["reason"] or tool_check["reason"]

        return {
            "allowed": allowed,
            "reason": reason,
            "daily":      daily,
            "concurrent": concurrent,
            "tools":      tool_check,
            "tier_config": cfg,
        }

    # ─── Admin: upgrade user tier ─────────────────────────
    async def set_user_tier(self, user_id: str, tier: str) -> bool:
        pool = db_manager.pg_pool
        if not pool:
            return False
        try:
            async with pool.acquire() as c:
                await c.execute(
                    "UPDATE users SET tier=$1, role=$2, updated_at=NOW() WHERE user_id=$3",
                    tier,
                    "admin" if tier == "admin" else tier,
                    user_id
                )
            return True
        except Exception as e:
            logger.error(f"Failed to set tier: {e}")
            return False

    # ─── Legacy compat ────────────────────────────────────
    async def check_quota(self, tenant_id: str, user_id: str, quota_type: str = "concurrent_executions") -> bool:
        result = await self.check_concurrent(user_id, "free")
        return result["allowed"]

    async def increment_usage(self, tenant_id: str, user_id: str):
        self.increment_active(user_id)

    async def decrement_usage(self, tenant_id: str, user_id: str):
        self.decrement_active(user_id)
