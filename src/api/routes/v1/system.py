# src/api/routes/v1/system.py
"""System settings — LLM provider switch, system info."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from src.api.dependencies import get_current_user
from src.agents.planner.llm_factory import llm_factory
from src.core.config import get_settings
from src.core.database import db_manager
from src.utils.logging import logger

router = APIRouter(prefix="/system", tags=["system"])

settings = get_settings()


class LLMSwitchRequest(BaseModel):
    provider: str  # "openai" or "local"
    model: Optional[str] = None


@router.get("/info")
async def system_info(current_user: dict = Depends(get_current_user)):
    """System info — LLM provider, tools, health."""
    return {
        "llm_provider": llm_factory.default_provider,
        "llm_model": getattr(llm_factory.get_client(), 'model_name', 'unknown'),
        "available_providers": ["openai", "local", "anthropic"],
        "local_llm_url": settings.local_llm_url,
        "local_llm_model": settings.local_llm_model,
        "environment": settings.environment.value,
        "services": {
            "postgresql": "connected" if db_manager.pg_pool else "disconnected",
            "redis": "connected" if db_manager.redis_client else "disconnected",
            "rabbitmq": "connected" if db_manager.rabbitmq_connection else "disconnected",
        }
    }


@router.post("/llm/switch")
async def switch_llm(req: LLMSwitchRequest, current_user: dict = Depends(get_current_user)):
    """Switch LLM provider at runtime (openai ↔ local)."""
    if req.provider not in ["openai", "local", "anthropic"]:
        raise HTTPException(400, f"Unknown provider: {req.provider}")
    
    old = llm_factory.default_provider
    llm_factory.default_provider = req.provider
    llm_factory.clients.clear()  # Clear cached clients
    
    # Create new client to verify it works
    try:
        client = llm_factory.get_client(
            provider=req.provider,
            model_name=req.model
        )
        model = client.model_name
    except Exception as e:
        # Rollback
        llm_factory.default_provider = old
        llm_factory.clients.clear()
        raise HTTPException(400, f"Failed to initialize {req.provider}: {e}")
    
    logger.info(f"🔄 LLM switched: {old} → {req.provider} (model: {model})")
    
    return {
        "previous": old,
        "current": req.provider,
        "model": model,
        "message": f"Switched to {req.provider} ({model})"
    }


@router.get("/llm/test")
async def test_llm(current_user: dict = Depends(get_current_user)):
    """Test current LLM connection."""
    try:
        ok = await llm_factory.test_connection()
        provider = llm_factory.default_provider
        model = getattr(llm_factory.get_client(), 'model_name', 'unknown')
        return {
            "status": "ok" if ok else "failed",
            "provider": provider,
            "model": model
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ========================================================
# Audit Logs
# ========================================================

@router.get("/audit")
async def query_audit_logs(
    user_id: str = None,
    action: str = None,
    status: str = None,
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """Query audit logs. Admin only — non-admins see only their own logs."""
    from src.services.audit import audit_logger

    # Non-admins can only see their own logs
    query_user = user_id
    if current_user.get("role") != "admin":
        query_user = current_user["sub"]

    return await audit_logger.query(
        user_id=query_user, action=action, status=status,
        limit=limit, offset=offset
    )


# ========================================================
# Target Rules
# ========================================================

@router.get("/targets")
async def list_target_rules(current_user: dict = Depends(get_current_user)):
    """List target allowlist/denylist rules."""
    if not db_manager.pg_pool:
        return {"rules": [], "message": "Database not available"}

    async with db_manager.pg_pool.acquire() as c:
        rows = await c.fetch(
            "SELECT id,tenant_id,pattern,rule_type,reason,created_by,created_at FROM target_rules WHERE tenant_id=$1 ORDER BY rule_type,pattern",
            current_user.get("tenant_id", "default")
        )
    return {"rules": [dict(r) for r in rows]}


@router.post("/targets")
async def add_target_rule(
    pattern: str,
    rule_type: str,
    reason: str = None,
    current_user: dict = Depends(get_current_user)
):
    """Add a target allow/deny rule. Admin only."""
    if current_user.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    if rule_type not in ("allow", "deny"):
        raise HTTPException(400, "rule_type must be 'allow' or 'deny'")
    if not db_manager.pg_pool:
        raise HTTPException(503, "Database not available")

    async with db_manager.pg_pool.acquire() as c:
        await c.execute(
            "INSERT INTO target_rules (tenant_id,pattern,rule_type,reason,created_by) VALUES ($1,$2,$3,$4,$5)",
            current_user.get("tenant_id", "default"), pattern, rule_type, reason, current_user["sub"]
        )

    # Reload validator patterns from DB
    from src.services.target_validator import target_validator
    await _reload_target_rules(target_validator, current_user.get("tenant_id", "default"))

    return {"message": f"Rule added: {rule_type} {pattern}", "pattern": pattern, "rule_type": rule_type}


@router.delete("/targets/{rule_id}")
async def delete_target_rule(rule_id: int, current_user: dict = Depends(get_current_user)):
    """Delete a target rule. Admin only."""
    if current_user.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    if not db_manager.pg_pool:
        raise HTTPException(503, "Database not available")

    async with db_manager.pg_pool.acquire() as c:
        res = await c.execute(
            "DELETE FROM target_rules WHERE id=$1 AND tenant_id=$2", rule_id, current_user.get("tenant_id", "default")
        )
    if "DELETE 0" in res:
        raise HTTPException(404, "Rule not found")

    return {"message": "Rule deleted", "rule_id": rule_id}


async def _reload_target_rules(validator, tenant_id: str):
    """Reload target rules from DB into validator."""
    if not db_manager.pg_pool:
        return
    async with db_manager.pg_pool.acquire() as c:
        rows = await c.fetch(
            "SELECT pattern,rule_type FROM target_rules WHERE tenant_id=$1", tenant_id
        )
    validator.allowed_patterns = [r["pattern"] for r in rows if r["rule_type"] == "allow"]
    validator.denied_patterns = list(validator.GLOBAL_DENYLIST) + [r["pattern"] for r in rows if r["rule_type"] == "deny"]

