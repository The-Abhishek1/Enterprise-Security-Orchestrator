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
