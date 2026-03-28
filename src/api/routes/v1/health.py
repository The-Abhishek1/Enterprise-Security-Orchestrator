# src/api/routes/v1/health.py
from fastapi import APIRouter
from typing import Dict, Any
from datetime import datetime

from src.core.database import db_manager
from src.utils.logging import logger

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint"""
    
    status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {}
    }
    
    # Check PostgreSQL
    try:
        if db_manager.pg_pool:
            async with db_manager.pg_pool.acquire() as conn:
                await conn.execute("SELECT 1")
            status["services"]["postgresql"] = "healthy"
        else:
            status["services"]["postql"] = "not initialized"
            status["status"] = "degraded"
    except Exception as e:
        status["services"]["postgresql"] = f"unhealthy: {str(e)}"
        status["status"] = "degraded"
    
    # Check Redis
    try:
        if db_manager.redis_client:
            await db_manager.redis_client.ping()
            status["services"]["redis"] = "healthy"
        else:
            status["services"]["redis"] = "not initialized"
            status["status"] = "degraded"
    except Exception as e:
        status["services"]["redis"] = f"unhealthy: {str(e)}"
        status["status"] = "degraded"
    
    # Check RabbitMQ - FIXED VERSION
    try:
        if db_manager.rabbitmq_connection and db_manager.rabbitmq_connection.is_closed is False:
            # Check if channel exists and is open
            if db_manager.rabbitmq_channel and not db_manager.rabbitmq_channel.is_closed:
                status["services"]["rabbitmq"] = "healthy"
            else:
                status["services"]["rabbitmq"] = "channel not open"
                status["status"] = "degraded"
        else:
            status["services"]["rabbitmq"] = "not connected"
            status["status"] = "degraded"
    except Exception as e:
        status["services"]["rabbitmq"] = f"unhealthy: {str(e)}"
        status["status"] = "degraded"
    
    return status


@router.get("/ready")
async def readiness_check() -> Dict[str, str]:
    """Readiness check for Kubernetes"""
    
    # Check critical services
    try:
        # PostgreSQL
        if db_manager.pg_pool:
            async with db_manager.pg_pool.acquire() as conn:
                await conn.execute("SELECT 1")
        else:
            return {"status": "not ready", "reason": "PostgreSQL not initialized"}
        
        # Redis
        if db_manager.redis_client:
            await db_manager.redis_client.ping()
        else:
            return {"status": "not ready", "reason": "Redis not initialized"}
        
        # RabbitMQ - FIXED VERSION
        if db_manager.rabbitmq_connection and not db_manager.rabbitmq_connection.is_closed:
            if db_manager.rabbitmq_channel and not db_manager.rabbitmq_channel.is_closed:
                return {"status": "ready"}
            else:
                return {"status": "not ready", "reason": "RabbitMQ channel not open"}
        else:
            return {"status": "not ready", "reason": "RabbitMQ not connected"}
    
    except Exception as e:
        return {"status": "not ready", "reason": str(e)}


@router.get("/live")
async def liveness_check() -> Dict[str, str]:
    """Liveness check for Kubernetes"""
    return {"status": "alive"}