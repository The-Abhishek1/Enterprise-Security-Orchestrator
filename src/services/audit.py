# src/services/audit.py
from typing import Dict, Any, Optional
from datetime import datetime
import json
import uuid

from src.utils.logging import logger
from src.core.database import db_manager


class AuditLogger:
    """Audit logging service"""
    
    def __init__(self):
        self.enabled = True
    
    async def log(
        self,
        action: str,
        user_id: str,
        tenant_id: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error: Optional[str] = None
    ) -> None:
        """Log an audit event"""
        
        if not self.enabled:
            return
        
        audit_entry = {
            "audit_id": f"audit_{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.utcnow(),
            "action": action,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
            "status": status,
            "error": error
        }
        
        # Log to structured logging
        logger.info(
            f"AUDIT: {action} - User: {user_id}, Tenant: {tenant_id}",
            extra={"audit": audit_entry}
        )
        
        # Store in database (if available)
        try:
            if db_manager and db_manager.pg_pool:
                await db_manager.execute_postgres(
                    """
                    INSERT INTO audit_logs 
                    (audit_id, timestamp, action, user_id, tenant_id, resource_type, resource_id, details, status, error)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    """,
                    audit_entry["audit_id"],
                    audit_entry["timestamp"],
                    audit_entry["action"],
                    audit_entry["user_id"],
                    audit_entry["tenant_id"],
                    audit_entry["resource_type"],
                    audit_entry["resource_id"],
                    json.dumps(audit_entry["details"]),
                    audit_entry["status"],
                    audit_entry["error"]
                )
        except Exception as e:
            logger.error(f"Failed to store audit log: {e}")


# Global audit logger instance
audit_logger = AuditLogger()