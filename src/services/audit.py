# src/services/audit.py

"""
Audit Logger — persists every API action to PostgreSQL.
Queryable via /api/v1/system/audit endpoint.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import json
import uuid

from src.core.database import db_manager
from src.utils.logging import logger


class AuditLogger:

    async def log(
        self,
        action: str,
        user_id: str,
        tenant_id: str = "default",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "success",
        error: Optional[str] = None,
    ):
        """Log an audit event to PostgreSQL."""
        # Structured log
        logger.info(f"AUDIT: {action} user={user_id} status={status}")

        if not db_manager or not db_manager.pg_pool:
            return

        aid = f"audit_{uuid.uuid4().hex[:12]}"
        ip = (details or {}).pop("ip", None)
        ua = (details or {}).pop("user_agent", None)

        try:
            await db_manager.execute_postgres(
                """INSERT INTO audit_logs
                   (audit_id,timestamp,action,user_id,tenant_id,resource_type,resource_id,details,status,error,ip_address,user_agent)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)""",
                aid, datetime.utcnow(), action, user_id, tenant_id,
                resource_type, resource_id,
                json.dumps(details) if details else None,
                status, error, ip, ua
            )
        except Exception as e:
            logger.debug(f"Audit write failed (non-fatal): {e}")

    async def query(
        self,
        user_id: str = None,
        action: str = None,
        status: str = None,
        since: datetime = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict:
        """Query audit logs with filters."""
        if not db_manager or not db_manager.pg_pool:
            return {"logs": [], "total": 0}

        conditions = []
        params = []
        idx = 1

        if user_id:
            conditions.append(f"user_id = ${idx}"); params.append(user_id); idx += 1
        if action:
            conditions.append(f"action ILIKE ${idx}"); params.append(f"%{action}%"); idx += 1
        if status:
            conditions.append(f"status = ${idx}"); params.append(status); idx += 1
        if since:
            conditions.append(f"timestamp >= ${idx}"); params.append(since); idx += 1

        where = " AND ".join(conditions) if conditions else "TRUE"

        pool = db_manager.pg_pool
        async with pool.acquire() as c:
            total = await c.fetchval(f"SELECT COUNT(*) FROM audit_logs WHERE {where}", *params)
            rows = await c.fetch(
                f"""SELECT audit_id,timestamp,action,user_id,tenant_id,resource_type,
                           resource_id,details,status,error,ip_address
                    FROM audit_logs WHERE {where}
                    ORDER BY timestamp DESC LIMIT ${idx} OFFSET ${idx+1}""",
                *params, limit, offset
            )

        logs = []
        for r in rows:
            d = dict(r)
            if d.get("details") and isinstance(d["details"], str):
                try: d["details"] = json.loads(d["details"])
                except: pass
            d["timestamp"] = d["timestamp"].isoformat() if d.get("timestamp") else None
            logs.append(d)

        return {"logs": logs, "total": total, "limit": limit, "offset": offset}


# Singleton
audit_logger = AuditLogger()
