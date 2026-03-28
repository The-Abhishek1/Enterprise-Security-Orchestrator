# src/services/user_service.py

"""
User management — registration, login, API keys, scan history.
All data stored in PostgreSQL.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import uuid
import secrets
import hashlib
import json

from src.core.database import db_manager
from src.utils.logging import logger

try:
    import bcrypt
    _has_bcrypt = True
except ImportError:
    _has_bcrypt = False
    logger.warning("⚠️ bcrypt not installed — using SHA256 for passwords (pip install bcrypt)")


def _hash_password(password: str) -> str:
    if _has_bcrypt:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return hashlib.sha256(password.encode()).hexdigest()


def _verify_password(password: str, hashed: str) -> bool:
    if _has_bcrypt:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    return hashlib.sha256(password.encode()).hexdigest() == hashed


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class UserService:
    """Manages users, API keys, and scan history via PostgreSQL."""
    
    # ========================================================
    # USERS
    # ========================================================
    
    async def register(self, email: str, username: str, password: str, role: str = "user") -> Dict:
        """Register a new user."""
        pool = db_manager.pg_pool
        if not pool:
            raise Exception("Database not available")
        
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        password_hash = _hash_password(password)
        
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO users (user_id, email, username, password_hash, role, tenant_id)
                       VALUES ($1, $2, $3, $4, $5, $6)""",
                    user_id, email, username, password_hash, role, "default"
                )
            
            logger.info(f"✅ User registered: {username} ({user_id})")
            return {"user_id": user_id, "email": email, "username": username, "role": role}
            
        except Exception as e:
            if "unique" in str(e).lower():
                raise Exception("Email or username already exists")
            raise
    
    async def login(self, email: str, password: str) -> Optional[Dict]:
        """Authenticate user, return user data if valid."""
        pool = db_manager.pg_pool
        if not pool:
            raise Exception("Database not available")
        
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT user_id, email, username, password_hash, role, tenant_id, is_active FROM users WHERE email = $1",
                email
            )
        
        if not row:
            return None
        
        if not row["is_active"]:
            return None
        
        if not _verify_password(password, row["password_hash"]):
            return None
        
        return {
            "user_id": row["user_id"],
            "email": row["email"],
            "username": row["username"],
            "role": row["role"],
            "tenant_id": row["tenant_id"]
        }
    
    async def get_user(self, user_id: str) -> Optional[Dict]:
        """Get user by user_id."""
        pool = db_manager.pg_pool
        if not pool:
            return None
        
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT user_id, email, username, role, tenant_id, is_active, created_at FROM users WHERE user_id = $1",
                user_id
            )
        
        if not row:
            return None
        
        return dict(row)
    
    # ========================================================
    # API KEYS
    # ========================================================
    
    async def create_api_key(self, user_id: str, name: str, permissions: List[str] = None, expires_days: int = None) -> Dict:
        """Create a new API key for a user."""
        pool = db_manager.pg_pool
        if not pool:
            raise Exception("Database not available")
        
        # Generate key: eso_<random>
        raw_key = f"eso_{secrets.token_urlsafe(32)}"
        key_id = f"key_{uuid.uuid4().hex[:12]}"
        key_hash = _hash_api_key(raw_key)
        key_prefix = raw_key[:12]
        
        if permissions is None:
            permissions = ["read", "execute"]
        
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO api_keys (key_id, key_hash, key_prefix, user_id, name, permissions, expires_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                key_id, key_hash, key_prefix, user_id, name, permissions, expires_at
            )
        
        logger.info(f"✅ API key created: {key_prefix}... for user {user_id}")
        
        # Return the raw key ONLY ONCE — it's not stored, only the hash
        return {
            "key_id": key_id,
            "api_key": raw_key,
            "prefix": key_prefix,
            "name": name,
            "permissions": permissions,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "message": "Save this key — it won't be shown again"
        }
    
    async def verify_api_key(self, raw_key: str) -> Optional[Dict]:
        """Verify an API key and return user data."""
        pool = db_manager.pg_pool
        if not pool:
            return None
        
        key_hash = _hash_api_key(raw_key)
        
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT k.key_id, k.user_id, k.name, k.permissions, k.is_active, k.expires_at,
                          u.email, u.username, u.role, u.tenant_id
                   FROM api_keys k JOIN users u ON k.user_id = u.user_id
                   WHERE k.key_hash = $1""",
                key_hash
            )
        
        if not row:
            return None
        
        if not row["is_active"]:
            return None
        
        if row["expires_at"] and row["expires_at"] < datetime.utcnow():
            return None
        
        # Update last_used_at
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE api_keys SET last_used_at = NOW() WHERE key_id = $1",
                row["key_id"]
            )
        
        return {
            "sub": row["user_id"],
            "email": row["email"],
            "username": row["username"],
            "role": row["role"],
            "tenant_id": row["tenant_id"],
            "permissions": list(row["permissions"]),
            "auth_method": "api_key"
        }
    
    async def list_api_keys(self, user_id: str) -> List[Dict]:
        """List API keys for a user (without the actual key)."""
        pool = db_manager.pg_pool
        if not pool:
            return []
        
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT key_id, key_prefix, name, permissions, is_active, last_used_at, expires_at, created_at
                   FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC""",
                user_id
            )
        
        return [dict(row) for row in rows]
    
    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        """Revoke an API key."""
        pool = db_manager.pg_pool
        if not pool:
            return False
        
        async with pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE api_keys SET is_active = FALSE WHERE key_id = $1 AND user_id = $2",
                key_id, user_id
            )
        
        return "UPDATE 1" in result
    
    # ========================================================
    # SCAN HISTORY
    # ========================================================
    
    async def save_scan(self, scan_data: Dict) -> bool:
        """Save a completed scan to history."""
        pool = db_manager.pg_pool
        if not pool:
            return False
        
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO scan_history 
                       (process_id, user_id, tenant_id, goal, target, status,
                        total_tasks, completed_tasks, failed_tasks, dynamic_tasks,
                        findings_count, risk_score, risk_level, tools_used,
                        llm_calls, duration_seconds, report, error,
                        started_at, completed_at)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
                       ON CONFLICT (process_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        completed_tasks = EXCLUDED.completed_tasks,
                        findings_count = EXCLUDED.findings_count,
                        risk_score = EXCLUDED.risk_score,
                        risk_level = EXCLUDED.risk_level,
                        report = EXCLUDED.report,
                        completed_at = EXCLUDED.completed_at""",
                    scan_data.get("process_id"),
                    scan_data.get("user_id"),
                    scan_data.get("tenant_id", "default"),
                    scan_data.get("goal", ""),
                    scan_data.get("target"),
                    scan_data.get("status", "completed"),
                    scan_data.get("total_tasks", 0),
                    scan_data.get("completed_tasks", 0),
                    scan_data.get("failed_tasks", 0),
                    scan_data.get("dynamic_tasks", 0),
                    scan_data.get("findings_count", 0),
                    scan_data.get("risk_score", 0.0),
                    scan_data.get("risk_level", "none"),
                    scan_data.get("tools_used", []),
                    scan_data.get("llm_calls", 0),
                    scan_data.get("duration_seconds", 0.0),
                    scan_data.get("report"),
                    scan_data.get("error"),
                    scan_data.get("started_at"),
                    scan_data.get("completed_at")
                )
            return True
        except Exception as e:
            logger.error(f"Failed to save scan history: {e}")
            return False
    
    async def get_scans(self, user_id: str, limit: int = 20, offset: int = 0) -> List[Dict]:
        """Get scan history for a user."""
        pool = db_manager.pg_pool
        if not pool:
            return []
        
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT process_id, goal, target, status, total_tasks, completed_tasks,
                          findings_count, risk_score, risk_level, tools_used,
                          duration_seconds, created_at, completed_at
                   FROM scan_history WHERE user_id = $1
                   ORDER BY created_at DESC LIMIT $2 OFFSET $3""",
                user_id, limit, offset
            )
        
        return [dict(row) for row in rows]
    
    async def get_scan(self, process_id: str, user_id: str) -> Optional[Dict]:
        """Get a specific scan with full report."""
        pool = db_manager.pg_pool
        if not pool:
            return None
        
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM scan_history WHERE process_id = $1 AND user_id = $2",
                process_id, user_id
            )
        
        return dict(row) if row else None
    
    async def get_scan_count(self, user_id: str) -> int:
        """Get total scan count for a user."""
        pool = db_manager.pg_pool
        if not pool:
            return 0
        
        async with pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT COUNT(*) FROM scan_history WHERE user_id = $1",
                user_id
            )


# Singleton
user_service = UserService()
