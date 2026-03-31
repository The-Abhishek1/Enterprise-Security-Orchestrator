# src/services/user_service.py

"""
User management + data persistence.
Everything goes to PostgreSQL: users, API keys, scans, findings.
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


def _hash_pw(pw: str) -> str:
    if _has_bcrypt:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    return hashlib.sha256(pw.encode()).hexdigest()


def _check_pw(pw: str, hashed: str) -> bool:
    if _has_bcrypt:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    return hashlib.sha256(pw.encode()).hexdigest() == hashed


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class UserService:

    # ─── helpers ───────────────────────────────────────────
    def _pool(self):
        p = db_manager.pg_pool
        if not p:
            raise Exception("Database not available")
        return p

    # ═══════════════════════════════════════════════════════
    #  USERS
    # ═══════════════════════════════════════════════════════

    async def register(self, email: str, username: str, password: str, role: str = "user") -> Dict:
        pool = self._pool()
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        try:
            async with pool.acquire() as c:
                await c.execute(
                    "INSERT INTO users (user_id,email,username,password_hash,role,tenant_id) VALUES ($1,$2,$3,$4,$5,'default')",
                    user_id, email, username, _hash_pw(password), role
                )
            logger.info(f"✅ User registered: {username} ({user_id})")
            return {"user_id": user_id, "email": email, "username": username, "role": role}
        except Exception as e:
            if "unique" in str(e).lower():
                raise Exception("Email or username already exists")
            raise

    async def login(self, email: str, password: str) -> Optional[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            r = await c.fetchrow(
                "SELECT user_id,email,username,password_hash,role,tenant_id,is_active FROM users WHERE email=$1", email
            )
        if not r or not r["is_active"]:
            return None
        if not _check_pw(password, r["password_hash"]):
            return None
        return {"user_id": r["user_id"], "email": r["email"], "username": r["username"], "role": r["role"], "tenant_id": r["tenant_id"]}

    async def get_user(self, user_id: str) -> Optional[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            r = await c.fetchrow(
                "SELECT user_id,email,username,role,tenant_id,is_active,created_at FROM users WHERE user_id=$1", user_id
            )
        return dict(r) if r else None

    # ═══════════════════════════════════════════════════════
    #  API KEYS
    # ═══════════════════════════════════════════════════════

    async def create_api_key(self, user_id: str, name: str, permissions: List[str] = None, expires_days: int = None) -> Dict:
        pool = self._pool()
        raw_key = f"eso_{secrets.token_urlsafe(32)}"
        key_id = f"key_{uuid.uuid4().hex[:12]}"
        expires_at = (datetime.utcnow() + timedelta(days=expires_days)) if expires_days else None

        async with pool.acquire() as c:
            await c.execute(
                "INSERT INTO api_keys (key_id,key_hash,key_prefix,user_id,name,permissions,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                key_id, _hash_key(raw_key), raw_key[:12], user_id, name, permissions or ["read", "execute"], expires_at
            )
        return {"key_id": key_id, "api_key": raw_key, "prefix": raw_key[:12], "name": name,
                "permissions": permissions or ["read", "execute"],
                "expires_at": expires_at.isoformat() if expires_at else None,
                "message": "Save this key — it won't be shown again"}

    async def verify_api_key(self, raw_key: str) -> Optional[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            r = await c.fetchrow(
                """SELECT k.key_id,k.user_id,k.permissions,k.is_active,k.expires_at,
                          u.email,u.username,u.role,u.tenant_id
                   FROM api_keys k JOIN users u ON k.user_id=u.user_id WHERE k.key_hash=$1""",
                _hash_key(raw_key)
            )
        if not r or not r["is_active"]:
            return None
        if r["expires_at"] and r["expires_at"] < datetime.utcnow():
            return None
        # Touch last_used
        async with pool.acquire() as c:
            await c.execute("UPDATE api_keys SET last_used_at=NOW() WHERE key_id=$1", r["key_id"])
        return {"sub": r["user_id"], "email": r["email"], "username": r["username"],
                "role": r["role"], "tenant_id": r["tenant_id"],
                "permissions": list(r["permissions"]), "auth_method": "api_key"}

    async def list_api_keys(self, user_id: str) -> List[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                "SELECT key_id,key_prefix,name,permissions,is_active,last_used_at,expires_at,created_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC",
                user_id
            )
        return [dict(r) for r in rows]

    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        pool = self._pool()
        async with pool.acquire() as c:
            res = await c.execute("UPDATE api_keys SET is_active=FALSE WHERE key_id=$1 AND user_id=$2", key_id, user_id)
        return "UPDATE 1" in res

    # ═══════════════════════════════════════════════════════
    #  SCAN HISTORY
    # ═══════════════════════════════════════════════════════

    async def save_scan(self, data: Dict) -> bool:
        pool = self._pool()
        try:
            async with pool.acquire() as c:
                await c.execute(
                    """INSERT INTO scan_history
                       (process_id,user_id,tenant_id,goal,target,status,
                        total_tasks,completed_tasks,failed_tasks,dynamic_tasks,
                        findings_count,risk_score,risk_level,tools_used,
                        llm_calls,duration_seconds,report,error,started_at,completed_at)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
                       ON CONFLICT (process_id) DO UPDATE SET
                        status=EXCLUDED.status, completed_tasks=EXCLUDED.completed_tasks,
                        findings_count=EXCLUDED.findings_count, risk_score=EXCLUDED.risk_score,
                        risk_level=EXCLUDED.risk_level, report=EXCLUDED.report, completed_at=EXCLUDED.completed_at""",
                    data.get("process_id"), data.get("user_id"), data.get("tenant_id", "default"),
                    data.get("goal", ""), data.get("target"), data.get("status", "completed"),
                    data.get("total_tasks", 0), data.get("completed_tasks", 0),
                    data.get("failed_tasks", 0), data.get("dynamic_tasks", 0),
                    data.get("findings_count", 0), data.get("risk_score", 0.0),
                    data.get("risk_level", "none"), data.get("tools_used", []),
                    data.get("llm_calls", 0), data.get("duration_seconds", 0.0),
                    data.get("report"), data.get("error"),
                    data.get("started_at"), data.get("completed_at")
                )
            return True
        except Exception as e:
            logger.error(f"❌ save_scan failed: {e}")
            return False

    async def get_scans(self, user_id: str, limit: int = 20, offset: int = 0) -> List[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT process_id,goal,target,status,total_tasks,completed_tasks,
                          findings_count,risk_score,risk_level,tools_used,
                          duration_seconds,created_at,completed_at
                   FROM scan_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3""",
                user_id, limit, offset
            )
        return [dict(r) for r in rows]

    async def get_scan(self, process_id: str, user_id: str) -> Optional[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            r = await c.fetchrow("SELECT * FROM scan_history WHERE process_id=$1 AND user_id=$2", process_id, user_id)
        return dict(r) if r else None

    async def get_scan_count(self, user_id: str) -> int:
        pool = self._pool()
        async with pool.acquire() as c:
            return await c.fetchval("SELECT COUNT(*) FROM scan_history WHERE user_id=$1", user_id)

    # ═══════════════════════════════════════════════════════
    #  FINDINGS
    # ═══════════════════════════════════════════════════════

    async def save_findings(self, process_id: str, user_id: str, findings: List[Dict]) -> int:
        """Save individual findings to PostgreSQL. Returns count saved."""
        pool = self._pool()
        saved = 0
        try:
            async with pool.acquire() as c:
                for f in findings:
                    fid = f"find_{uuid.uuid4().hex[:12]}"
                    await c.execute(
                        """INSERT INTO findings
                           (finding_id,process_id,user_id,type,severity,source,
                            port,protocol,service,version,state,finding,template,
                            path,status_code,risk_score,validated,false_positive,impact,raw_data)
                           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
                           ON CONFLICT (finding_id) DO NOTHING""",
                        fid, process_id, user_id,
                        f.get("type", "unknown"),
                        f.get("validated_severity", f.get("severity", "info")),
                        f.get("source", "unknown"),
                        f.get("port"), f.get("protocol"), f.get("service"),
                        str(f.get("version", ""))[:200], f.get("state"),
                        str(f.get("finding", ""))[:2000],
                        f.get("template"), f.get("path"),
                        f.get("status_code"),
                        f.get("risk_score", 0.0),
                        f.get("validated", False),
                        f.get("false_positive", False),
                        f.get("impact"),
                        json.dumps(f)
                    )
                    saved += 1
            logger.info(f"💾 Saved {saved} findings for {process_id}")
        except Exception as e:
            logger.error(f"❌ save_findings failed: {e}")
        return saved

    async def get_findings(self, process_id: str, user_id: str) -> List[Dict]:
        """Get all findings for a scan."""
        pool = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT finding_id,type,severity,source,port,protocol,service,version,
                          state,finding,template,path,status_code,risk_score,
                          validated,false_positive,impact,created_at
                   FROM findings WHERE process_id=$1 AND user_id=$2
                   ORDER BY risk_score DESC, created_at""",
                process_id, user_id
            )
        return [dict(r) for r in rows]

    async def search_findings(
        self, user_id: str,
        severity: str = None, source: str = None, finding_type: str = None,
        port: int = None, search: str = None,
        limit: int = 50, offset: int = 0
    ) -> Dict:
        """Search findings across all scans for a user."""
        pool = self._pool()

        conditions = ["user_id = $1"]
        params: list = [user_id]
        idx = 2

        if severity:
            conditions.append(f"severity = ${idx}")
            params.append(severity)
            idx += 1
        if source:
            conditions.append(f"source = ${idx}")
            params.append(source)
            idx += 1
        if finding_type:
            conditions.append(f"type = ${idx}")
            params.append(finding_type)
            idx += 1
        if port:
            conditions.append(f"port = ${idx}")
            params.append(port)
            idx += 1
        if search:
            conditions.append(f"(finding ILIKE ${idx} OR service ILIKE ${idx} OR template ILIKE ${idx})")
            params.append(f"%{search}%")
            idx += 1

        where = " AND ".join(conditions)

        async with pool.acquire() as c:
            total = await c.fetchval(f"SELECT COUNT(*) FROM findings WHERE {where}", *params)

            params_with_limit = params + [limit, offset]
            rows = await c.fetch(
                f"""SELECT f.finding_id, f.process_id, f.type, f.severity, f.source,
                           f.port, f.protocol, f.service, f.version, f.state,
                           f.finding, f.template, f.path, f.status_code,
                           f.risk_score, f.validated, f.false_positive,
                           f.created_at, s.target
                    FROM findings f
                    LEFT JOIN scan_history s ON f.process_id = s.process_id
                    WHERE {where}
                    ORDER BY f.risk_score DESC, f.created_at DESC
                    LIMIT ${idx} OFFSET ${idx + 1}""",
                *params_with_limit
            )

        return {"findings": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

    async def get_finding_stats(self, user_id: str) -> Dict:
        """Get aggregated finding statistics for a user."""
        pool = self._pool()
        async with pool.acquire() as c:
            total = await c.fetchval("SELECT COUNT(*) FROM findings WHERE user_id=$1", user_id)
            by_severity = await c.fetch(
                "SELECT severity, COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY severity ORDER BY count DESC", user_id
            )
            by_source = await c.fetch(
                "SELECT source, COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY source ORDER BY count DESC", user_id
            )
            by_type = await c.fetch(
                "SELECT type, COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY type ORDER BY count DESC", user_id
            )
            top_ports = await c.fetch(
                "SELECT port, service, COUNT(*) as count FROM findings WHERE user_id=$1 AND port IS NOT NULL GROUP BY port, service ORDER BY count DESC LIMIT 10",
                user_id
            )
        return {
            "total": total,
            "by_severity": {r["severity"]: r["count"] for r in by_severity},
            "by_source": {r["source"]: r["count"] for r in by_source},
            "by_type": {r["type"]: r["count"] for r in by_type},
            "top_ports": [dict(r) for r in top_ports],
        }


# Singleton
user_service = UserService()
