"""
user_service.py — hardened user management.

Fixes vs original:
- login() now fetches and returns 'tier'
- login() resets scans_today on new day automatically
- register() validates email format and username chars
- brute-force protection via Redis (5 fails → 15min lockout)
- get_user() now returns tier
- scan isolation enforced in get_scan()
- update_tier() method for payment integration
- increment_scan_count() for daily quota tracking
"""
import uuid, secrets, hashlib, json, re
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from src.core.database import db_manager
from src.utils.logging import logger

try:
    import bcrypt
    _has_bcrypt = True
except ImportError:
    _has_bcrypt = False


# ── password helpers ────────────────────────────────────────────────────────
def _hash_pw(pw: str) -> str:
    if _has_bcrypt:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    return hashlib.sha256(pw.encode()).hexdigest()

def _check_pw(pw: str, hashed: str) -> bool:
    # Always try sha256 first (legacy hashes created before bcrypt was available)
    if hashlib.sha256(pw.encode()).hexdigest() == hashed:
        return True
    # Try bcrypt if available and hash looks like a bcrypt hash
    if _has_bcrypt and hashed.startswith("$2"):
        try:
            return bcrypt.checkpw(pw.encode(), hashed.encode())
        except Exception:
            return False
    return False

def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# ── validation ──────────────────────────────────────────────────────────────
EMAIL_RE    = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-\.]{3,32}$')

BRUTE_MAX_ATTEMPTS = 5
BRUTE_WINDOW_SEC   = 900   # 15 minutes


class UserService:

    def _pool(self):
        p = db_manager.pg_pool
        if not p:
            raise Exception("Database not available")
        return p

    def _redis(self):
        return db_manager.redis_client  # may be None

    # ── brute-force helpers ─────────────────────────────────────────────────
    async def _check_brute_force(self, email: str) -> bool:
        """Return True if locked out."""
        r = self._redis()
        if not r:
            return False
        key = f"bf:{hashlib.sha256(email.lower().encode()).hexdigest()[:16]}"
        try:
            count = await r.get(key)
            return int(count or 0) >= BRUTE_MAX_ATTEMPTS
        except Exception:
            return False

    async def _record_failed_login(self, email: str):
        r = self._redis()
        if not r:
            return
        key = f"bf:{hashlib.sha256(email.lower().encode()).hexdigest()[:16]}"
        try:
            pipe = r.pipeline()
            pipe.incr(key)
            pipe.expire(key, BRUTE_WINDOW_SEC)
            await pipe.execute()
        except Exception:
            pass

    async def _clear_brute_force(self, email: str):
        r = self._redis()
        if not r:
            return
        key = f"bf:{hashlib.sha256(email.lower().encode()).hexdigest()[:16]}"
        try:
            await r.delete(key)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # USERS
    # ═══════════════════════════════════════════════════════════════════════

    async def register(self, email: str, username: str, password: str, role: str = "user") -> Dict:
        # Validate
        if not EMAIL_RE.match(email):
            raise ValueError("Invalid email format")
        if not USERNAME_RE.match(username):
            raise ValueError("Username must be 3-32 chars: letters, numbers, _ - .")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        # Reject obviously weak passwords
        if password.lower() in ("password", "12345678", "qwerty123", "password1"):
            raise ValueError("Password is too common")

        user_id = f"user_{uuid.uuid4().hex[:12]}"
        pool    = self._pool()
        try:
            async with pool.acquire() as c:
                await c.execute(
                    """INSERT INTO users
                       (user_id,email,username,password_hash,role,tier,tenant_id)
                       VALUES ($1,$2,$3,$4,$5,'free','default')""",
                    user_id, email.lower().strip(), username, _hash_pw(password), role
                )
            logger.info(f"✅ User registered: {username} ({user_id})")
            return {"user_id": user_id, "email": email.lower().strip(),
                    "username": username, "role": role, "tier": "free"}
        except Exception as e:
            if "unique" in str(e).lower():
                raise Exception("Email or username already exists")
            raise

    async def login(self, email: str, password: str) -> Optional[Dict]:
        # Brute-force check
        if await self._check_brute_force(email):
            raise Exception("Account temporarily locked. Too many failed attempts. Try again in 15 minutes.")

        pool = self._pool()
        async with pool.acquire() as c:
            r = await c.fetchrow(
                """SELECT user_id,email,username,password_hash,role,tier,
                          tenant_id,is_active,scans_today,scans_today_reset
                   FROM users WHERE email=$1""",
                email.lower().strip()
            )

        if not r:
            await self._record_failed_login(email)
            return None

        if not r["is_active"]:
            raise Exception("Account is disabled. Contact support.")

        if not _check_pw(password, r["password_hash"]):
            await self._record_failed_login(email)
            return None

        # Successful login
        await self._clear_brute_force(email)

        # Reset daily scan counter if it's a new day
        reset_ts = r["scans_today_reset"]
        if reset_ts and (datetime.utcnow() - reset_ts).total_seconds() > 86400:
            async with pool.acquire() as c:
                await c.execute(
                    "UPDATE users SET scans_today=0, scans_today_reset=NOW(), updated_at=NOW() WHERE user_id=$1",
                    r["user_id"]
                )

        return {
            "user_id":   r["user_id"],
            "email":     r["email"],
            "username":  r["username"],
            "role":      r["role"] or "user",
            "tier":      r["tier"] or "free",
            "tenant_id": r["tenant_id"] or "default",
        }

    async def get_user(self, user_id: str) -> Optional[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            r = await c.fetchrow(
                """SELECT user_id,email,username,role,tier,tenant_id,
                          is_active,scans_today,total_scans,created_at
                   FROM users WHERE user_id=$1""",
                user_id
            )
        return dict(r) if r else None

    async def update_tier(self, user_id: str, tier: str) -> bool:
        """Upgrade/downgrade a user's tier. Called by payment verification."""
        valid_tiers = {"free", "pro", "enterprise", "admin"}
        if tier not in valid_tiers:
            raise ValueError(f"Invalid tier: {tier}")
        pool = self._pool()
        try:
            async with pool.acquire() as c:
                result = await c.execute(
                    "UPDATE users SET tier=$1, updated_at=NOW() WHERE user_id=$2",
                    tier, user_id
                )
            logger.info(f"✅ User {user_id} tier → {tier}")
            return "UPDATE 1" in result
        except Exception as e:
            logger.error(f"update_tier failed: {e}")
            return False

    async def increment_scan_count(self, user_id: str) -> bool:
        """Increment scans_today and total_scans. Called after scan is queued."""
        pool = self._pool()
        try:
            async with pool.acquire() as c:
                await c.execute(
                    """UPDATE users
                       SET scans_today = CASE
                           WHEN scans_today_reset < NOW() - INTERVAL '1 day'
                           THEN 1
                           ELSE scans_today + 1
                       END,
                       scans_today_reset = CASE
                           WHEN scans_today_reset < NOW() - INTERVAL '1 day'
                           THEN NOW()
                           ELSE scans_today_reset
                       END,
                       total_scans = total_scans + 1,
                       updated_at  = NOW()
                       WHERE user_id = $1""",
                    user_id
                )
            return True
        except Exception as e:
            logger.error(f"increment_scan_count failed: {e}")
            return False

    # ═══════════════════════════════════════════════════════════════════════
    # API KEYS
    # ═══════════════════════════════════════════════════════════════════════

    async def create_api_key(self, user_id: str, name: str,
                              permissions: List[str] = None,
                              expires_days: int = None) -> Dict:
        if not name or len(name) > 100:
            raise ValueError("Key name must be 1-100 characters")
        pool    = self._pool()
        raw_key = f"eso_{secrets.token_urlsafe(32)}"
        key_id  = f"key_{uuid.uuid4().hex[:12]}"
        expires_at = datetime.utcnow() + timedelta(days=expires_days) if expires_days else None
        async with pool.acquire() as c:
            await c.execute(
                """INSERT INTO api_keys
                   (key_id,key_hash,key_prefix,user_id,name,permissions,expires_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7)""",
                key_id, _hash_key(raw_key), raw_key[:12], user_id,
                name, permissions or ["read","execute"], expires_at
            )
        return {
            "key_id": key_id, "api_key": raw_key, "prefix": raw_key[:12],
            "name": name, "permissions": permissions or ["read","execute"],
            "expires_at": expires_at.isoformat() if expires_at else None,
            "message": "Save this key — it won't be shown again",
        }

    async def verify_api_key(self, raw_key: str) -> Optional[Dict]:
        if not raw_key.startswith("eso_") or len(raw_key) < 20:
            return None
        pool = self._pool()
        async with pool.acquire() as c:
            r = await c.fetchrow(
                """SELECT k.key_id,k.user_id,k.permissions,k.is_active,k.expires_at,
                          u.email,u.username,u.role,u.tier,u.tenant_id,u.is_active as user_active
                   FROM api_keys k JOIN users u ON k.user_id=u.user_id
                   WHERE k.key_hash=$1""",
                _hash_key(raw_key)
            )
        if not r or not r["is_active"] or not r["user_active"]:
            return None
        if r["expires_at"] and r["expires_at"] < datetime.utcnow():
            return None
        # Touch last_used async
        async with pool.acquire() as c:
            await c.execute("UPDATE api_keys SET last_used_at=NOW() WHERE key_id=$1", r["key_id"])
        return {
            "sub": r["user_id"], "email": r["email"], "username": r["username"],
            "role": r["role"], "tier": r["tier"] or "free",
            "tenant_id": r["tenant_id"],
            "permissions": list(r["permissions"]), "auth_method": "api_key",
        }

    async def list_api_keys(self, user_id: str) -> List[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT key_id,key_prefix,name,permissions,is_active,
                          last_used_at,expires_at,created_at
                   FROM api_keys WHERE user_id=$1 AND is_active=TRUE
                   ORDER BY created_at DESC""",
                user_id
            )
        return [dict(r) for r in rows]

    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        pool = self._pool()
        async with pool.acquire() as c:
            res = await c.execute(
                "UPDATE api_keys SET is_active=FALSE WHERE key_id=$1 AND user_id=$2",
                key_id, user_id
            )
        return "UPDATE 1" in res

    # ═══════════════════════════════════════════════════════════════════════
    # SCAN HISTORY
    # ═══════════════════════════════════════════════════════════════════════

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
                        status=EXCLUDED.status,
                        completed_tasks=EXCLUDED.completed_tasks,
                        findings_count=EXCLUDED.findings_count,
                        risk_score=EXCLUDED.risk_score,
                        risk_level=EXCLUDED.risk_level,
                        report=EXCLUDED.report,
                        completed_at=EXCLUDED.completed_at""",
                    data.get("process_id"), data.get("user_id"),
                    data.get("tenant_id", "default"),
                    data.get("goal", ""), data.get("target"),
                    data.get("status", "completed"),
                    data.get("total_tasks", 0), data.get("completed_tasks", 0),
                    data.get("failed_tasks", 0), data.get("dynamic_tasks", 0),
                    data.get("findings_count", 0), data.get("risk_score", 0.0),
                    data.get("risk_level", "none"), data.get("tools_used", []),
                    data.get("llm_calls", 0), data.get("duration_seconds", 0.0),
                    data.get("report"), data.get("error"),
                    data.get("started_at"), data.get("completed_at"),
                )
            return True
        except Exception as e:
            logger.error(f"save_scan failed: {e}")
            return False

    async def get_scans(self, user_id: str, limit: int = 20, offset: int = 0) -> List[Dict]:
        # Clamp limit to prevent abuse
        limit = min(max(1, limit), 200)
        pool  = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT process_id,goal,target,status,total_tasks,completed_tasks,
                          findings_count,risk_score,risk_level,tools_used,
                          duration_seconds,created_at,completed_at
                   FROM scan_history WHERE user_id=$1
                   ORDER BY created_at DESC LIMIT $2 OFFSET $3""",
                user_id, limit, offset
            )
        return [dict(r) for r in rows]

    async def get_scan(self, process_id: str, user_id: Optional[str] = None) -> Optional[Dict]:
        """
        Fetch a single scan. If user_id is provided, enforces ownership.
        Pass user_id=None only for admin calls.
        """
        pool = self._pool()
        async with pool.acquire() as c:
            if user_id:
                # Strict user isolation
                r = await c.fetchrow(
                    "SELECT * FROM scan_history WHERE process_id=$1 AND user_id=$2",
                    process_id, user_id
                )
            else:
                r = await c.fetchrow(
                    "SELECT * FROM scan_history WHERE process_id=$1",
                    process_id
                )
        return dict(r) if r else None

    async def get_scan_count(self, user_id: str) -> int:
        pool = self._pool()
        async with pool.acquire() as c:
            return await c.fetchval(
                "SELECT COUNT(*) FROM scan_history WHERE user_id=$1", user_id
            )

    # ═══════════════════════════════════════════════════════════════════════
    # FINDINGS
    # ═══════════════════════════════════════════════════════════════════════

    async def save_findings(self, process_id: str, user_id: str, findings: List[Dict]) -> int:
        pool  = self._pool()
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
                        f.get("template"), f.get("path"), f.get("status_code"),
                        f.get("risk_score", 0.0),
                        f.get("validated", False), f.get("false_positive", False),
                        f.get("impact"), json.dumps(f)
                    )
                    saved += 1
            logger.info(f"💾 Saved {saved} findings for {process_id}")
        except Exception as e:
            logger.error(f"save_findings failed: {e}")
        return saved

    async def get_findings(self, process_id: str, user_id: str) -> List[Dict]:
        """Always enforces user_id isolation."""
        pool = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT finding_id,type,severity,source,port,protocol,service,
                          version,state,finding,template,path,status_code,
                          risk_score,validated,false_positive,impact,created_at
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
        limit = min(max(1, limit), 500)
        pool  = self._pool()

        conditions = ["f.user_id = $1"]
        params: list = [user_id]
        idx = 2

        if severity:
            conditions.append(f"f.severity = ${idx}"); params.append(severity); idx += 1
        if source:
            conditions.append(f"f.source = ${idx}"); params.append(source); idx += 1
        if finding_type:
            conditions.append(f"f.type = ${idx}"); params.append(finding_type); idx += 1
        if port:
            conditions.append(f"f.port = ${idx}"); params.append(port); idx += 1
        if search:
            # Sanitize: no LIKE wildcards from user input
            safe = search.replace("%","").replace("_","")[:100]
            conditions.append(
                f"(f.finding ILIKE ${idx} OR f.service ILIKE ${idx} OR f.template ILIKE ${idx})"
            )
            params.append(f"%{safe}%"); idx += 1

        where = " AND ".join(conditions)

        async with pool.acquire() as c:
            total = await c.fetchval(f"SELECT COUNT(*) FROM findings f WHERE {where}", *params)
            rows  = await c.fetch(
                f"""SELECT f.finding_id,f.process_id,f.type,f.severity,f.source,
                           f.port,f.protocol,f.service,f.version,f.state,
                           f.finding,f.template,f.path,f.status_code,
                           f.risk_score,f.validated,f.false_positive,
                           f.created_at,s.target
                    FROM findings f
                    LEFT JOIN scan_history s ON f.process_id=s.process_id AND s.user_id=f.user_id
                    WHERE {where}
                    ORDER BY f.risk_score DESC, f.created_at DESC
                    LIMIT ${idx} OFFSET ${idx+1}""",
                *(params + [limit, offset])
            )
        return {"findings": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

    async def get_finding_stats(self, user_id: str) -> Dict:
        pool = self._pool()
        async with pool.acquire() as c:
            total       = await c.fetchval("SELECT COUNT(*) FROM findings WHERE user_id=$1", user_id)
            by_severity = await c.fetch("SELECT severity,COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY severity ORDER BY count DESC", user_id)
            by_source   = await c.fetch("SELECT source,COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY source ORDER BY count DESC", user_id)
            by_type     = await c.fetch("SELECT type,COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY type ORDER BY count DESC", user_id)
            top_ports   = await c.fetch("SELECT port,service,COUNT(*) as count FROM findings WHERE user_id=$1 AND port IS NOT NULL GROUP BY port,service ORDER BY count DESC LIMIT 10", user_id)
        return {
            "total":       total,
            "by_severity": {r["severity"]: r["count"] for r in by_severity},
            "by_source":   {r["source"]:   r["count"] for r in by_source},
            "by_type":     {r["type"]:     r["count"] for r in by_type},
            "top_ports":   [dict(r) for r in top_ports],
        }


user_service = UserService()
