# src/services/collaboration.py

"""
Collaboration — teams, members, shared scans, finding comments.
"""

from typing import Dict, List, Optional
from datetime import datetime
import uuid
import json

from src.core.database import db_manager
from src.utils.logging import logger


class CollaborationService:

    def _pool(self):
        p = db_manager.pg_pool
        if not p:
            raise Exception("Database not available")
        return p

    # ═══ TEAMS ═══

    async def create_team(self, owner_id: str, name: str, description: str = None, tenant_id: str = "default") -> Dict:
        pool = self._pool()
        tid = f"team_{uuid.uuid4().hex[:12]}"
        async with pool.acquire() as c:
            await c.execute(
                "INSERT INTO teams (team_id,name,description,owner_id,tenant_id) VALUES ($1,$2,$3,$4,$5)",
                tid, name, description, owner_id, tenant_id
            )
            # Owner is auto-added as admin
            await c.execute(
                "INSERT INTO team_members (team_id,user_id,role,invited_by) VALUES ($1,$2,'admin',$2)",
                tid, owner_id
            )
        return {"team_id": tid, "name": name, "role": "admin"}

    async def list_teams(self, user_id: str) -> List[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT t.team_id, t.name, t.description, t.owner_id, t.created_at, tm.role,
                          (SELECT COUNT(*) FROM team_members WHERE team_id=t.team_id) as member_count
                   FROM teams t JOIN team_members tm ON t.team_id=tm.team_id
                   WHERE tm.user_id=$1 ORDER BY t.created_at DESC""",
                user_id
            )
        return [dict(r) for r in rows]

    async def get_team_members(self, team_id: str, user_id: str) -> List[Dict]:
        pool = self._pool()
        # Verify user is in team
        async with pool.acquire() as c:
            member = await c.fetchrow("SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2", team_id, user_id)
            if not member:
                raise Exception("Not a member of this team")
            rows = await c.fetch(
                """SELECT tm.user_id, tm.role, tm.joined_at, u.username, u.email
                   FROM team_members tm JOIN users u ON tm.user_id=u.user_id
                   WHERE tm.team_id=$1 ORDER BY tm.joined_at""",
                team_id
            )
        return [dict(r) for r in rows]

    async def invite_member(self, team_id: str, inviter_id: str, invite_email: str, role: str = "member") -> Dict:
        pool = self._pool()
        async with pool.acquire() as c:
            # Check inviter is admin/owner
            inviter = await c.fetchrow("SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2", team_id, inviter_id)
            if not inviter or inviter["role"] not in ("admin", "owner"):
                raise Exception("Only admins can invite")
            # Find user by email
            target = await c.fetchrow("SELECT user_id, username FROM users WHERE email=$1", invite_email)
            if not target:
                raise Exception(f"User with email {invite_email} not found")
            # Add to team
            await c.execute(
                "INSERT INTO team_members (team_id,user_id,role,invited_by) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
                team_id, target["user_id"], role, inviter_id
            )
        return {"user_id": target["user_id"], "username": target["username"], "role": role}

    async def remove_member(self, team_id: str, remover_id: str, target_user_id: str) -> bool:
        pool = self._pool()
        async with pool.acquire() as c:
            remover = await c.fetchrow("SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2", team_id, remover_id)
            if not remover or remover["role"] not in ("admin", "owner"):
                raise Exception("Only admins can remove members")
            res = await c.execute("DELETE FROM team_members WHERE team_id=$1 AND user_id=$2", team_id, target_user_id)
        return "DELETE 1" in res

    async def get_team_scans(self, team_id: str, user_id: str) -> List[Dict]:
        """Get scans from all team members."""
        pool = self._pool()
        async with pool.acquire() as c:
            member = await c.fetchrow("SELECT 1 FROM team_members WHERE team_id=$1 AND user_id=$2", team_id, user_id)
            if not member:
                raise Exception("Not a member")
            rows = await c.fetch(
                """SELECT sh.process_id, sh.target, sh.goal, sh.status, sh.findings_count,
                          sh.risk_level, sh.risk_score, sh.duration_seconds, sh.created_at,
                          u.username
                   FROM scan_history sh
                   JOIN team_members tm ON sh.user_id=tm.user_id AND tm.team_id=$1
                   JOIN users u ON sh.user_id=u.user_id
                   ORDER BY sh.created_at DESC LIMIT 50""",
                team_id
            )
        return [dict(r) for r in rows]

    # ═══ COMMENTS ═══

    async def add_comment(self, finding_id: str, process_id: str, user_id: str, username: str, content: str, comment_type: str = "manual") -> Dict:
        pool = self._pool()
        cid = f"cmt_{uuid.uuid4().hex[:12]}"
        async with pool.acquire() as c:
            await c.execute(
                "INSERT INTO finding_comments (comment_id,finding_id,process_id,user_id,username,content,comment_type) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                cid, finding_id, process_id, user_id, username, content, comment_type
            )
        return {"comment_id": cid, "content": content, "username": username, "comment_type": comment_type, "created_at": datetime.utcnow().isoformat()}

    async def get_comments(self, process_id: str, finding_id: str = None) -> List[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            if finding_id:
                rows = await c.fetch(
                    "SELECT * FROM finding_comments WHERE finding_id=$1 ORDER BY created_at", finding_id
                )
            else:
                rows = await c.fetch(
                    "SELECT * FROM finding_comments WHERE process_id=$1 ORDER BY created_at", process_id
                )
        return [dict(r) for r in rows]


collaboration_service = CollaborationService()
