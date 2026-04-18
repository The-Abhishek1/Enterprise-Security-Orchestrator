# src/services/schedule_service.py

"""
Scan Templates + Scheduled Scans.
Templates: reusable scan configs.
Schedules: cron-like recurring scans using templates.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import uuid
import json
import asyncio

from src.core.database import db_manager
from src.utils.logging import logger


def _parse_cron(expression: str, from_time: datetime = None) -> Optional[datetime]:
    """
    Simple cron parser — supports: hourly, daily, weekly, monthly, or interval like '4h', '12h', '7d'.
    Full cron expressions (5-field) are parsed for common patterns.
    Returns the next run time.
    """
    now = from_time or datetime.utcnow()
    expr = expression.strip().lower()

    # Shorthand intervals
    if expr.endswith('m') and expr[:-1].isdigit():
        return now + timedelta(minutes=int(expr[:-1]))
    if expr.endswith('h') and expr[:-1].isdigit():
        return now + timedelta(hours=int(expr[:-1]))
    if expr.endswith('d') and expr[:-1].isdigit():
        return now + timedelta(days=int(expr[:-1]))

    # Named shortcuts
    shortcuts = {
        'hourly': timedelta(hours=1),
        'daily': timedelta(days=1),
        'weekly': timedelta(weeks=1),
        'monthly': timedelta(days=30),
    }
    if expr in shortcuts:
        return now + shortcuts[expr]

    # 5-field cron: try common patterns
    parts = expr.split()
    if len(parts) == 5:
        # */N in minutes field = every N minutes
        if parts[0].startswith('*/') and parts[0][2:].isdigit():
            return now + timedelta(minutes=int(parts[0][2:]))
        # 0 */N = every N hours
        if parts[0] == '0' and parts[1].startswith('*/') and parts[1][2:].isdigit():
            return now + timedelta(hours=int(parts[1][2:]))
        # 0 0 * * * = daily at midnight
        if parts[:3] == ['0', '0', '*']:
            next_day = now.replace(hour=0, minute=0, second=0) + timedelta(days=1)
            return next_day
        # 0 0 * * 0 = weekly on Sunday
        if parts[:3] == ['0', '0', '*'] and parts[4] == '0':
            days_until_sunday = (6 - now.weekday()) % 7 or 7
            return now.replace(hour=0, minute=0, second=0) + timedelta(days=days_until_sunday)

    # Fallback: daily
    logger.warning(f"⚠️ Unrecognized cron '{expression}', defaulting to daily")
    return now + timedelta(days=1)


class ScheduleService:

    def _pool(self):
        p = db_manager.pg_pool
        if not p:
            raise Exception("Database not available")
        return p

    # ═══════════════════════════════════════════════════════
    #  TEMPLATES
    # ═══════════════════════════════════════════════════════

    async def create_template(self, user_id: str, name: str, target: str, goal: str,
                               description: str = None, parameters: Dict = None,
                               tags: List[str] = None, tenant_id: str = "default") -> Dict:
        pool = self._pool()
        tid = f"tmpl_{uuid.uuid4().hex[:12]}"
        async with pool.acquire() as c:
            await c.execute(
                """INSERT INTO scan_templates
                   (template_id,user_id,tenant_id,name,description,target,goal,parameters,tags)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)""",
                tid, user_id, tenant_id, name, description, target, goal,
                json.dumps(parameters or {}), tags or []
            )
        logger.info(f"📋 Template created: {name} ({tid})")
        return {"template_id": tid, "name": name, "target": target, "goal": goal}

    async def list_templates(self, user_id: str) -> List[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT template_id,name,description,target,goal,parameters,tags,is_active,created_at,updated_at
                   FROM scan_templates WHERE user_id=$1 ORDER BY created_at DESC""",
                user_id
            )
        results = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("parameters"), str):
                try: d["parameters"] = json.loads(d["parameters"])
                except: pass
            results.append(d)
        return results

    async def get_template(self, template_id: str, user_id: str) -> Optional[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            r = await c.fetchrow(
                "SELECT * FROM scan_templates WHERE template_id=$1 AND user_id=$2", template_id, user_id
            )
        if not r:
            return None
        d = dict(r)
        if isinstance(d.get("parameters"), str):
            try: d["parameters"] = json.loads(d["parameters"])
            except: pass
        return d

    async def update_template(self, template_id: str, user_id: str, updates: Dict) -> bool:
        pool = self._pool()
        fields = []
        params = []
        idx = 1
        for key in ["name", "description", "target", "goal", "is_active"]:
            if key in updates:
                fields.append(f"{key}=${idx}")
                params.append(updates[key])
                idx += 1
        if "parameters" in updates:
            fields.append(f"parameters=${idx}")
            params.append(json.dumps(updates["parameters"]))
            idx += 1
        if "tags" in updates:
            fields.append(f"tags=${idx}")
            params.append(updates["tags"])
            idx += 1
        if not fields:
            return False
        fields.append(f"updated_at=${idx}")
        params.append(datetime.utcnow())
        idx += 1
        params.extend([template_id, user_id])
        async with pool.acquire() as c:
            res = await c.execute(
                f"UPDATE scan_templates SET {','.join(fields)} WHERE template_id=${idx} AND user_id=${idx+1}",
                *params
            )
        return "UPDATE 1" in res

    async def delete_template(self, template_id: str, user_id: str) -> bool:
        pool = self._pool()
        async with pool.acquire() as c:
            res = await c.execute(
                "DELETE FROM scan_templates WHERE template_id=$1 AND user_id=$2", template_id, user_id
            )
        return "DELETE 1" in res

    # ═══════════════════════════════════════════════════════
    #  SCHEDULED SCANS
    # ═══════════════════════════════════════════════════════

    async def create_schedule(self, user_id: str, template_id: str, cron_expression: str,
                               max_runs: int = None, tenant_id: str = "default") -> Dict:
        pool = self._pool()
        sid = f"sched_{uuid.uuid4().hex[:12]}"
        next_run = _parse_cron(cron_expression)

        # Verify template exists
        tmpl = await self.get_template(template_id, user_id)
        if not tmpl:
            raise Exception(f"Template {template_id} not found")

        async with pool.acquire() as c:
            await c.execute(
                """INSERT INTO scheduled_scans
                   (schedule_id,user_id,tenant_id,template_id,cron_expression,next_run_at,max_runs)
                   VALUES ($1,$2,$3,$4,$5,$6,$7)""",
                sid, user_id, tenant_id, template_id, cron_expression, next_run, max_runs
            )
        logger.info(f"⏰ Schedule created: {sid} (template: {template_id}, cron: {cron_expression}, next: {next_run})")
        return {
            "schedule_id": sid, "template_id": template_id,
            "cron_expression": cron_expression,
            "next_run_at": next_run.isoformat() if next_run else None,
            "template_name": tmpl["name"], "target": tmpl["target"]
        }

    async def list_schedules(self, user_id: str) -> List[Dict]:
        pool = self._pool()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT s.schedule_id, s.template_id, s.cron_expression, s.is_active,
                          s.last_run_at, s.next_run_at, s.run_count,
                          s.max_runs, s.created_at,
                          t.name as template_name, t.target, t.goal
                   FROM scheduled_scans s
                   JOIN scan_templates t ON s.template_id = t.template_id
                   WHERE s.user_id=$1 ORDER BY s.created_at DESC""",
                user_id
            )
        return [dict(r) for r in rows]

    async def toggle_schedule(self, schedule_id: str, user_id: str, active: bool) -> bool:
        pool = self._pool()
        async with pool.acquire() as c:
            res = await c.execute(
                "UPDATE scheduled_scans SET is_active=$1 WHERE schedule_id=$2 AND user_id=$3",
                active, schedule_id, user_id
            )
        return "UPDATE 1" in res

    async def delete_schedule(self, schedule_id: str, user_id: str) -> bool:
        pool = self._pool()
        async with pool.acquire() as c:
            res = await c.execute(
                "DELETE FROM scheduled_scans WHERE schedule_id=$1 AND user_id=$2", schedule_id, user_id
            )
        return "DELETE 1" in res

    # ═══════════════════════════════════════════════════════
    #  CRON RUNNER
    # ═══════════════════════════════════════════════════════

    async def get_due_schedules(self) -> List[Dict]:
        """Get all schedules that are due to run now."""
        pool = self._pool()
        now = datetime.utcnow()
        async with pool.acquire() as c:
            rows = await c.fetch(
                """SELECT s.*, t.target, t.goal, t.parameters
                   FROM scheduled_scans s
                   JOIN scan_templates t ON s.template_id = t.template_id
                   WHERE s.is_active = TRUE AND s.next_run_at <= $1
                   AND (s.max_runs IS NULL OR s.run_count < s.max_runs)""",
                now
            )
        return [dict(r) for r in rows]

    async def mark_run(self, schedule_id: str, process_id: str):
        """Update schedule after a run."""
        pool = self._pool()
        async with pool.acquire() as c:
            # Get current cron expression to calculate next run
            row = await c.fetchrow(
                "SELECT cron_expression FROM scheduled_scans WHERE schedule_id=$1", schedule_id
            )
            if not row:
                return
            next_run = _parse_cron(row["cron_expression"])
            await c.execute(
                """UPDATE scheduled_scans SET
                   last_run_at=NOW(), next_run_at=$1, run_count=run_count+1
                   WHERE schedule_id=$3""",
                next_run, process_id, schedule_id
            )


# Singleton
schedule_service = ScheduleService()
