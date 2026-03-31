# src/services/cron_runner.py

"""
Background cron runner — checks for due scheduled scans and triggers them.
Started on app startup, runs every 60 seconds.
"""

import asyncio
import uuid

from src.services.schedule_service import schedule_service
from src.utils.logging import logger


class CronRunner:
    """Periodically checks for due scheduled scans and triggers them."""

    def __init__(self):
        self._task: asyncio.Task = None
        self._running = False
        self._scheduler = None  # Set from app.py

    def set_scheduler(self, scheduler):
        """Inject the hybrid scheduler for executing scans."""
        self._scheduler = scheduler

    async def start(self):
        """Start the cron loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("⏰ Cron runner started (checking every 60s)")

    async def stop(self):
        """Stop the cron loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("⏰ Cron runner stopped")

    async def _loop(self):
        """Main loop — check for due scans every 60 seconds."""
        while self._running:
            try:
                await self._tick()
            except Exception as e:
                logger.error(f"⏰ Cron tick error: {e}")
            await asyncio.sleep(60)

    async def _tick(self):
        """Single tick — find and execute due scans."""
        if not self._scheduler:
            return

        try:
            due = await schedule_service.get_due_schedules()
        except Exception:
            return  # DB not ready yet

        if not due:
            return

        logger.info(f"⏰ Found {len(due)} due scheduled scan(s)")

        for sched in due:
            try:
                process_id = f"proc_{uuid.uuid4().hex[:12]}"
                target = sched.get("target", "")
                goal = sched.get("goal", f"Scheduled scan of {target}")

                logger.info(f"⏰ Triggering scheduled scan: {sched['schedule_id']} → {target} (pid: {process_id})")

                # Trigger scan via scheduler
                asyncio.create_task(
                    self._scheduler.schedule_execution(
                        goal=goal,
                        target=target,
                        user_id=sched["user_id"],
                        tenant_id=sched.get("tenant_id", "default"),
                        budget_limit=None,
                        priority=5,
                        parameters={"scheduled": True, "schedule_id": sched["schedule_id"]},
                        process_id=process_id
                    )
                )

                # Update schedule with next run time
                await schedule_service.mark_run(sched["schedule_id"], process_id)

                # Disable if max runs reached
                if sched.get("max_runs") and (sched.get("run_count", 0) + 1) >= sched["max_runs"]:
                    await schedule_service.toggle_schedule(
                        sched["schedule_id"], sched["user_id"], False
                    )
                    logger.info(f"⏰ Schedule {sched['schedule_id']} reached max runs, disabled")

            except Exception as e:
                logger.error(f"⏰ Failed to trigger schedule {sched.get('schedule_id')}: {e}")


# Singleton
cron_runner = CronRunner()
