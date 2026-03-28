# src/scheduler/lifecycle_manager.py
from enum import Enum
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable
import asyncio

from src.models.execution import ExecutionStatus, TaskStatus
from src.utils.logging import logger


class LifecycleManager:
    """
    Enterprise Lifecycle Manager
    
    Manages the complete lifecycle of executions:
    - State transitions
    - Event notifications
    - Timeout handling
    - Pause/resume/cancel operations
    """
    
    def __init__(self):
        self.executions: Dict[str, Dict] = {}
        self.listeners: Dict[str, List[Callable]] = {}
        self.timeouts: Dict[str, asyncio.Task] = {}
        
        logger.info("✅ Lifecycle Manager initialized")
    
    async def create_execution(
        self,
        process_id: str,
        user_id: str,
        tenant_id: str,
        initial_status: ExecutionStatus = ExecutionStatus.PENDING
    ) -> Dict:
        """Create new execution record"""
        
        execution = {
            "process_id": process_id,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "status": initial_status.value,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "tasks": {},
            "timeline": [
                {
                    "status": initial_status.value,
                    "timestamp": datetime.utcnow()
                }
            ]
        }
        
        self.executions[process_id] = execution
        
        await self._notify_listeners(process_id, initial_status)
        
        return execution
    
    async def transition(
        self,
        process_id: str,
        new_status: ExecutionStatus,
        reason: Optional[str] = None
    ) -> bool:
        """Transition execution to new status"""
        
        if process_id not in self.executions:
            logger.error(f"Execution {process_id} not found")
            return False
        
        execution = self.executions[process_id]
        old_status = execution["status"]
        
        # Validate transition
        if not self._is_valid_transition(old_status, new_status.value):
            logger.warning(
                f"Invalid transition: {old_status} -> {new_status.value}",
                extra={"process_id": process_id}
            )
            return False
        
        # Update status
        execution["status"] = new_status.value
        execution["updated_at"] = datetime.utcnow().isoformat()
        
        # Add to timeline
        execution["timeline"].append({
            "status": new_status.value,
            "timestamp": datetime.utcnow().isoformat(),
            "reason": reason
        })
        
        # Handle special statuses
        if new_status == ExecutionStatus.COMPLETED:
            execution["completed_at"] = datetime.utcnow().isoformat()
            await self._cancel_timeout(process_id)
        
        elif new_status == ExecutionStatus.FAILED:
            execution["failed_at"] = datetime.utcnow().isoformat()
            await self._cancel_timeout(process_id)
        
        elif new_status == ExecutionStatus.RUNNING:
            execution["started_at"] = datetime.utcnow().isoformat()
        
        logger.info(
            f"Execution {process_id} transitioned: {old_status} -> {new_status.value}",
            extra={
                "process_id": process_id,
                "old_status": old_status,
                "new_status": new_status.value
            }
        )
        
        # Notify listeners
        await self._notify_listeners(process_id, new_status)
        
        return True
    
    def _is_valid_transition(self, old: str, new: str) -> bool:
        """Check if status transition is valid"""
        
        # Define valid transitions
        valid_transitions = {
            "pending": ["planning", "cancelled"],
            "planning": ["validating", "failed", "cancelled"],
            "validating": ["queued", "failed", "cancelled"],
            "queued": ["running", "cancelled"],
            "running": ["paused", "completed", "failed", "cancelled", "timeout"],
            "paused": ["running", "cancelled"],
            "completed": [],
            "failed": [],
            "cancelled": [],
            "timeout": []
        }
        
        return new in valid_transitions.get(old, [])
    
    async def update_task(
        self,
        process_id: str,
        task_id: str,
        status: TaskStatus,
        details: Optional[Dict] = None
    ) -> bool:
        """Update task status"""
        
        if process_id not in self.executions:
            return False
        
        execution = self.executions[process_id]
        
        if "tasks" not in execution:
            execution["tasks"] = {}
        
        if task_id not in execution["tasks"]:
            execution["tasks"][task_id] = {
                "created_at": datetime.utcnow()
            }
        
        task = execution["tasks"][task_id]
        task["status"] = status.value
        task["updated_at"] = datetime.utcnow()
        
        if details:
            task.update(details)
        
        if status == TaskStatus.RUNNING:
            task["started_at"] = datetime.utcnow()
        elif status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
            task["completed_at"] = datetime.utcnow()
        
        return True
    
    async def set_timeout(
        self,
        process_id: str,
        timeout_seconds: int,
        callback: Optional[Callable] = None
    ):
        """Set timeout for execution"""
        
        async def timeout_handler():
            await asyncio.sleep(timeout_seconds)
            
            if process_id in self.executions:
                execution = self.executions[process_id]
                if execution["status"] in ["running", "queued", "planning"]:
                    await self.transition(
                        process_id,
                        ExecutionStatus.TIMEOUT,
                        f"Execution timed out after {timeout_seconds}s"
                    )
                    
                    if callback:
                        await callback(process_id)
        
        # Cancel existing timeout
        await self._cancel_timeout(process_id)
        
        # Create new timeout task
        task = asyncio.create_task(timeout_handler())
        self.timeouts[process_id] = task
        
        logger.debug(f"Set timeout {timeout_seconds}s for {process_id}")
    
    async def _cancel_timeout(self, process_id: str):
        """Cancel timeout for execution"""
        
        if process_id in self.timeouts:
            self.timeouts[process_id].cancel()
            del self.timeouts[process_id]
    
    async def pause(self, process_id: str) -> bool:
        """Pause execution"""
        return await self.transition(
            process_id,
            ExecutionStatus.PAUSED,
            "Execution paused by user"
        )
    
    async def resume(self, process_id: str) -> bool:
        """Resume execution"""
        return await self.transition(
            process_id,
            ExecutionStatus.RUNNING,
            "Execution resumed by user"
        )
    
    async def cancel(self, process_id: str) -> bool:
        """Cancel execution"""
        return await self.transition(
            process_id,
            ExecutionStatus.CANCELLED,
            "Execution cancelled by user"
        )
    
    async def on_status_change(
        self,
        callback: Callable,
        status: Optional[ExecutionStatus] = None
    ) -> str:
        """Register callback for status changes"""
        
        listener_id = f"listener_{len(self.listeners)}"
        
        if listener_id not in self.listeners:
            self.listeners[listener_id] = []
        
        self.listeners[listener_id].append({
            "callback": callback,
            "status": status.value if status else None
        })
        
        return listener_id
    
    async def _notify_listeners(self, process_id: str, status: ExecutionStatus):
        """Notify listeners of status change"""
        
        for listeners in self.listeners.values():
            for listener in listeners:
                if not listener["status"] or listener["status"] == status.value:
                    try:
                        await listener["callback"](process_id, status)
                    except Exception as e:
                        logger.error(f"Listener callback failed: {e}")
    
    def get_execution(self, process_id: str) -> Optional[Dict]:
        """Get execution details"""
        return self.executions.get(process_id)
    
    def get_timeline(self, process_id: str) -> List[Dict]:
        """Get execution timeline"""
        
        execution = self.executions.get(process_id)
        if not execution:
            return []
        
        return execution.get("timeline", [])
    
    def list_executions(
        self,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """List executions with filters"""
        
        results = list(self.executions.values())
        
        if user_id:
            results = [e for e in results if e["user_id"] == user_id]
        if tenant_id:
            results = [e for e in results if e["tenant_id"] == tenant_id]
        if status:
            results = [e for e in results if e["status"] == status]
        
        # Sort by created_at descending
        results.sort(key=lambda x: x["created_at"], reverse=True)
        
        return results[:limit]