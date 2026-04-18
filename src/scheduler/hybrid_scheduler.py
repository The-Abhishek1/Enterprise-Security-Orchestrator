# src/scheduler/hybrid_scheduler.py
from typing import Optional, Dict, Any, List
from datetime import datetime
import asyncio
import uuid

from src.models.dag import DAG, TaskNode, TaskType, AgentCapability
from src.models.execution import Execution, ExecutionStatus, TaskStatus
from src.engine.execution_controller import ExecutionController
from src.scheduler.lifecycle_manager import LifecycleManager
from src.scheduler.task_context import TaskContextManager
from src.scheduler.budget_tracker import BudgetTracker
from src.scheduler.quota_manager import QuotaManager
from src.agents.planner.planner_agent import PlannerAgent
from src.agents.verifier.verifier_agent import VerifierAgent
from src.memory.memory_service import MemoryService
from src.utils.logging import logger
from src.core.exceptions import (
    DAGValidationError,
    BudgetExceededError,
    QuotaExceededError
)

# Global singleton
_scheduler_instance = None


def get_scheduler_instance():
    """Get singleton scheduler instance"""
    return _scheduler_instance


def set_scheduler_instance(instance):
    """Set singleton scheduler instance"""
    global _scheduler_instance
    _scheduler_instance = instance


class HybridScheduler:
    """
    Enterprise Hybrid Scheduler
    
    Features:
    - Full execution lifecycle management
    - DAG-based task orchestration
    - Integration with planner and verifier agents
    - Budget and quota enforcement
    - State persistence
    - Parallel execution
    - Pause/resume/cancel operations
    """
    
    def __init__(
        self,
        memory_service: MemoryService,
        planner_agent: PlannerAgent,
        verifier_agent: VerifierAgent
    ):
        self.memory_service = memory_service
        self.planner_agent = planner_agent
        self.verifier_agent = verifier_agent
        
        self.lifecycle_manager = LifecycleManager()
        self.context_manager = TaskContextManager()
        self.budget_tracker = BudgetTracker()
        self.quota_manager = QuotaManager()
        
        # Active executions
        self.executions: Dict[str, Execution] = {}
        
        # Execution tasks (for cancellation)
        self.execution_tasks: Dict[str, asyncio.Task] = {}
        
        # Orchestrator reference (set later)
        self.orchestrator = None
        
        # AI-powered collaboration engine (falls back to hardcoded if LLM unavailable)
        self.execution_controller = None  # Set after orchestrator is connected
        self.max_dynamic_tasks_per_level = 3  # Cap dynamic task insertion
        
        set_scheduler_instance(self)
        
        logger.info(f"✅ Hybrid Scheduler initialized (ID: {id(self)})")
    
    def set_orchestrator(self, orchestrator):
        """Set orchestrator reference and create execution controller"""
        self.orchestrator = orchestrator
        
        # Create execution controller with tool router from orchestrator
        self.execution_controller = ExecutionController(
            tool_router=orchestrator.tool_router,
            memory_service=self.memory_service,
            max_dynamic_tasks=self.max_dynamic_tasks_per_level,
            max_duration=1800
        )
        
        logger.info(f"🔗 Scheduler connected to orchestrator + execution controller")

    async def schedule_execution(
        self,
        goal: str,
        user_id: str,
        tenant_id: str,
        target: Optional[str] = None,
        budget_limit: Optional[float] = None,
        priority: int = 5,  # Changed to int
        parameters: Optional[Dict] = None,
        process_id: Optional[str] = None  # Add this parameter
    ) -> str:
        """Schedule a new execution - returns process_id immediately"""
        
        # Use provided process_id or create new one
        if process_id is None:
            process_id = f"proc_{uuid.uuid4().hex[:12]}"
        
        logger.info(f"📋 Scheduling execution {process_id}")
        
        # NOTE: quota already checked + incremented by hybrid.py before calling here.
        # Removed internal double-check — check_quota() uses legacy "free" tier fallback.
        
        # Create execution record
        execution = Execution(
            process_id=process_id,
            goal=goal,
            target=target,
            user_id=user_id,
            tenant_id=tenant_id,
            priority=priority,  # Now integer
            budget_limit=budget_limit,
            metadata=parameters or {}
        )
        
        self.executions[process_id] = execution
        
        # Create lifecycle record
        await self.lifecycle_manager.create_execution(process_id, user_id, tenant_id)
        
        # Initialize budget
        if budget_limit:
            await self.budget_tracker.initialize_budget(process_id, user_id, tenant_id, budget_limit)
        
        # Start execution in background
        asyncio.create_task(self._execute_planning_phase(process_id))
        
        logger.info(f"✅ Execution {process_id} scheduled, background task created")
        return {
            "process_id": process_id,
            "status": "pending",
            "message": "Execution scheduled for planning"
            }

    async def _execute_planning_phase(self, process_id: str):
        """Execute planning phase with detailed logging"""
        
        logger.info(f"🔵 ===== STARTING PLANNING PHASE for {process_id} =====")
        
        try:
            execution = self.executions[process_id]
            
            # Update status with detailed message
            await self.lifecycle_manager.transition(
                process_id,
                ExecutionStatus.PLANNING,
                reason="Starting planning phase"
            )
            logger.info(f"📋 Status updated to PLANNING for {process_id}")
            
            # Step 1: Query memory for similar tasks
            logger.info(f"🔍 Step 1/4: Querying memory for similar tasks...")
            similar_tasks = await self.memory_service.find_similar_tasks(
                goal=execution.goal,
                target=execution.target,
                limit=5
            )
            logger.info(f"📚 Found {len(similar_tasks)} similar tasks in memory")
            
            # Step 2: Create plan using planner agent
            logger.info(f"🤖 Step 2/4: Calling planner agent with LLM...")
            logger.info(f"   Goal: {execution.goal[:100]}")
            logger.info(f"   Target: {execution.target or 'Not specified'}")
            
            dag = await self.planner_agent.create_plan(
                process_id=process_id,
                goal=execution.goal,
                target=execution.target,
                user_id=execution.user_id,
                tenant_id=execution.tenant_id,
                similar_tasks=similar_tasks,
                parameters=execution.metadata
            )
            
            logger.info(f"✅ Plan created successfully!")
            logger.info(f"   • Total tasks: {dag.total_tasks}")
            logger.info(f"   • Estimated duration: {dag.estimated_duration_seconds}s")
            logger.info(f"   • Estimated cost: ${dag.estimated_total_cost:.4f}")
            
            execution.dag_id = dag.dag_id
            execution.dag = dag.model_dump()
            execution.total_tasks = dag.total_tasks
            execution.estimated_cost = dag.estimated_total_cost
            
            # Step 3: Validate DAG
            logger.info(f"🔍 Step 3/4: Validating DAG structure...")
            await self.lifecycle_manager.transition(
                process_id,
                ExecutionStatus.VALIDATING,
                reason="Validating execution plan"
            )
            
            validated_dag = await self.verifier_agent.validate_dag(
                dag=dag,
                user_id=execution.user_id,
                tenant_id=execution.tenant_id
            )
            logger.info(f"✅ DAG validation successful - no cycles or issues found")
            
            # Step 4: Check budget
            if execution.budget_limit:
                logger.info(f"💰 Step 4/4: Checking budget (limit: ${execution.budget_limit})...")
                if not await self.budget_tracker.check_budget(
                    process_id,
                    validated_dag.estimated_total_cost
                ):
                    raise BudgetExceededError(
                        f"Estimated cost ${validated_dag.estimated_total_cost:.2f} "
                        f"exceeds budget ${execution.budget_limit:.2f}"
                    )
                logger.info(f"✅ Budget check passed")
            
            # Store in memory
            logger.info(f"💾 Storing plan in memory system...")
            await self.memory_service.store_plan(
                goal=execution.goal,
                target=execution.target,
                dag=validated_dag,
                user_id=execution.user_id,
                tenant_id=execution.tenant_id
            )
            
            # Update execution
            execution.dag = validated_dag.model_dump()
            execution.status = ExecutionStatus.QUEUED
            execution.updated_at = datetime.utcnow()
            
            logger.info(f"✅ ===== PLANNING COMPLETED for {process_id} =====")
            logger.info(f"📊 Execution queued with {validated_dag.total_tasks} tasks")
            
            # Start execution phase
            await self._execute_execution_phase(process_id, validated_dag)
            
        except Exception as e:
            logger.error(f"❌ ===== PLANNING FAILED for {process_id} =====")
            logger.error(f"Error: {str(e)}")
            logger.exception(e)
            
            await self._handle_execution_error(process_id, e)

    async def _execute_execution_phase(self, process_id: str, dag: DAG):
        """Delegate execution to the Execution Controller."""
        
        logger.info(f"🟢 ===== STARTING EXECUTION PHASE for {process_id} =====")
        
        try:
            execution = self.executions[process_id]
            
            await self.lifecycle_manager.transition(
                process_id, ExecutionStatus.QUEUED, reason="Plan validated, queuing"
            )
            await self.lifecycle_manager.transition(
                process_id, ExecutionStatus.RUNNING, reason="Starting execution"
            )
            
            execution.started_at = datetime.utcnow()
            execution.status = ExecutionStatus.RUNNING
            
            # Set timeout
            timeout = execution.metadata.get("timeout", 1800)
            await self.lifecycle_manager.set_timeout(
                process_id, timeout, self._handle_timeout
            )
            
            if not self.execution_controller:
                raise Exception("Execution controller not initialized")
            
            # === DELEGATE TO EXECUTION CONTROLLER ===
            result = await self.execution_controller.execute(
                execution=execution,
                dag=dag,
                lifecycle_manager=self.lifecycle_manager,
                context_manager=self.context_manager
            )
            
            # Store result
            execution.metadata["execution_result"] = {
                "findings_count": len(result.get("findings", [])),
                "risk_summary": result.get("risk_summary", {}),
                "duration": result.get("duration", 0),
                "dynamic_tasks": result.get("dynamic_tasks", 0),
                "llm_calls": result.get("llm_calls", 0),
                "executed_tools": result.get("executed_tools", []),
            }
            # Store raw findings for DB persistence
            execution.metadata["all_findings"] = result.get("findings", [])
            
            await self._complete_execution(process_id)
            
        except Exception as e:
            logger.error(f"❌ ===== EXECUTION FAILED for {process_id} =====")
            logger.error(f"Error: {str(e)}")
            logger.exception(e)
            await self._handle_execution_error(process_id, e)

    async def _complete_execution(self, process_id: str):
        """Mark execution as completed and save to history."""
        
        execution = self.executions.get(process_id)
        if not execution:
            return
        
        execution.status = ExecutionStatus.COMPLETED
        execution.completed_at = datetime.utcnow()
        
        await self.lifecycle_manager.transition(
            process_id,
            ExecutionStatus.COMPLETED
        )
        
        duration = (execution.completed_at - execution.started_at).total_seconds() if execution.started_at else 0
        
        # Store in memory
        await self.memory_service.store_execution_result(
            process_id=process_id,
            result={
                "status": "completed",
                "total_cost": execution.actual_cost,
                "total_tasks": execution.total_tasks,
                "completed_tasks": execution.completed_tasks,
                "failed_tasks": execution.failed_tasks,
                "duration_seconds": duration
            }
        )
        
        # Save to scan history (PostgreSQL)
        try:
            from src.services.user_service import user_service
            exec_result = execution.metadata.get("execution_result", {})
            risk_summary = exec_result.get("risk_summary", {})
            
            await user_service.save_scan({
                "process_id": process_id,
                "user_id": execution.user_id,
                "tenant_id": execution.tenant_id,
                "goal": execution.goal,
                "target": execution.target,
                "status": "completed",
                "total_tasks": execution.total_tasks,
                "completed_tasks": execution.completed_tasks,
                "failed_tasks": execution.failed_tasks,
                "dynamic_tasks": exec_result.get("dynamic_tasks", 0),
                "findings_count": exec_result.get("findings_count", 0),
                "risk_score": risk_summary.get("overall_score", 0.0),
                "risk_level": risk_summary.get("overall_risk", "none"),
                "tools_used": list(set(
                    t.get("tool", "") for t in exec_result.get("executed_tools", [])
                )),
                "llm_calls": exec_result.get("llm_calls", 0),
                "duration_seconds": duration,
                "report": execution.metadata.get("report"),
                "started_at": execution.started_at,
                "completed_at": execution.completed_at
            })
            
            # Save individual findings
            all_findings = execution.metadata.get("all_findings", [])
            if all_findings:
                await user_service.save_findings(process_id, execution.user_id, all_findings)
            
            logger.info(f"💾 Scan + {len(all_findings)} findings saved to DB: {process_id}")
        except Exception as e:
            logger.warning(f"⚠️ Failed to save scan history: {e}")
        
        # Decrement quota
        await self.quota_manager.decrement_usage(
            execution.tenant_id,
            execution.user_id
        )
        
        # Cleanup
        self.execution_tasks.pop(process_id, None)
        
        logger.info(f"Execution {process_id} completed")
    
    async def _handle_execution_error(self, process_id: str, error: Exception):
        """Handle execution error"""
        
        execution = self.executions.get(process_id)
        if not execution:
            return
        
        execution.status = ExecutionStatus.FAILED
        execution.error = str(error)
        execution.error_details = {
            "type": error.__class__.__name__,
            "message": str(error)
        }
        
        await self.lifecycle_manager.transition(
            process_id,
            ExecutionStatus.FAILED,
            reason=str(error)
        )
        
        # Store in memory
        await self.memory_service.store_execution_result(
            process_id=process_id,
            result={
                "status": "failed",
                "error": str(error),
                "error_type": error.__class__.__name__
            }
        )
        
        # Decrement quota
        await self.quota_manager.decrement_usage(
            execution.tenant_id,
            execution.user_id
        )
        
        # Cleanup
        self.execution_tasks.pop(process_id, None)
        
        logger.error(
            f"Execution {process_id} failed: {error}",
            extra={
                "process_id": process_id,
                "error": str(error)
            }
        )
    
    async def _handle_timeout(self, process_id: str):
        """Handle execution timeout"""
        
        execution = self.executions.get(process_id)
        if execution and execution.status == ExecutionStatus.RUNNING:
            await self._handle_execution_error(
                process_id,
                TimeoutError("Execution timed out")
            )
    
    async def get_execution_status(self, process_id: str) -> Optional[Dict[str, Any]]:
        """Get current execution status with findings, report, and proposals"""
        
        execution = self.executions.get(process_id)
        if not execution:
            return None
        
        result = {
            "process_id": process_id,
            "status": execution.status.value,
            "goal": execution.goal,
            "target": execution.target,
            "progress": (
                (execution.completed_tasks / execution.total_tasks * 100)
                if execution.total_tasks > 0 else 0
            ),
            "completed_tasks": execution.completed_tasks,
            "total_tasks": execution.total_tasks,
            "failed_tasks": execution.failed_tasks,
            "created_at": execution.created_at,
            "started_at": execution.started_at,
            "updated_at": execution.updated_at,
            "completed_at": execution.completed_at,
            "error": execution.error,
        }
        
        # Include report if available
        if execution.metadata.get("report"):
            result["report"] = execution.metadata["report"]
        
        # Include execution stats
        if execution.metadata.get("execution_result"):
            exec_result = execution.metadata["execution_result"]
            result["findings_count"] = exec_result.get("findings_count", 0)
            result["risk_summary"] = exec_result.get("risk_summary", {})
            result["duration"] = exec_result.get("duration", 0)
            result["dynamic_tasks"] = exec_result.get("dynamic_tasks", 0)
            result["llm_calls"] = exec_result.get("llm_calls", 0)
        
        # Include pending proposals if awaiting approval
        if execution.metadata.get("awaiting_approval"):
            result["awaiting_approval"] = True
            result["pending_proposals"] = execution.metadata.get("pending_proposals", [])
        
        return result
    
    async def pause_execution(self, process_id: str) -> bool:
        """Pause execution"""
        
        execution = self.executions.get(process_id)
        if not execution:
            return False
        
        if execution.status != ExecutionStatus.RUNNING:
            return False
        
        return await self.lifecycle_manager.pause(process_id)
    
    async def resume_execution(self, process_id: str) -> bool:
        """Resume execution"""
        
        execution = self.executions.get(process_id)
        if not execution:
            return False
        
        if execution.status != ExecutionStatus.PAUSED:
            return False
        
        return await self.lifecycle_manager.resume(process_id)
    
    async def cancel_execution(self, process_id: str) -> bool:
        """Cancel execution"""
        
        execution = self.executions.get(process_id)
        if not execution:
            return False
        
        # Cancel execution task
        if process_id in self.execution_tasks:
            self.execution_tasks[process_id].cancel()
        
        # Update status
        result = await self.lifecycle_manager.cancel(process_id)
        
        if result:
            execution.status = ExecutionStatus.CANCELLED
            
            # Decrement quota
            await self.quota_manager.decrement_usage(
                execution.tenant_id,
                execution.user_id
            )
        
        return result
    
    async def _get_current_usage(self, tenant_id: str, user_id: str) -> int:
        """Get current concurrent execution count"""
        
        usage = await self.quota_manager.get_usage("tenant", tenant_id)
        return usage.get("concurrent_executions", 0)
    
    def list_executions(
        self,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """List executions"""
        
        return self.lifecycle_manager.list_executions(
            user_id=user_id,
            tenant_id=tenant_id,
            status=status,
            limit=limit
        )