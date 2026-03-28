# src/engine/execution_controller.py

"""
Execution Controller — orchestrates the full scan lifecycle.

Replaces the old agent orchestrator and scheduler execution phase.
No domain agents — LLM controls everything.

Flow per level:
  Tool Executor → Result Parser → Analysis Agent (LLM) → Risk Engine → Task Proposer (LLM) → Controller Decision
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio
import uuid
import json

from src.models.dag import DAG, TaskNode, TaskType, AgentCapability
from src.models.execution import Execution, ExecutionStatus, TaskStatus
from src.engine.result_parser import ResultParser
from src.engine.risk_engine import RiskEngine
from src.engine.llm_agents import AnalysisAgent, TaskProposerAgent, ReportGeneratorAgent
from src.tools.tool_router import ToolRouter
from src.memory.memory_service import MemoryService
from src.utils.logging import logger


# Capability mapping for task proposals
CAPABILITY_MAP = {
    "port_scan": AgentCapability.PORT_SCAN,
    "network_scan": AgentCapability.NETWORK_SCAN,
    "vuln_scan": AgentCapability.VULN_SCAN,
    "web_scan": AgentCapability.WEB_SCAN,
    "directory_bruteforce": AgentCapability.WEB_SCAN,
    "dns_enumeration": AgentCapability.DNS_ENUMERATION,
    "sql_injection": AgentCapability.SQL_INJECTION,
    "web_vuln_scan": AgentCapability.WEB_SCAN,
    "server_misconfiguration": AgentCapability.WEB_SCAN,
    "parameter_fuzzing": AgentCapability.WEB_SCAN,
    "vhost_discovery": AgentCapability.WEB_SCAN,
    "tech_detection": AgentCapability.WEB_SCAN,
    "web_fingerprint": AgentCapability.WEB_SCAN,
}

TOOL_CAPABILITY = {
    "nmap": "network_scan",
    "nuclei": "vuln_scan",
    "gobuster": "directory_bruteforce",
    "sqlmap": "sql_injection",
    "nikto": "web_vuln_scan",
    "ffuf": "directory_bruteforce",
    "whatweb": "tech_detection",
}


class ExecutionController:
    """
    Controls the execution loop with LLM intelligence.
    
    No domain agents. No hardcoded tool params.
    LLM decides everything: validation, next steps, stopping conditions.
    """
    
    def __init__(
        self,
        tool_router: ToolRouter,
        memory_service: MemoryService,
        max_dynamic_tasks: int = 3,
        max_duration: float = 1800,  # 30 minutes (includes approval wait time)
    ):
        self.tool_router = tool_router
        self.memory_service = memory_service
        self.max_dynamic_tasks = max_dynamic_tasks
        self.max_duration = max_duration
        
        # Engine components
        self.result_parser = ResultParser()
        self.risk_engine = RiskEngine()
        self.analysis_agent = AnalysisAgent()
        self.task_proposer = TaskProposerAgent()
        self.report_generator = ReportGeneratorAgent()
        
        # Execution tracking
        self.llm_calls = 0
        self.llm_failures = 0
        
        # User approval for dynamic tasks
        self._pending_proposals: Dict[str, List[Dict]] = {}  # process_id -> proposals
        self._approval_events: Dict[str, asyncio.Event] = {}  # process_id -> event
        self._approved_tasks: Dict[str, List[str]] = {}  # process_id -> approved task names
        
        logger.info("✅ Execution Controller initialized")
    
    async def execute(
        self,
        execution: Execution,
        dag: DAG,
        lifecycle_manager,
        context_manager
    ) -> Dict[str, Any]:
        """
        Execute the full DAG with LLM-powered loop.
        
        Returns execution result dict with findings, report, and stats.
        """
        
        process_id = execution.process_id
        target = execution.target or "unknown"
        
        logger.info(f"🟢 ===== EXECUTION CONTROLLER: Starting {process_id} =====")
        logger.info(f"   Target: {target}")
        logger.info(f"   Max dynamic tasks: {self.max_dynamic_tasks}")
        logger.info(f"   Max duration: {self.max_duration}s")
        
        # State tracking
        all_findings: List[Dict] = []
        executed_tools: List[Dict] = []
        dynamic_tasks_added = 0
        start_time = datetime.utcnow()
        
        # Get initial execution order
        execution_order = dag.get_execution_order()
        logger.info(f"📊 Initial DAG: {len(execution_order)} levels, {dag.total_tasks} tasks")
        
        level_number = 0
        
        while level_number < len(execution_order):
            # === CONTROLLER CHECK: Should we continue? ===
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            
            if execution.status in [ExecutionStatus.CANCELLED, ExecutionStatus.TIMEOUT, ExecutionStatus.FAILED]:
                logger.warning(f"⚠️ Execution {process_id} is {execution.status.value}, stopping")
                break
            
            if elapsed >= self.max_duration:
                logger.warning(f"⏱️ Time limit reached ({elapsed:.0f}s / {self.max_duration:.0f}s), stopping")
                break
            
            task_ids = execution_order[level_number]
            level_number += 1
            
            # === EXECUTE LEVEL ===
            logger.info(f"▶️ Level {level_number}/{len(execution_order)}: {len(task_ids)} tasks")
            
            level_findings, level_tool_runs = await self._execute_level(
                execution=execution,
                dag=dag,
                task_ids=task_ids,
                lifecycle_manager=lifecycle_manager,
                context_manager=context_manager
            )
            
            all_findings.extend(level_findings)
            executed_tools.extend(level_tool_runs)
            
            progress = (execution.completed_tasks / execution.total_tasks * 100) if execution.total_tasks > 0 else 0
            logger.info(f"📈 Progress: {progress:.1f}% ({execution.completed_tasks}/{execution.total_tasks} tasks)")
            
            if not level_findings:
                logger.info(f"   No findings from this level, continuing")
                continue
            
            # === RESULT PARSING (already done in _execute_level) ===
            
            # === ANALYSIS AGENT (LLM) ===
            logger.info(f"🧠 ===== ANALYSIS AGENT (Level {level_number}) =====")
            analysis = await self.analysis_agent.analyze(level_findings, target)
            self.llm_calls += 1
            
            # Replace findings with validated ones (false positives removed)
            validated_findings = analysis.get("validated_findings", level_findings)
            if analysis.get("removed", 0) > 0:
                # Update all_findings — remove the level's raw findings and add validated
                all_findings = all_findings[:-len(level_findings)]
                all_findings.extend(validated_findings)
            
            # === RISK ENGINE ===
            logger.info(f"⚖️ ===== RISK ENGINE (Level {level_number}) =====")
            scored_findings = self.risk_engine.score_findings(validated_findings)
            risk_summary = self.risk_engine.get_risk_summary(all_findings)
            
            logger.info(f"   Overall risk: {risk_summary['overall_risk']} (score: {risk_summary['overall_score']})")
            logger.info(f"   Critical: {risk_summary['critical_count']}, High: {risk_summary['high_count']}, Medium: {risk_summary['medium_count']}")
            
            # Log top risk findings
            for f in scored_findings[:3]:
                if f.get("risk_score", 0) >= 4.0:
                    logger.info(f"   ⚠️ [{f['risk_label']}] {f.get('type')}: {f.get('service', f.get('finding', ''))[:60]} (score: {f['risk_score']:.1f})")
            
            # === MEMORY WRITE ===
            await self._store_findings(process_id, level_number, validated_findings, risk_summary)
            
            # === CONTROLLER DECISION: Continue or stop? ===
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            budget_remaining = (execution.budget_limit or 999) - execution.actual_cost
            
            decision = self.risk_engine.should_continue_scanning(
                findings=all_findings,
                dynamic_tasks_added=dynamic_tasks_added,
                max_dynamic_tasks=self.max_dynamic_tasks,
                budget_remaining=budget_remaining,
                elapsed_seconds=elapsed,
                max_duration=self.max_duration
            )
            
            if not decision["should_continue"]:
                logger.info(f"🚦 Controller decision: STOP — {', '.join(decision['reasons_to_stop'])}")
                continue  # Don't propose new tasks, but finish remaining levels
            
            # === TASK PROPOSER AGENT (LLM) ===
            logger.info(f"💡 ===== TASK PROPOSER (Level {level_number}) =====")
            
            existing_names = {t.name for t in dag.nodes.values()}
            
            proposals = await self.task_proposer.propose(
                findings=validated_findings,
                target=target,
                executed_tools=executed_tools,
                existing_task_names=existing_names
            )
            self.llm_calls += 1
            
            if proposals:
                remaining_slots = self.max_dynamic_tasks - dynamic_tasks_added
                proposals = proposals[:remaining_slots]
                
                logger.info(f"   📋 {len(proposals)} task(s) proposed — waiting for user approval:")
                for i, prop in enumerate(proposals):
                    logger.info(f"      {i+1}. {prop['task_name']} (tool: {prop['tool']}, priority: {prop['priority']})")
                    logger.info(f"         Reason: {prop['reason'][:80]}")
                
                # Store proposals and wait for user approval
                self._pending_proposals[process_id] = proposals
                self._approval_events[process_id] = asyncio.Event()
                
                execution.metadata["pending_proposals"] = [
                    {
                        "task_name": p["task_name"],
                        "tool": p["tool"],
                        "reason": p["reason"],
                        "priority": p["priority"],
                        "parameters": {k: v for k, v in p.get("parameters", {}).items() if k != "target"}
                    }
                    for p in proposals
                ]
                execution.metadata["awaiting_approval"] = True
                
                logger.info(f"   ⏸️ Execution paused — waiting for user approval via POST /api/v1/hybrid/approve/{process_id}")
                
                # Cancel execution timeout during approval wait
                await lifecycle_manager._cancel_timeout(process_id)
                
                # Wait for approval (timeout after 5 minutes)
                try:
                    await asyncio.wait_for(
                        self._approval_events[process_id].wait(),
                        timeout=300
                    )
                except asyncio.TimeoutError:
                    logger.info(f"   ⏱️ Approval timeout — continuing without new tasks")
                    self._cleanup_approval(process_id)
                    execution.metadata["awaiting_approval"] = False
                    # Restart execution timeout with remaining time
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
                    remaining = max(self.max_duration - elapsed, 300)
                    await lifecycle_manager.set_timeout(process_id, int(remaining), None)
                    continue
                
                # Restart execution timeout with remaining time
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                remaining = max(self.max_duration - elapsed, 300)
                await lifecycle_manager.set_timeout(process_id, int(remaining), None)
                
                # Process approved tasks
                approved_names = self._approved_tasks.get(process_id, [])
                execution.metadata["awaiting_approval"] = False
                
                if not approved_names:
                    logger.info(f"   ❌ User rejected all proposals — continuing with original plan")
                    self._cleanup_approval(process_id)
                    continue
                
                # Add only approved tasks
                new_task_ids = []
                for prop in proposals:
                    if prop["task_name"] in approved_names:
                        tool_name = prop["tool"]
                        cap_str = TOOL_CAPABILITY.get(tool_name, "vuln_scan")
                        capability = CAPABILITY_MAP.get(cap_str, AgentCapability.VULN_SCAN)
                        
                        task_node = TaskNode(
                            name=prop["task_name"],
                            description=f"AI-proposed (user approved): {prop['reason']}",
                            task_type=TaskType.SCANNING,
                            required_capabilities=[capability],
                            parameters={**prop["parameters"], "target": target},
                            metadata={
                                "dynamic": True,
                                "tool": tool_name,
                                "reason": prop["reason"],
                                "proposing_agent": "task_proposer_llm",
                                "user_approved": True
                            }
                        )
                        
                        dag.add_node(task_node)
                        new_task_ids.append(task_node.task_id)
                        dynamic_tasks_added += 1
                        
                        logger.info(f"   ✅ Approved by user: {prop['task_name']} (tool: {tool_name})")
                
                if new_task_ids:
                    execution_order.append(new_task_ids)
                    execution.total_tasks = len(dag.nodes)
                    dag.update_stats()
                    logger.info(f"   📊 DAG expanded: {execution.total_tasks} tasks, {len(execution_order)} levels")
                
                self._cleanup_approval(process_id)
            else:
                logger.info(f"   No new tasks proposed")
        
        # === FINAL RISK SUMMARY ===
        final_risk = self.risk_engine.get_risk_summary(all_findings)
        
        # === GENERATE REPORT ===
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"📝 ===== GENERATING REPORT =====")
        report = await self.report_generator.generate(
            target=target,
            findings=all_findings,
            executed_tools=executed_tools,
            risk_summary=final_risk,
            duration_seconds=duration,
            total_tasks=execution.total_tasks,
            dynamic_tasks=dynamic_tasks_added
        )
        self.llm_calls += 1
        
        if report:
            execution.metadata["report"] = report
            logger.info(f"\n{'='*60}")
            for line in report.split('\n'):
                logger.info(f"📄 {line}")
            logger.info(f"{'='*60}")
        
        # === FINAL STATS ===
        logger.info(f"🎉 ===== EXECUTION COMPLETE for {process_id} =====")
        logger.info(f"📊 Final stats:")
        logger.info(f"   • Tasks: {execution.completed_tasks}/{execution.total_tasks} (dynamic: {dynamic_tasks_added})")
        logger.info(f"   • Duration: {duration:.1f}s ({duration/60:.1f} min)")
        logger.info(f"   • Findings: {len(all_findings)}")
        logger.info(f"   • Risk: {final_risk['overall_risk']} (score: {final_risk['overall_score']})")
        logger.info(f"   • LLM calls: {self.llm_calls}")
        
        return {
            "findings": all_findings,
            "risk_summary": final_risk,
            "report": report,
            "executed_tools": executed_tools,
            "duration": duration,
            "dynamic_tasks": dynamic_tasks_added,
            "llm_calls": self.llm_calls
        }
    
    # ========================================================
    # LEVEL EXECUTION
    # ========================================================
    
    async def _execute_level(
        self,
        execution: Execution,
        dag: DAG,
        task_ids: List[str],
        lifecycle_manager,
        context_manager
    ) -> tuple:
        """Execute one level of tasks. Returns (findings, tool_runs)."""
        
        tasks = []
        for task_id in task_ids:
            if task_id not in dag.nodes:
                continue
            task = dag.nodes[task_id]
            
            is_dynamic = task.metadata.get("dynamic", False)
            tag = " [DYNAMIC]" if is_dynamic else ""
            logger.info(f"   🔧 {task.name}{tag}")
            
            await lifecycle_manager.update_task(
                execution.process_id, task_id, TaskStatus.RUNNING
            )
            
            tasks.append(self._execute_single_task(execution, dag, task, context_manager))
        
        start = datetime.utcnow()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = (datetime.utcnow() - start).total_seconds()
        
        level_findings = []
        tool_runs = []
        
        for task_id, result in zip(task_ids, results):
            if isinstance(result, Exception):
                logger.error(f"   ❌ {task_id}: {result}")
                await lifecycle_manager.update_task(
                    execution.process_id, task_id, TaskStatus.FAILED, {"error": str(result)}
                )
                execution.failed_tasks += 1
            else:
                findings, tool_run = result
                level_findings.extend(findings)
                if tool_run:
                    tool_runs.append(tool_run)
                
                await lifecycle_manager.update_task(
                    execution.process_id, task_id, TaskStatus.COMPLETED, {"findings_count": len(findings)}
                )
                execution.completed_tasks += 1
                logger.info(f"   ✅ {task_id}: {len(findings)} findings")
        
        logger.info(f"   📊 Level done: {duration:.1f}s, {len(level_findings)} findings")
        return level_findings, tool_runs
    
    async def _execute_single_task(
        self,
        execution: Execution,
        dag: DAG,
        task: TaskNode,
        context_manager
    ) -> tuple:
        """Execute a single task directly via tool router. Returns (findings, tool_run_info)."""
        
        tool_name = task.metadata.get("tool")
        params = {**task.parameters}
        
        if not tool_name:
            # Determine from capabilities
            caps = [c.value for c in task.required_capabilities]
            if any(c in caps for c in ["port_scan", "network_scan"]):
                tool_name = "nmap"
            elif any(c in caps for c in ["vuln_scan", "web_scan"]):
                tool_name = "nuclei"
            elif "directory_bruteforce" in caps:
                tool_name = "gobuster"
            elif "sql_injection" in caps:
                tool_name = "sqlmap"
            else:
                tool_name = "nmap"  # Default fallback
        
        # Ensure target
        if "target" not in params:
            params["target"] = execution.target
        
        # Get tool config
        tool_config = await self.tool_router.tool_registry.get_tool(tool_name)
        if not tool_config:
            raise Exception(f"Tool '{tool_name}' not found")
        
        logger.info(f"   🐳 Running {tool_name}: {json.dumps({k:v for k,v in params.items() if k != 'target'}, default=str)[:80]}")
        result = await self.tool_router._execute_tool(
            tool=tool_config,
            params=params,
            user_id=execution.user_id,
            tenant_id=execution.tenant_id,
            execution_id=f"exec_{task.task_id}"
        )
        
        # Parse results
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code", -1)
        command = result.get("command", "")
        
        findings = self.result_parser.parse(tool_name, stdout, stderr, exit_code)
        
        tool_run = {
            "tool": tool_name,
            "task_name": task.name,
            "args": command,
            "findings_count": len(findings),
            "exit_code": exit_code,
            "duration": result.get("duration", 0)
        }
        
        return findings, tool_run
    
    async def _store_findings(self, process_id, level, findings, risk_summary):
        """Store findings in memory."""
        try:
            await self.memory_service.store_task_result(
                task_id=f"level_{level}",
                process_id=process_id,
                result={
                    "findings_count": len(findings),
                    "risk_summary": risk_summary
                }
            )
        except Exception as e:
            logger.debug(f"Memory write failed: {e}")
    
    def _cleanup_approval(self, process_id: str):
        """Clean up approval state."""
        self._pending_proposals.pop(process_id, None)
        self._approval_events.pop(process_id, None)
        self._approved_tasks.pop(process_id, None)
    
    def get_pending_proposals(self, process_id: str) -> Optional[List[Dict]]:
        """Get pending proposals for a process (called by API)."""
        return self._pending_proposals.get(process_id)
    
    def approve_proposals(self, process_id: str, approved_task_names: List[str]):
        """Approve specific proposals (called by API)."""
        self._approved_tasks[process_id] = approved_task_names
        event = self._approval_events.get(process_id)
        if event:
            event.set()
            logger.info(f"✅ User approved {len(approved_task_names)} tasks for {process_id}")
    
    def reject_all_proposals(self, process_id: str):
        """Reject all proposals (called by API)."""
        self._approved_tasks[process_id] = []
        event = self._approval_events.get(process_id)
        if event:
            event.set()
            logger.info(f"❌ User rejected all proposals for {process_id}")
