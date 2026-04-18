"""
execution_controller.py — Complete, correct, industry-grade execution engine.

FIXES applied vs broken version:
1. Calls tool_router.route_and_execute() — correct method (was .execute())
2. Uses dag.get_execution_order() — correct method (was .get_execution_levels())
3. Passes TaskNode + correct params dict to ToolRouter
4. extra_args built from LLM-provided flags so _prepare_tool_args uses them
5. ScanEvent used for all event_bus.publish() calls

Full pipeline:
  Scheduler → execute(execution, dag)
    ├─ Target validation
    ├─ DAG topological levels → parallel asyncio.gather per level
    │   └─ _execute_task → tool_router.route_and_execute → WorkerPool → Docker
    │       └─ ResultParser.parse → findings[]
    ├─ AnalysisAgent.analyze per level (AI validation + CVEs + mitigations)
    ├─ RiskEngine.score_findings + get_risk_summary
    ├─ RiskEngine.should_continue_scanning (stop condition logic)
    ├─ TaskProposerAgent.propose (dynamic follow-up tasks with flags)
    ├─ User approval gate (waits up to 5min for /hybrid/approve API call)
    ├─ CVECorrelationAgent.correlate (matches against Xcloak CVE DB)
    ├─ ReportGeneratorAgent.generate (full pentest report with defensive recs)
    └─ Grafana metrics + Slack notifications
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio
import uuid

from src.models.dag import DAG, TaskNode, TaskType, AgentCapability
from src.models.execution import Execution
from src.engine.result_parser import ResultParser
from src.engine.risk_engine import RiskEngine
from src.engine.llm_agents import (
    AnalysisAgent, TaskProposerAgent, ReportGeneratorAgent,
    CVECorrelationAgent, GrafanaMetricsAgent, SlackNotificationAgent,
    grafana_agent, slack_agent, cve_agent,
)
from src.tools.tool_router import ToolRouter
from src.services.target_validator import target_validator
from src.memory.memory_service import MemoryService
from src.services.event_bus import event_bus, ScanEvent
from src.utils.logging import logger


# Maps tool name → AgentCapability string
TOOL_TO_CAP: Dict[str, str] = {
    "nmap":     "network_scan",
    "nuclei":   "vuln_scan",
    "gobuster": "directory_bruteforce",
    "sqlmap":   "sql_injection",
    "nikto":    "web_vuln_scan",
    "ffuf":     "parameter_fuzzing",
    "whatweb":  "tech_detection",
}

# Maps capability string → AgentCapability enum
CAP_ENUM: Dict[str, AgentCapability] = {
    "network_scan":        AgentCapability.NETWORK_SCAN,
    "port_scan":           AgentCapability.PORT_SCAN,
    "os_detection":        AgentCapability.NETWORK_SCAN,
    "service_detection":   AgentCapability.NETWORK_SCAN,
    "vuln_scan":           AgentCapability.VULN_SCAN,
    "cve_detection":       AgentCapability.VULN_SCAN,
    "web_scan":            AgentCapability.WEB_SCAN,
    "directory_bruteforce":AgentCapability.WEB_SCAN,
    "parameter_fuzzing":   AgentCapability.WEB_SCAN,
    "web_vuln_scan":       AgentCapability.WEB_SCAN,
    "tech_detection":      AgentCapability.WEB_SCAN,
    "web_fingerprint":     AgentCapability.WEB_SCAN,
    "dns_enumeration":     AgentCapability.DNS_ENUMERATION,
    "sql_injection":       AgentCapability.SQL_INJECTION,
    "database_extraction": AgentCapability.SQL_INJECTION,
}


def _emit(process_id: str, event_type: str, data: dict) -> None:
    """Non-blocking event publish — never raises."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(
            event_bus.publish(ScanEvent(event_type, process_id, data))
        )
    except Exception:
        pass


class ExecutionController:
    """
    Orchestrates the full security scan lifecycle.
    Called by HybridScheduler._execute_execution_phase().
    """

    def __init__(
        self,
        tool_router: ToolRouter,
        memory_service: MemoryService,
        max_dynamic_tasks: int = 3,
        max_duration: float = 1800,
    ):
        self.tool_router       = tool_router
        self.memory_service    = memory_service
        self.max_dynamic_tasks = max_dynamic_tasks
        self.max_duration      = max_duration

        self.result_parser    = ResultParser()
        self.risk_engine      = RiskEngine()
        self.analysis_agent   = AnalysisAgent()
        self.task_proposer    = TaskProposerAgent()
        self.report_generator = ReportGeneratorAgent()

        self.llm_calls    = 0
        self.llm_failures = 0

        # Per-scan approval state (for dynamic tasks)
        self._approval_events: Dict[str, asyncio.Event] = {}
        self._approved_tasks:  Dict[str, List[str]]     = {}

        logger.info("✅ Execution Controller initialized")

    # ═══════════════════════════════════════════════════════════════════
    # MAIN ENTRY — called by HybridScheduler
    # ═══════════════════════════════════════════════════════════════════

    async def execute(
        self,
        execution: Execution,
        dag: DAG,
        lifecycle_manager,
        context_manager,
    ) -> Dict[str, Any]:
        process_id = execution.process_id
        target     = execution.target or "unknown"
        start_time = datetime.utcnow()

        logger.info(f"🟢 EXECUTION START: {process_id} → {target}")

        # ── Target validation ─────────────────────────────────────────
        if execution.target:
            val = target_validator.validate(execution.target)
            if not val["allowed"]:
                _emit(process_id, "error", {"message": f"Target rejected: {val['reason']}"})
                raise ValueError(f"Target not allowed: {val['reason']}")
            target = val["sanitized"]

        # ── Push start metric ─────────────────────────────────────────
        tier = execution.metadata.get("tier", "free")
        asyncio.create_task(
            grafana_agent.push_scan_started(process_id, execution.user_id, target, tier)
        )

        # State
        all_findings:   List[Dict] = []
        executed_tools: List[Dict] = []
        dynamic_tasks               = 0

        # Get topological execution levels (parallel task groups)
        try:
            levels = dag.get_execution_order()
        except Exception as e:
            logger.warning(f"DAG order error ({e}) — flat execution")
            levels = [list(dag.nodes.keys())]

        _emit(process_id, "execution_start", {
            "target": target, "total_tasks": dag.total_tasks, "levels": len(levels),
        })

        try:
            for level_idx, level_task_ids in enumerate(levels):
                level_tasks = [dag.nodes[tid] for tid in level_task_ids if tid in dag.nodes]
                if not level_tasks:
                    continue

                tools_in_level = [t.metadata.get("tool", "?") for t in level_tasks]
                logger.info(f"📋 Level {level_idx+1}/{len(levels)}: {tools_in_level}")

                _emit(process_id, "level_start", {
                    "level": level_idx + 1, "total_levels": len(levels), "tools": tools_in_level,
                })

                level_start = datetime.utcnow()

                # Execute all tasks in this level in PARALLEL
                level_results = await asyncio.gather(*[
                    self._execute_task(task, execution, process_id, target)
                    for task in level_tasks
                ], return_exceptions=True)

                level_findings: List[Dict] = []
                for task, result in zip(level_tasks, level_results):
                    if isinstance(result, Exception):
                        logger.error(f"Task {task.task_id} ({task.metadata.get('tool','?')}) failed: {result}")
                        execution.failed_tasks = getattr(execution, "failed_tasks", 0) + 1
                        continue
                    if result:
                        level_findings.extend(result.get("findings", []))
                        executed_tools.append({
                            "tool":     task.metadata.get("tool", "unknown"),
                            "task_id":  task.task_id,
                            "findings": len(result.get("findings", [])),
                            "duration": result.get("duration", 0),
                        })
                        execution.completed_tasks = getattr(execution, "completed_tasks", 0) + 1

                all_findings.extend(level_findings)
                level_dur = (datetime.utcnow() - level_start).total_seconds()

                _emit(process_id, "level_complete", {
                    "level": level_idx + 1, "findings": len(level_findings), "duration": level_dur,
                })
                logger.info(f"   ✅ Level {level_idx+1}: {level_dur:.1f}s | {len(level_findings)} findings")

                # ── AI analysis after EACH level ──────────────────────
                if all_findings:
                    _emit(process_id, "analysis_start", {"count": len(all_findings)})

                    try:
                        analysis = await self.analysis_agent.analyze(all_findings, target)
                        self.llm_calls += 1
                        validated = analysis.get("validated_findings", all_findings)
                        removed   = analysis.get("removed", 0)
                        all_findings = validated

                        # Immediate Slack alert on critical
                        for f in validated:
                            if f.get("validated_severity") == "critical":
                                asyncio.create_task(slack_agent.notify_critical_finding(f, target))

                        scored       = self.risk_engine.score_findings(all_findings)
                        risk_summary = self.risk_engine.get_risk_summary(scored)
                        all_findings = scored

                        _emit(process_id, "analysis_done", {
                            "validated": len(validated), "removed": removed,
                            "summary":   analysis.get("summary", ""),
                            "risk":      risk_summary,
                        })
                        _emit(process_id, "risk_update", {
                            "risk":     risk_summary.get("overall_risk", "none"),
                            "score":    risk_summary.get("overall_score", 0),
                            "critical": risk_summary.get("critical_count", 0),
                            "high":     risk_summary.get("high_count", 0),
                        })
                    except Exception as e:
                        logger.warning(f"Analysis failed (non-critical): {e}")
                        scored = self.risk_engine.score_findings(all_findings)
                        risk_summary = self.risk_engine.get_risk_summary(scored)
                        all_findings = scored

                # ── Dynamic proposals after LAST planned level ────────
                is_last = (level_idx == len(levels) - 1)
                elapsed = (datetime.utcnow() - start_time).total_seconds()

                if is_last and dynamic_tasks < self.max_dynamic_tasks and all_findings:
                    # Check if we should continue
                    stop_check = self.risk_engine.should_continue_scanning(
                        findings=all_findings,
                        dynamic_tasks_added=dynamic_tasks,
                        max_dynamic_tasks=self.max_dynamic_tasks,
                        budget_remaining=999,  # budget handled by scheduler
                        elapsed_seconds=elapsed,
                        max_duration=self.max_duration,
                    )

                    if stop_check["should_continue"]:
                        allowed_tools = execution.metadata.get("allowed_tools")
                        try:
                            proposal_result = await self.task_proposer.propose(
                                findings=all_findings, target=target, goal=execution.goal,
                                tools_used=[t.get("tool","") for t in executed_tools],
                                allowed_tools=allowed_tools,
                                dynamic_tasks_used=dynamic_tasks,
                                max_dynamic=self.max_dynamic_tasks,
                            )
                            self.llm_calls += 1

                            if proposal_result.get("should_propose") and proposal_result.get("proposals"):
                                proposals = proposal_result["proposals"]

                                # Set up approval gate
                                event = asyncio.Event()
                                self._approval_events[process_id] = event
                                execution.metadata["awaiting_approval"]  = True
                                execution.metadata["pending_proposals"]  = proposals

                                _emit(process_id, "approval_needed", {
                                    "proposals": proposals,
                                    "count":     len(proposals),
                                    "message":   f"AI proposes {len(proposals)} follow-up tasks",
                                })

                                # Wait up to 5 minutes for user approval
                                try:
                                    await asyncio.wait_for(event.wait(), timeout=300.0)
                                except asyncio.TimeoutError:
                                    logger.info(f"Approval timeout for {process_id} — skipping")

                                execution.metadata["awaiting_approval"] = False
                                approved = self._approved_tasks.get(process_id, [])

                                if approved:
                                    for prop in proposals:
                                        if prop["task_name"] not in approved:
                                            continue
                                        dyn_task   = self._proposal_to_task(prop)
                                        dyn_result = await self._execute_task(
                                            dyn_task, execution, process_id, target
                                        )
                                        if dyn_result and not isinstance(dyn_result, Exception):
                                            new_f = dyn_result.get("findings", [])
                                            all_findings.extend(new_f)
                                            executed_tools.append({
                                                "tool":     prop.get("tool"),
                                                "task_id":  dyn_task.task_id,
                                                "findings": len(new_f),
                                            })
                                            dynamic_tasks += 1
                                            execution.completed_tasks = getattr(execution, "completed_tasks", 0) + 1

                                _emit(process_id, "approval_done", {
                                    "approved": len(approved), "dynamic_tasks": dynamic_tasks,
                                })
                        except Exception as e:
                            logger.warning(f"Task proposal failed (non-critical): {e}")

            # ── CVE Correlation ───────────────────────────────────────
            cve_matches: List[Dict] = []
            try:
                from src.core.database import db_manager
                if db_manager.pg_pool:
                    cve_matches = await cve_agent.correlate(all_findings, db_manager.pg_pool)
                    if cve_matches:
                        await cve_agent.update_cve_scan_context(
                            [m["cve_id"] for m in cve_matches], target, process_id, db_manager.pg_pool
                        )
                        _emit(process_id, "cve_matched", {
                            "count":   len(cve_matches),
                            "cve_ids": [m["cve_id"] for m in cve_matches[:5]],
                        })
            except Exception as e:
                logger.warning(f"CVE correlation (non-critical): {e}")

            # ── Generate pentest report ───────────────────────────────
            duration   = (datetime.utcnow() - start_time).total_seconds()
            tools_used = list(set(t.get("tool","") for t in executed_tools if t.get("tool")))
            final_risk = self.risk_engine.get_risk_summary(all_findings)

            _emit(process_id, "report_start", {"findings": len(all_findings)})

            report = ""
            try:
                report = await self.report_generator.generate(
                    target=target, findings=all_findings, duration=duration,
                    tools_used=tools_used, goal=execution.goal, cve_matches=cve_matches,
                )
                self.llm_calls += 1
                execution.metadata["report"] = report

                for line in (report or "").split("\n")[:60]:
                    if line.strip():
                        _emit(process_id, "report_line", {"line": line})
            except Exception as e:
                logger.warning(f"Report generation (non-critical): {e}")

            _emit(process_id, "report_done", {"length": len(report)})

            # ── Metrics & notifications ───────────────────────────────
            sev_counts: Dict[str, int] = {}
            for f in all_findings:
                s = f.get("validated_severity", f.get("severity", "info"))
                sev_counts[s] = sev_counts.get(s, 0) + 1

            asyncio.create_task(grafana_agent.push_scan_completed(
                process_id, execution.user_id, duration,
                len(all_findings), final_risk.get("overall_risk","none"), tier
            ))
            asyncio.create_task(grafana_agent.push_finding_severity(sev_counts, process_id))
            asyncio.create_task(slack_agent.notify_scan_complete(
                target, len(all_findings), final_risk.get("overall_risk","none"),
                process_id, final_risk.get("critical_count", 0),
            ))

            _emit(process_id, "complete", {
                "findings":    len(all_findings),
                "risk":        final_risk.get("overall_risk", "none"),
                "score":       final_risk.get("overall_score", 0),
                "duration":    duration,
                "llm_calls":   self.llm_calls,
                "cve_matches": len(cve_matches),
            })

            logger.info(
                f"🎉 DONE: {process_id} | "
                f"findings={len(all_findings)} | risk={final_risk.get('overall_risk')} | "
                f"{duration:.1f}s | cve={len(cve_matches)} | llm={self.llm_calls}"
            )

            return {
                "findings":       all_findings,
                "findings_count": len(all_findings),
                "risk_summary":   final_risk,
                "duration":       duration,
                "dynamic_tasks":  dynamic_tasks,
                "llm_calls":      self.llm_calls,
                "executed_tools": executed_tools,
                "cve_matches":    cve_matches,
                "report":         report,
            }

        except Exception as e:
            logger.error(f"❌ Execution failed {process_id}: {e}")
            _emit(process_id, "error", {"message": str(e)})
            raise

    # ═══════════════════════════════════════════════════════════════════
    # TASK EXECUTION — calls ToolRouter.route_and_execute() correctly
    # ═══════════════════════════════════════════════════════════════════

    async def _execute_task(
        self,
        task: TaskNode,
        execution: Execution,
        process_id: str,
        target: str,
    ) -> Dict[str, Any]:
        """Execute a single task via ToolRouter → WorkerPool → Docker container."""
        tool_name = task.metadata.get("tool") or self._infer_tool(task)
        if not tool_name:
            logger.warning(f"No tool for task {task.task_id}")
            return {"findings": [], "duration": 0}

        # Validate & sanitize flags from LLM plan
        raw_flags = task.parameters.get("flags", "")
        if raw_flags:
            flag_check = target_validator.validate_tool_flags(tool_name, raw_flags)
            if not flag_check["allowed"]:
                logger.warning(f"Flags rejected for {tool_name}: {flag_check['reason']}")
                raw_flags = ""
            else:
                raw_flags = flag_check["sanitized_flags"]

        # Validate target
        t_val = target_validator.validate(target)
        if not t_val["allowed"]:
            logger.warning(f"Target rejected in task: {t_val['reason']}")
            return {"findings": [], "duration": 0}
        clean_target = t_val["sanitized"]

        logger.info(f"▶ {task.name} | tool={tool_name} | target={clean_target}")
        if raw_flags:
            logger.info(f"  flags: {raw_flags}")

        _emit(process_id, "task_start", {
            "task_id":   task.task_id,
            "task_name": task.name,
            "tool":      tool_name,
            "target":    clean_target,
            "flags":     raw_flags,
        })

        # Ensure task has the right capability enum for ToolRouter
        if not task.required_capabilities:
            cap_str  = TOOL_TO_CAP.get(tool_name, "network_scan")
            cap_enum = CAP_ENUM.get(cap_str, AgentCapability.NETWORK_SCAN)
            task.required_capabilities = [cap_enum]

        # Build params dict for ToolRouter._prepare_tool_args()
        # extra_args contains the pre-split flags so the arg builder uses them directly
        params = {
            **task.parameters,
            "tool":   tool_name,
            "target": clean_target,
        }
        if raw_flags:
            params["flags"]      = raw_flags
            params["extra_args"] = raw_flags.split()

        task_start = datetime.utcnow()
        try:
            # ── THE CORRECT CALL ──────────────────────────────────────
            result = await self.tool_router.route_and_execute(
                task=task,
                params=params,
                user_id=execution.user_id,
                tenant_id=execution.tenant_id,
                execution_id=process_id,
            )

            duration  = (datetime.utcnow() - task_start).total_seconds()
            exit_code = result.get("exit_code", 0)
            stdout    = result.get("stdout", "")
            stderr    = result.get("stderr", "")

            logger.info(f"✅ {tool_name}: {duration:.1f}s | exit={exit_code} | out={len(stdout)}b")

            # Stream output lines as real-time events
            for line in (stdout + "\n" + stderr).split("\n")[:150]:
                if line.strip():
                    _emit(process_id, "task_output", {"line": line, "tool": tool_name})

            # Parse raw output → structured findings
            findings = self.result_parser.parse(tool_name, stdout, stderr, exit_code, clean_target)
            logger.info(f"   📊 {tool_name}: {len(findings)} findings parsed")

            _emit(process_id, "task_complete", {
                "task_id":   task.task_id,
                "tool":      tool_name,
                "findings":  len(findings),
                "duration":  duration,
                "exit_code": exit_code,
            })

            return {"findings": findings, "duration": duration}

        except asyncio.TimeoutError:
            dur = (datetime.utcnow() - task_start).total_seconds()
            logger.warning(f"⏱ {tool_name} timed out after {dur:.1f}s")
            _emit(process_id, "task_timeout", {"task_id": task.task_id, "tool": tool_name, "duration": dur})
            return {"findings": [], "duration": dur, "timed_out": True}

        except Exception as e:
            dur = (datetime.utcnow() - task_start).total_seconds()
            logger.error(f"❌ {tool_name} failed: {e}")
            _emit(process_id, "task_error", {"task_id": task.task_id, "tool": tool_name, "error": str(e)})
            return {"findings": [], "duration": dur, "error": str(e)}

    # ═══════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════

    def _infer_tool(self, task: TaskNode) -> Optional[str]:
        """Infer tool name from capabilities when metadata.tool is missing."""
        for cap in task.required_capabilities:
            cs = cap.value if hasattr(cap, "value") else str(cap)
            for tool, cap_str in TOOL_TO_CAP.items():
                if cap_str == cs or cs in cap_str:
                    return tool
        return None

    def _proposal_to_task(self, proposal: Dict) -> TaskNode:
        """Convert AI task proposal into an executable TaskNode."""
        tool     = proposal.get("tool", "nmap")
        cap_str  = TOOL_TO_CAP.get(tool, "network_scan")
        cap_enum = CAP_ENUM.get(cap_str, AgentCapability.NETWORK_SCAN)
        return TaskNode(
            task_id=f"dyn_{uuid.uuid4().hex[:8]}",
            name=proposal.get("task_name", f"Dynamic {tool}"),
            description=proposal.get("reason", ""),
            task_type=TaskType.TOOL_EXECUTION,
            required_capabilities=[cap_enum],
            parameters={**proposal.get("parameters", {}), "tool": tool},
            estimated_duration_seconds=proposal.get("estimated_duration", 180),
            metadata={"tool": tool, "dynamic": True},
        )

    def approve_tasks(self, process_id: str, task_names: List[str]) -> None:
        """API endpoint calls this when user approves dynamic tasks."""
        self._approved_tasks[process_id] = task_names
        if ev := self._approval_events.get(process_id):
            ev.set()
        logger.info(f"✅ Approved for {process_id}: {task_names}")

    def reject_tasks(self, process_id: str) -> None:
        """API endpoint calls this when user rejects dynamic task proposals."""
        self._approved_tasks[process_id] = []
        if ev := self._approval_events.get(process_id):
            ev.set()
        logger.info(f"❌ Rejected for {process_id}")
