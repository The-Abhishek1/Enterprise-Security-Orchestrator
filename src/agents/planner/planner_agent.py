# src/agents/planner/planner_agent.py
from typing import Optional, Dict, Any, List
from datetime import datetime
import json
import uuid
import asyncio
from src.agents.planner.llm_factory import llm_factory
from src.agents.planner.prompt_templates import PLANNER_SYSTEM_PROMPT, get_planning_prompt
from src.memory.memory_service import MemoryService
from src.models.dag import DAG, TaskNode, TaskType, AgentCapability
from src.utils.logging import logger
from src.core.config import get_settings

settings = get_settings()


class PlannerAgent:
    """
    Enterprise Planner Agent
    
    Uses LLM to decompose goals into executable DAGs
    Supports multiple LLM providers (OpenAI, Anthropic, Local)
    Memory-aware planning using past executions
    """
    
    def __init__(self, memory_service: Optional[MemoryService] = None):
        self.memory_service = memory_service
        self.llm_factory = llm_factory
        self.llm_client = self.llm_factory.get_client()
        
        logger.info(f"✅ Planner Agent initialized with LLM: {self.llm_client.__class__.__name__}")
    
    
    async def create_plan(
        self,
        process_id: str,
        goal: str,
        user_id: str,
        tenant_id: str,
        target: Optional[str] = None,
        similar_tasks: Optional[List[Dict]] = None,
        parameters: Optional[Dict] = None
    ) -> DAG:
        """
        Create execution plan from goal
        
        Returns:
            DAG object with tasks and dependencies
        """
        
        logger.info(
            f"Creating plan for goal: {goal[:100]}",
            extra={
                "process_id": process_id,
                "user_id": user_id,
                "tenant_id": tenant_id
            }
        )
        
        # Check memory for similar plans (fast)
        cached_plan = None
        if self.memory_service:
            try:
                cached_plan = await asyncio.wait_for(
                    self.memory_service.find_similar_plan(
                        goal=goal,
                        target=target,
                        tenant_id=tenant_id
                    ),
                    timeout=2.0  # 2 second timeout for memory lookup
                )
            except asyncio.TimeoutError:
                logger.warning("Memory lookup timed out")
        
        if cached_plan and cached_plan.get("success_rate", 0) > 0.7:
            logger.info(f"✅ Using cached plan with {cached_plan.get('task_count', 0)} tasks")
            return await self._cached_plan_to_dag(cached_plan, process_id)
        
        # Generate plan using LLM with timeout
        try:
            plan_data = await asyncio.wait_for(
                self._generate_plan_with_llm(goal, target, similar_tasks),
                timeout=50.0  # 20 second timeout for LLM planning
            )
        except asyncio.TimeoutError:
            logger.warning("LLM planning timed out, using fallback plan")
            plan_data = None
        except Exception as e:
            logger.error(f"LLM planning failed: {e}")
            plan_data = None
        
        if plan_data:
            # Convert to DAG
            dag = await self._plan_to_dag(plan_data, process_id, goal, target)
            
            # Store in memory for future use (don't wait for it)
            if self.memory_service:
                asyncio.create_task(
                    self.memory_service.store_plan(
                        goal=goal,
                        target=target,
                        dag=dag,
                        user_id=user_id,
                        tenant_id=tenant_id
                    )
                )
            
            logger.info(
                f"✅ Plan created with {dag.total_tasks} tasks",
                extra={
                    "process_id": process_id,
                    "total_tasks": dag.total_tasks,
                    "estimated_duration": dag.estimated_duration_seconds
                }
            )
            
            return dag
        
        # Fallback to default plan
        logger.info("Using default fallback plan")
        return self._create_default_plan(process_id, goal, target)
    
    async def _generate_plan_with_llm(
        self,
        goal: str,
        target: Optional[str],
        similar_tasks: Optional[List[Dict]]
    ) -> Dict[str, Any]:
        """Generate plan using LLM"""
        
        context = {"similar_tasks": similar_tasks} if similar_tasks else None
        prompt = get_planning_prompt(goal, target, context)
        
        try:
            response = await self.llm_client.generate_json(
                prompt=prompt,
                system_prompt=PLANNER_SYSTEM_PROMPT
            )
            
            # Validate response structure
            if not response.get("tasks"):
                raise ValueError("No tasks in LLM response")
            
            return response
            
        except Exception as e:
            logger.error(f"LLM planning failed: {e}")
            raise
    
    async def _plan_to_dag(
        self,
        plan_data: Dict[str, Any],
        process_id: str,
        goal: str,
        target: Optional[str]
    ) -> DAG:
        """Convert plan data to DAG object"""
        
        dag = DAG(
            dag_id=f"dag_{uuid.uuid4().hex[:8]}",
            process_id=process_id,
            name=goal[:50],
            description=goal
        )
        
        # Create task nodes
        task_map = {}
        for task_data in plan_data.get("tasks", []):
            task_id = task_data.get("id", f"task_{uuid.uuid4().hex[:8]}")
            
            # Map capabilities strings to enums
            capabilities = []
            for cap in task_data.get("capabilities", []):
                try:
                    capabilities.append(AgentCapability(cap))
                except ValueError:
                    logger.warning(f"Unknown capability: {cap}")
            
            # Create task node
            task = TaskNode(
                task_id=task_id,
                name=task_data.get("name", "Unknown task"),
                description=task_data.get("description", ""),
                task_type=self._map_task_type(task_data.get("type", "tool_execution")),
                required_capabilities=capabilities,
                parameters={
                    "target": target,
                    **task_data.get("parameters", {})
                },
                estimated_duration_seconds=task_data.get("estimated_duration", 300),
                estimated_cost=self._estimate_task_cost(task_data),
                metadata={
                    "tool": task_data.get("tool")  # Pass tool name from LLM plan
                }
            )
            
            dag.add_node(task)
            task_map[task_id] = task
        
        # Add dependencies
        for dep in plan_data.get("dependencies", []):
            from_task = dep.get("from")
            to_task = dep.get("to")
            if from_task in task_map and to_task in task_map:
                dag.add_edge(from_task, to_task)
        
        # Update stats
        dag.update_stats()
        
        return dag
    
    def _map_task_type(self, type_str: str) -> TaskType:
        """Map string to TaskType enum"""
        type_map = {
            "reconnaissance": TaskType.RECONNAISSANCE,
            "scanning": TaskType.SCANNING,
            "vulnerability_scan": TaskType.VULNERABILITY_SCAN,
            "exploitation": TaskType.EXPLOITATION,
            "reporting": TaskType.REPORTING,
            "tool_execution": TaskType.TOOL_EXECUTION
        }
        return type_map.get(type_str, TaskType.TOOL_EXECUTION)
    
    def _estimate_task_cost(self, task_data: Dict) -> float:
        """Estimate cost for task"""
        # Base cost calculation
        duration = task_data.get("estimated_duration", 300)
        complexity = len(task_data.get("capabilities", []))
        
        # Simple cost model: $0.001 per second + $0.01 per capability
        return (duration * 0.001) + (complexity * 0.01)
    
    async def _cached_plan_to_dag(self, cached_plan: Dict, process_id: str) -> DAG:
        """Convert cached plan to DAG"""
        
        dag = DAG(
            dag_id=f"dag_{uuid.uuid4().hex[:8]}",
            process_id=process_id,
            name=cached_plan.get("name", "Cached plan"),
            description=cached_plan.get("description", "")
        )
        
        # Reconstruct tasks from cache
        for task_data in cached_plan.get("tasks", []):
            task = TaskNode(**task_data)
            dag.add_node(task)
        
        # Add dependencies
        for dep in cached_plan.get("dependencies", []):
            dag.add_edge(dep["from"], dep["to"])
        
        dag.update_stats()
        return dag
    
    def _create_default_plan(self, process_id: str, goal: str, target: Optional[str]) -> DAG:
        """Create default plan when LLM fails"""
        
        dag = DAG(
            dag_id=f"dag_{uuid.uuid4().hex[:8]}",
            process_id=process_id,
            name=goal[:50],
            description=goal
        )
        
        recon_task = TaskNode(
            task_id=f"task_{uuid.uuid4().hex[:8]}",
            name="Port and Service Scan",
            description="Discover open ports and services",
            task_type=TaskType.RECONNAISSANCE,
            required_capabilities=[AgentCapability.NETWORK_SCAN, AgentCapability.PORT_SCAN],
            parameters={"target": target, "scan_type": "-sT -sV", "ports": "1-1000", "timing": "-T4"},
            estimated_duration_seconds=60,
            estimated_cost=0.05,
            metadata={"tool": "nmap"}
        )
        dag.add_node(recon_task)
        
        vuln_task = TaskNode(
            task_id=f"task_{uuid.uuid4().hex[:8]}",
            name="Vulnerability Scan",
            description="Scan for known vulnerabilities",
            task_type=TaskType.VULNERABILITY_SCAN,
            required_capabilities=[AgentCapability.VULN_SCAN],
            parameters={"target": target, "severity": "critical,high,medium"},
            estimated_duration_seconds=120,
            estimated_cost=0.10,
            metadata={"tool": "nuclei"}
        )
        dag.add_node(vuln_task)
        
        dag.add_edge(recon_task.task_id, vuln_task.task_id)
        dag.update_stats()
        
        logger.info("Created default fallback plan (nmap → nuclei)")
        return dag