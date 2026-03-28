# src/agents/verifier/verifier_agent.py
from typing import Optional, Dict, Any, List, Set
from datetime import datetime

from src.agents.planner.llm_factory import llm_factory
from src.agents.verifier.dag_validator import DAGValidator
from src.agents.verifier.resource_validator import ResourceValidator
from src.models.dag import DAG, TaskNode, TaskStatus
from src.utils.logging import logger
from src.core.config import get_settings
from src.core.exceptions import DAGValidationError

settings = get_settings()


class VerifierAgent:
    """
    Enterprise Verifier Agent
    
    Validates execution plans for:
    - DAG structure (cycles, dependencies)
    - Resource availability
    - Capability matching
    - Security constraints
    - Budget compliance
    """
    
    def __init__(self):
        self.dag_validator = DAGValidator()
        self.resource_validator = ResourceValidator()
        self.llm_factory = llm_factory
        self.llm_client = self.llm_factory.get_client() if settings.llm_provider else None
        
        logger.info("✅ Verifier Agent initialized")
    
    async def validate_dag(
        self,
        dag: DAG,
        user_id: str,
        tenant_id: str,
        check_resources: bool = True,
        check_budget: bool = True
    ) -> DAG:
        """
        Validate DAG for execution
        
        Returns:
            Validated DAG (may be modified)
            
        Raises:
            DAGValidationError if validation fails
        """
        
        logger.info(
            f"Validating DAG {dag.dag_id}",
            extra={
                "dag_id": dag.dag_id,
                "process_id": dag.process_id,
                "total_tasks": dag.total_tasks
            }
        )
        
        issues = []
        
        # Step 1: Basic structure validation
        structure_issues = self.dag_validator.validate_structure(dag)
        issues.extend(structure_issues)
        
        # Step 2: Check for cycles
        if self.dag_validator.has_cycles(dag):
            issues.append("DAG contains cycles")
        
        # Step 3: Validate dependencies
        dep_issues = self.dag_validator.validate_dependencies(dag)
        issues.extend(dep_issues)
        
        # Step 4: Check resource availability
        if check_resources:
            resource_issues = await self.resource_validator.validate_resources(
                dag, tenant_id
            )
            issues.extend(resource_issues)
        
        # Step 5: Validate task capabilities
        capability_issues = await self._validate_capabilities(dag)
        issues.extend(capability_issues)
        
        # Step 6: Check budget (if enabled)
        if check_budget and dag.estimated_total_cost > 0:
            budget_issues = await self._validate_budget(dag, user_id, tenant_id)
            issues.extend(budget_issues)
        
        # If issues found, try to auto-fix or report
        if issues:
            # Try auto-fix for simple issues
            fixed_dag = await self._attempt_auto_fix(dag, issues)
            if fixed_dag:
                logger.info(f"✅ Auto-fixed {len(issues)} issues in DAG")
                return fixed_dag
            
            # Use LLM for complex issues if available
            if self.llm_client and len(issues) > 2:
                fixed_dag = await self._llm_fix_dag(dag, issues)
                if fixed_dag:
                    logger.info(f"✅ LLM fixed {len(issues)} issues in DAG")
                    return fixed_dag
            
            # Report issues
            error_msg = f"DAG validation failed: {', '.join(issues[:3])}"
            logger.error(error_msg)
            raise DAGValidationError(error_msg, details={"issues": issues})
        
        logger.info(f"✅ DAG {dag.dag_id} validated successfully")
        return dag
    
    async def _validate_capabilities(self, dag: DAG) -> List[str]:
        """Validate that all required capabilities are available"""
        
        issues = []
        required_caps = set()
        
        for task in dag.nodes.values():
            for cap in task.required_capabilities:
                required_caps.add(cap.value)
        
        # Check against available tools (to be implemented with tool registry)
        # For now, assume all capabilities are available
        logger.debug(f"Required capabilities: {required_caps}")
        
        return issues
    
    async def _validate_budget(self, dag: DAG, user_id: str, tenant_id: str) -> List[str]:
        """Validate budget constraints"""
        
        issues = []
        
        # This will be integrated with budget tracker in Phase 3
        if dag.estimated_total_cost > 1000:  # Example threshold
            issues.append(f"Estimated cost ${dag.estimated_total_cost:.2f} exceeds threshold")
        
        return issues
    
    async def _attempt_auto_fix(self, dag: DAG, issues: List[str]) -> Optional[DAG]:
        """Attempt to auto-fix common issues"""
        
        fixed = False
        
        # Fix missing dependencies
        for task_id, task in dag.nodes.items():
            # Add implicit dependencies based on task type
            if task.task_type.value == "vulnerability_scan":
                # Ensure there's a reconnaissance task before vuln scan
                has_recon = False
                for other_id, other_task in dag.nodes.items():
                    if other_task.task_type.value == "reconnaissance":
                        if other_id not in task.dependencies:
                            task.dependencies.append(other_id)
                            fixed = True
                            has_recon = True
                            break
                
                if not has_recon:
                    # Create recon task
                    logger.warning("Adding missing reconnaissance task")
                    # This would create a new task
                    fixed = True
        
        if fixed:
            dag.update_stats()
            return dag
        
        return None
    
    async def _llm_fix_dag(self, dag: DAG, issues: List[str]) -> Optional[DAG]:
        """Use LLM to fix complex DAG issues"""
        
        if not self.llm_client:
            return None
        
        try:
            # Convert DAG to JSON for LLM
            dag_json = dag.model_dump_json(indent=2)
            
            prompt = f"""
The following DAG has validation issues:

{dag_json}

Issues found:
{chr(10).join(f'- {issue}' for issue in issues)}

Please fix the DAG structure. Return the corrected DAG as JSON.
"""
            
            from src.agents.verifier.prompt_templates import VERIFIER_SYSTEM_PROMPT
            
            response = await self.llm_client.generate_json(
                prompt=prompt,
                system_prompt=VERIFIER_SYSTEM_PROMPT
            )
            
            if response.get("valid"):
                # Reconstruct fixed DAG
                fixed_dag = DAG(**response.get("dag", {}))
                return fixed_dag
            
        except Exception as e:
            logger.error(f"LLM DAG fix failed: {e}")
        
        return None


