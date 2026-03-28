# src/agents/verifier/resource_validator.py
from src.models.dag import DAG
from typing import List


class ResourceValidator:
    """Resource availability validator"""
    
    async def validate_resources(self, dag: DAG, tenant_id: str) -> List[str]:
        """Validate resource availability"""
        
        issues = []
        
        # Calculate total resource requirements
        total_cpu = 0.0
        total_memory = 0
        concurrent_tasks = 0
        
        for task in dag.nodes.values():
            # Estimate resource usage based on task type
            cpu, memory = self._estimate_resource_usage(task)
            total_cpu += cpu
            total_memory += memory
        
        # Get execution order to check concurrency
        try:
            execution_order = dag.get_execution_order()
            max_concurrent = max(len(level) for level in execution_order)
            concurrent_tasks = max_concurrent
        except:
            pass
        
        # Check against limits (to be integrated with quota manager)
        if total_cpu > 8.0:  # 8 CPU cores limit example
            issues.append(f"Total CPU requirement {total_cpu} exceeds limit")
        
        if total_memory > 16 * 1024 * 1024 * 1024:  # 16GB limit example
            issues.append(f"Total memory requirement exceeds limit")
        
        if concurrent_tasks > 5:  # Max 5 concurrent tasks example
            issues.append(f"Too many concurrent tasks: {concurrent_tasks}")
        
        return issues
    
    def _estimate_resource_usage(self, task) -> tuple:
        """Estimate CPU and memory usage for task"""
        
        # Default values
        cpu = 0.5  # 0.5 CPU cores
        memory = 512 * 1024 * 1024  # 512MB
        
        # Adjust based on task type
        if task.task_type.value == "vulnerability_scan":
            cpu = 1.0
            memory = 1024 * 1024 * 1024  # 1GB
        elif task.task_type.value == "exploitation":
            cpu = 1.5
            memory = 2 * 1024 * 1024 * 1024  # 2GB
        
        return cpu, memory