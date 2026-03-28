# src/agents/verifier/dag_validator.py
from src.models.dag import DAG
from typing import List

class DAGValidator:
    """DAG structure validator"""
    
    def validate_structure(self, dag: DAG) -> List[str]:
        """Validate basic DAG structure"""
        
        issues = []
        
        # Check for empty DAG
        if not dag.nodes:
            issues.append("DAG has no tasks")
        
        # Check for duplicate task IDs
        task_ids = set()
        for task_id in dag.nodes:
            if task_id in task_ids:
                issues.append(f"Duplicate task ID: {task_id}")
            task_ids.add(task_id)
        
        return issues
    
    def has_cycles(self, dag: DAG) -> bool:
        """Check if DAG has cycles using DFS"""
        
        visited = set()
        recursion_stack = set()
        
        def dfs(node_id: str) -> bool:
            visited.add(node_id)
            recursion_stack.add(node_id)
            
            # Find all outgoing edges from this node
            for edge in dag.edges:
                if edge["from"] == node_id:
                    neighbor = edge["to"]
                    if neighbor not in visited:
                        if dfs(neighbor):
                            return True
                    elif neighbor in recursion_stack:
                        return True
            
            recursion_stack.remove(node_id)
            return False
        
        for node_id in dag.nodes:
            if node_id not in visited:
                if dfs(node_id):
                    return True
        
        return False
    
    def validate_dependencies(self, dag: DAG) -> List[str]:
        """Validate task dependencies"""
        
        issues = []
        
        for task_id, task in dag.nodes.items():
            for dep_id in task.dependencies:
                if dep_id not in dag.nodes:
                    issues.append(f"Task {task_id} depends on non-existent task {dep_id}")
        
        return issues



