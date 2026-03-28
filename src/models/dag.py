# src/models/dag.py
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from enum import Enum
import uuid
from pydantic import BaseModel, Field


class TaskType(str, Enum):
    """Types of tasks"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    TOOL_EXECUTION = "tool_execution"


class AgentCapability(str, Enum):
    """Agent capabilities"""
    NETWORK_SCAN = "network_scan"
    PORT_SCAN = "port_scan"
    VULN_SCAN = "vuln_scan"
    WEB_SCAN = "web_scan"
    DNS_ENUMERATION = "dns_enumeration"
    SQL_INJECTION = "sql_injection"
    EXPLOIT = "exploit"
    OSINT = "osint"


class TaskStatus(str, Enum):
    """Task status"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"
    SKIPPED = "skipped"


class TaskNode(BaseModel):
    """Represents a single task in the DAG"""
    
    task_id: str = Field(default_factory=lambda: f"task_{uuid.uuid4().hex[:8]}")
    name: str
    description: Optional[str] = None
    task_type: TaskType
    required_capabilities: List[AgentCapability] = Field(default_factory=list)
    
    # DAG relationships
    dependencies: List[str] = Field(default_factory=list)  # Task IDs this depends on
    
    # Parameters
    parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Execution state
    status: TaskStatus = TaskStatus.PENDING
    assigned_agent: Optional[str] = None
    assigned_tool: Optional[str] = None
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Results
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    
    # Metrics
    estimated_duration_seconds: int = 300
    estimated_cost: float = 0.0
    actual_cost: float = 0.0
    retry_count: int = 0
    max_retries: int = 3
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "task_id": self.task_id,
            "name": self.name,
            "task_type": self.task_type.value,
            "status": self.status.value,
            "dependencies": self.dependencies,
            "parameters": self.parameters
        }


class DAG(BaseModel):
    """Directed Acyclic Graph of tasks"""
    
    dag_id: str = Field(default_factory=lambda: f"dag_{uuid.uuid4().hex[:8]}")
    process_id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    
    # Tasks
    nodes: Dict[str, TaskNode] = Field(default_factory=dict)
    
    # DAG structure
    edges: List[Dict[str, str]] = Field(default_factory=list)  # [{"from": "task1", "to": "task2"}]
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Stats
    total_tasks: int = 0
    estimated_total_cost: float = 0.0
    estimated_duration_seconds: int = 0
    
    # Version
    version: int = 1
    
    def add_node(self, task: TaskNode) -> None:
        """Add a task node"""
        self.nodes[task.task_id] = task
        self.total_tasks = len(self.nodes)
        self.estimated_total_cost += task.estimated_cost
        self.estimated_duration_seconds = max(
            self.estimated_duration_seconds,
            task.estimated_duration_seconds
        )
    
    def add_edge(self, from_task: str, to_task: str) -> None:
        """Add a dependency edge"""
        if from_task not in self.nodes or to_task not in self.nodes:
            raise ValueError(f"Invalid edge: {from_task} -> {to_task}")
        
        self.edges.append({"from": from_task, "to": to_task})
        self.nodes[to_task].dependencies.append(from_task)
    
    def get_execution_order(self) -> List[List[str]]:
        """
        Get topological execution order (parallel levels)
        Returns list of levels, each level is list of task IDs that can run in parallel
        """
        # Calculate in-degree for each node
        in_degree = {task_id: 0 for task_id in self.nodes}
        for edge in self.edges:
            in_degree[edge["to"]] += 1
        
        # Find initial nodes (no dependencies)
        queue = [task_id for task_id, degree in in_degree.items() if degree == 0]
        execution_order = []
        
        while queue:
            # Current level - all tasks that can run in parallel
            level = queue.copy()
            execution_order.append(level)
            
            # Remove these tasks from queue
            queue.clear()
            
            # Process each task in current level
            for task_id in level:
                # Find all tasks that depend on this task
                for edge in self.edges:
                    if edge["from"] == task_id:
                        to_task = edge["to"]
                        in_degree[to_task] -= 1
                        if in_degree[to_task] == 0:
                            queue.append(to_task)
        
        # Check for cycles
        if len([t for t in in_degree.values() if t > 0]) > 0:
            raise ValueError("DAG contains cycles")
        
        return execution_order
    
    def validate(self) -> bool:
        """Validate DAG structure"""
        # Check for cycles
        try:
            self.get_execution_order()
            return True
        except ValueError:
            return False
    
    def update_stats(self) -> None:
        """Update DAG statistics"""
        self.total_tasks = len(self.nodes)
        self.estimated_total_cost = sum(
            task.estimated_cost for task in self.nodes.values()
        )
        self.estimated_duration_seconds = max(
            (task.estimated_duration_seconds for task in self.nodes.values()),
            default=0
        )
        self.updated_at = datetime.utcnow()


class TaskContext(BaseModel):
    """Context for task execution"""
    
    context_id: str = Field(default_factory=lambda: f"ctx_{uuid.uuid4().hex[:8]}")
    process_id: str
    task_id: str
    user_id: str
    tenant_id: str
    
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Environment
    environment_vars: Dict[str, str] = Field(default_factory=dict)
    working_directory: Optional[str] = None
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    def add_output(self, key: str, value: Any) -> None:
        """Add output value"""
        self.outputs[key] = value
    
    def add_artifact(self, name: str, data: Any, mime_type: str = "application/octet-stream") -> None:
        """Add artifact"""
        self.artifacts.append({
            "name": name,
            "data": data,
            "mime_type": mime_type,
            "created_at": datetime.utcnow().isoformat()
        })