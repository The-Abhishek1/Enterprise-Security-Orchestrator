# src/models/execution.py
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uuid


class ExecutionStatus(str, Enum):
    """Execution status"""
    PENDING = "pending"
    PLANNING = "planning"
    VALIDATING = "validating"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskStatus(str, Enum):
    """Task status"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"
    BLOCKED = "blocked"


class ExecutionPriority(int, Enum):
    """Execution priority (higher = more important)"""
    LOW = 0
    MEDIUM = 5
    HIGH = 10
    CRITICAL = 20


class Execution(BaseModel):
    """Execution model for persistence"""
    
    process_id: str = Field(default_factory=lambda: f"proc_{uuid.uuid4().hex[:12]}")
    goal: str
    target: Optional[str] = None
    user_id: str
    tenant_id: str
    
    status: ExecutionStatus = ExecutionStatus.PENDING
    priority: ExecutionPriority = ExecutionPriority.MEDIUM
    
    # DAG reference
    dag_id: Optional[str] = None
    dag: Optional[Dict] = None
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Budget
    budget_limit: Optional[float] = None
    estimated_cost: float = 0.0
    actual_cost: float = 0.0
    
    # Statistics
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    
    # Results
    result_summary: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class TaskExecution(BaseModel):
    """Task execution model"""
    
    task_id: str
    execution_id: str
    process_id: str
    
    # Add these missing fields
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    inputs: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    status: TaskStatus = TaskStatus.PENDING
    assigned_agent: Optional[str] = None
    assigned_tool: Optional[str] = None
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Results
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None
    
    # Metrics
    cost: float = 0.0
    duration_seconds: Optional[float] = None
    retry_count: int = 0
    
    # Dependencies
    dependencies: List[str] = Field(default_factory=list)
    dependent_tasks: List[str] = Field(default_factory=list)