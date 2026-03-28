from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    PLANNING = "planning"
    VALIDATING = "validating"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class HybridExecutionResponse(BaseModel):
    """Response for hybrid execution"""
    
    process_id: str
    status: ExecutionStatus
    goal: str
    target: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    message: Optional[str] = None


class ExecutionStatusResponse(BaseModel):
    """Execution status response"""
    
    process_id: str
    status: ExecutionStatus
    progress: float = Field(..., ge=0, le=100)
    current_task: Optional[str] = None
    completed_tasks: int = 0
    total_tasks: int = 0
    started_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    error: Optional[str] = None


class ExecutionListResponse(BaseModel):
    """List executions response"""
    
    executions: List[HybridExecutionResponse]
    total: int
    page: int
    page_size: int
    has_more: bool