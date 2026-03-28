# src/api/models/request.py
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class ExecutionMode(str, Enum):
    SYNC = "sync"
    ASYNC = "async"
    BATCH = "batch"


class ExecutionPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HybridExecutionRequest(BaseModel):
    """Request for hybrid execution"""
    
    goal: str = Field(..., description="Security goal to execute", min_length=3, max_length=1000)
    target: Optional[str] = Field(None, description="Target domain/IP/URL")
    mode: ExecutionMode = Field(ExecutionMode.ASYNC, description="Execution mode")
    priority: ExecutionPriority = Field(ExecutionPriority.MEDIUM, description="Execution priority")
    budget_limit: Optional[float] = Field(None, description="Budget limit in USD", ge=0)
    timeout: Optional[int] = Field(600, description="Execution timeout in seconds", ge=60, le=86400)
    webhook_url: Optional[str] = Field(None, description="Webhook URL for notifications")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Additional parameters")
    
    @validator("webhook_url")
    def validate_webhook(cls, v):
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("Webhook URL must start with http:// or https://")
        return v


class ScheduledExecutionRequest(HybridExecutionRequest):
    """Request for scheduled execution"""
    
    schedule: str = Field(..., description="Cron expression for scheduling")
    start_date: Optional[datetime] = Field(None, description="Start date for schedule")
    end_date: Optional[datetime] = Field(None, description="End date for schedule")
    max_executions: Optional[int] = Field(None, description="Maximum number of executions", ge=1)


class BatchExecutionRequest(BaseModel):
    """Request for batch execution"""
    
    executions: List[HybridExecutionRequest] = Field(..., description="List of executions", min_items=1, max_items=100)
    parallel: bool = Field(True, description="Execute in parallel")
    continue_on_error: bool = Field(False, description="Continue on error")


