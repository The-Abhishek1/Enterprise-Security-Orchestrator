# src/core/exceptions.py
from typing import Optional, Dict, Any


class EnterpriseBaseException(Exception):
    """Base exception for all enterprise exceptions"""
    
    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)


class AuthenticationError(EnterpriseBaseException):
    """Authentication failed"""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            code="AUTHENTICATION_ERROR",
            status_code=401,
            details=details
        )


class AuthorizationError(EnterpriseBaseException):
    """Authorization failed"""
    
    def __init__(self, message: str = "Permission denied", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            code="AUTHORIZATION_ERROR",
            status_code=403,
            details=details
        )


class RateLimitExceededError(EnterpriseBaseException):
    """Rate limit exceeded"""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 60, details: Optional[Dict] = None):
        super().__init__(
            message=message,
            code="RATE_LIMIT_EXCEEDED",
            status_code=429,
            details={**(details or {}), "retry_after": retry_after}
        )


class ValidationError(EnterpriseBaseException):
    """Request validation failed"""
    
    def __init__(self, message: str = "Validation failed", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=400,
            details=details
        )


class ResourceNotFoundError(EnterpriseBaseException):
    """Resource not found"""
    
    def __init__(self, message: str = "Resource not found", resource_type: str = "resource", resource_id: str = ""):
        super().__init__(
            message=message,
            code="RESOURCE_NOT_FOUND",
            status_code=404,
            details={"resource_type": resource_type, "resource_id": resource_id}
        )


class BudgetExceededError(EnterpriseBaseException):
    """Budget exceeded"""
    
    def __init__(self, message: str = "Budget exceeded", budget_limit: float = 0, current_cost: float = 0):
        super().__init__(
            message=message,
            code="BUDGET_EXCEEDED",
            status_code=402,
            details={"budget_limit": budget_limit, "current_cost": current_cost}
        )


class QuotaExceededError(EnterpriseBaseException):
    """Quota exceeded"""
    
    def __init__(self, message: str = "Quota exceeded", quota_type: str = "unknown", limit: int = 0, current: int = 0):
        super().__init__(
            message=message,
            code="QUOTA_EXCEEDED",
            status_code=429,
            details={"quota_type": quota_type, "limit": limit, "current": current}
        )


class DAGValidationError(EnterpriseBaseException):
    """DAG validation failed"""
    
    def __init__(self, message: str = "DAG validation failed", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            code="DAG_VALIDATION_ERROR",
            status_code=400,
            details=details
        )


class ToolExecutionError(EnterpriseBaseException):
    """Tool execution failed"""
    
    def __init__(self, message: str = "Tool execution failed", tool: str = "unknown", exit_code: int = -1):
        super().__init__(
            message=message,
            code="TOOL_EXECUTION_ERROR",
            status_code=500,
            details={"tool": tool, "exit_code": exit_code}
        )


class AgentExecutionError(EnterpriseBaseException):
    """Agent execution failed"""
    
    def __init__(self, message: str = "Agent execution failed", agent: str = "unknown", task: str = ""):
        super().__init__(
            message=message,
            code="AGENT_EXECUTION_ERROR",
            status_code=500,
            details={"agent": agent, "task": task}
        )


class WorkerExecutionError(EnterpriseBaseException):
    """Worker execution failed"""
    
    def __init__(self, message: str = "Worker execution failed", worker_id: str = "unknown"):
        super().__init__(
            message=message,
            code="WORKER_EXECUTION_ERROR",
            status_code=500,
            details={"worker_id": worker_id}
        )


class RetryExhaustedError(Exception):
    """All retry attempts exhausted"""
    
    def __init__(self, message: str, last_error: str = ""):
        self.message = message
        self.last_error = last_error
        super().__init__(message)