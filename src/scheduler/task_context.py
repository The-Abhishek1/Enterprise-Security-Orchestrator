# src/scheduler/task_context.py
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid
import os
import tempfile
import shutil
import json

from src.models.execution import TaskExecution
from src.utils.logging import logger
from src.core.security import encrypt_value, decrypt_value


class TaskContextManager:
    """
    Enterprise Task Context Manager
    
    Manages:
    - Isolated execution context per task
    - Temporary file/directory management
    - Environment variables
    - Secure data handling
    - Input/output passing between tasks
    """
    
    def __init__(self):
        self.contexts: Dict[str, TaskExecution] = {}
        self.temp_dirs: Dict[str, str] = {}
        self.outputs: Dict[str, Dict[str, Any]] = {}
        
        logger.info("✅ Task Context Manager initialized")
    
    async def create_context(
        self,
        process_id: str,
        task_id: str,
        user_id: str,
        tenant_id: str,
        inputs: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None
    ) -> TaskExecution:
        """Create isolated context for task"""
        
        execution = TaskExecution(
            task_id=task_id,
            execution_id=execution_id or f"exec_{uuid.uuid4().hex[:12]}",
            process_id=process_id,
            user_id=user_id,  # Add this
            tenant_id=tenant_id,  # Add this
            inputs=inputs or {}
        )
        
        # Create temporary working directory
        temp_dir = tempfile.mkdtemp(
            prefix=f"eso_{process_id}_{task_id}_",
            suffix=f"_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        )
        
        self.temp_dirs[execution.execution_id] = temp_dir
        self.contexts[execution.execution_id] = execution
        
        logger.debug(
            f"Created context for task {task_id}",
            extra={
                "process_id": process_id,
                "task_id": task_id,
                "execution_id": execution.execution_id,
                "temp_dir": temp_dir
            }
        )
        
        return execution
    
    async def get_context(self, execution_id: str) -> Optional[TaskExecution]:
        """Get context by execution ID"""
        return self.contexts.get(execution_id)
    
    async def update_context(
        self,
        execution_id: str,
        status: Optional[str] = None,
        result: Optional[Dict] = None,
        error: Optional[str] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        exit_code: Optional[int] = None
    ) -> Optional[TaskExecution]:
        """Update context with execution results"""
        
        context = self.contexts.get(execution_id)
        if not context:
            return None
        
        if status:
            context.status = status
        
        if result:
            context.result = result
            # Store output for dependent tasks
            self.outputs[context.task_id] = result
        
        if error:
            context.error = error
        
        if stdout:
            context.stdout = stdout
        
        if stderr:
            context.stderr = stderr
        
        if exit_code is not None:
            context.exit_code = exit_code
        
        if status in ["completed", "failed", "cancelled"]:
            context.completed_at = datetime.utcnow()
            # Clean up temp directory
            await self.cleanup_context(execution_id)
        
        return context
    
    async def get_input(self, execution_id: str, key: str) -> Any:
        """Get input value"""
        context = self.contexts.get(execution_id)
        if not context or not context.inputs:
            return None
        
        return context.inputs.get(key)
    
    async def get_dependency_output(self, task_id: str, key: Optional[str] = None) -> Any:
        """Get output from dependent task"""
        
        output = self.outputs.get(task_id)
        if not output:
            return None
        
        if key:
            return output.get(key)
        
        return output
    
    def get_temp_path(self, execution_id: str, filename: str) -> Optional[str]:
        """Get path for temporary file"""
        
        temp_dir = self.temp_dirs.get(execution_id)
        if not temp_dir:
            return None
        
        return os.path.join(temp_dir, filename)
    
    async def write_temp_file(self, execution_id: str, filename: str, data: Any) -> str:
        """Write data to temporary file"""
        
        file_path = self.get_temp_path(execution_id, filename)
        if not file_path:
            raise ValueError(f"No temp directory for execution {execution_id}")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Write data
        if isinstance(data, (dict, list)):
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
        elif isinstance(data, str):
            with open(file_path, 'w') as f:
                f.write(data)
        else:
            with open(file_path, 'wb') as f:
                f.write(data)
        
        return file_path
    
    async def read_temp_file(self, execution_id: str, filename: str) -> Any:
        """Read data from temporary file"""
        
        file_path = self.get_temp_path(execution_id, filename)
        if not file_path or not os.path.exists(file_path):
            return None
        
        # Read based on extension
        if filename.endswith('.json'):
            with open(file_path, 'r') as f:
                return json.load(f)
        elif filename.endswith('.txt'):
            with open(file_path, 'r') as f:
                return f.read()
        else:
            with open(file_path, 'rb') as f:
                return f.read()
    
    async def cleanup_context(self, execution_id: str):
        """Clean up context and temporary files"""
        
        # Remove temp directory
        temp_dir = self.temp_dirs.pop(execution_id, None)
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.debug(f"Cleaned up temp directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp directory {temp_dir}: {e}")
        
        # Keep context for history
        # self.contexts.pop(execution_id, None)
    
    async def get_context_stats(self) -> Dict[str, Any]:
        """Get context manager statistics"""
        
        return {
            "active_contexts": len(self.contexts),
            "active_temp_dirs": len(self.temp_dirs),
            "stored_outputs": len(self.outputs)
        }