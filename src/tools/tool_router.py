# src/tools/tool_router.py
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio
import hashlib

from src.tools.tool_registry import ToolRegistry
from src.tools.rate_limiter import ToolRateLimiter
from src.tools.cost_tracker import ToolCostTracker
from src.workers.worker_pool import WorkerPool
from src.core.config import get_settings
from src.utils.logging import logger
from src.core.exceptions import ToolExecutionError

settings = get_settings()


class ToolRouter:
    """
    Enterprise Tool Router
    
    Responsibilities:
    - Tool selection based on capability
    - Rate limiting per user/tool
    - Load balancing across workers
    - Cost tracking & budget enforcement
    - Tool version management
    """
    
    def __init__(
        self,
        tool_registry: ToolRegistry,
        worker_pool: WorkerPool,
        rate_limiter: Optional[ToolRateLimiter] = None,
        cost_tracker: Optional[ToolCostTracker] = None
    ):
        self.tool_registry = tool_registry
        self.worker_pool = worker_pool
        self.rate_limiter = rate_limiter or ToolRateLimiter()
        self.cost_tracker = cost_tracker or ToolCostTracker()
        
        # Connect worker pool to tool registry
        self.worker_pool.tool_registry = tool_registry
        
        # Load balancing strategies
        self.load_balancers = {
            "round_robin": self._round_robin_load_balancer,
            "least_loaded": self._least_loaded_load_balancer,
            "random": self._random_load_balancer
        }
        
        # Tool execution metrics
        self.metrics: Dict[str, Dict] = {}
        
        logger.info("✅ Tool Router initialized")
    
    async def route_and_execute(
        self,
        task: Any,
        params: Dict[str, Any],
        user_id: str,
        tenant_id: str,
        execution_id: str
    ) -> Dict[str, Any]:
        """
        Route task to appropriate tool and execute
        
        Args:
            task: Task node containing required capabilities
            params: Tool parameters
            user_id: User identifier
            tenant_id: Tenant identifier
            execution_id: Execution identifier
        
        Returns:
            Tool execution result
        """
        logger.info(f"🛠️ ToolRouter executing task: {getattr(task, 'name', 'unknown')}")
        
        # Get required capability from task
        required_capability = None
        if hasattr(task, 'required_capabilities') and task.required_capabilities:
            required_capability = task.required_capabilities[0]
        
        if not required_capability:
            # Try to determine from params
            tool_name = params.get("tool")
            if tool_name:
                tool = await self.tool_registry.get_tool(tool_name)
                if tool:
                    required_capability = tool.get("capabilities", [None])[0]
        
        if not required_capability:
            raise ToolExecutionError(
                message="No capability specified for task",
                tool="unknown"
            )
        
        # Get capability value
        capability_value = required_capability.value if hasattr(required_capability, 'value') else required_capability
        
        # Find suitable tools
        available_tools = await self.tool_registry.find_tools_by_capability(
            capability=capability_value,
            tenant_id=tenant_id
        )
        
        if not available_tools:
            raise ToolExecutionError(
                message=f"No tool found for capability: {capability_value}",
                tool="unknown"
            )
        
        # Check rate limits
        if self.rate_limiter:
            await self.rate_limiter.check_limits(
                user_id=user_id,
                tenant_id=tenant_id,
                tools=available_tools
            )
        
        # Select tool with load balancing
        selected_tool = await self._select_tool(available_tools, params)
        
        # Estimate and check cost
        estimated_cost = await self.cost_tracker.estimate_cost(
            tool_name=selected_tool["name"],
            params=params
        )
        
        if not await self.cost_tracker.check_budget(
            user_id=user_id,
            tenant_id=tenant_id,
            estimated_cost=estimated_cost,
            execution_id=execution_id
        ):
            raise ToolExecutionError(
                message="Budget limit exceeded",
                tool=selected_tool["name"]
            )
        
        # Execute tool
        try:
            start_time = datetime.utcnow()
            
            result = await self._execute_tool(
                tool=selected_tool,
                params=params,
                user_id=user_id,
                tenant_id=tenant_id,
                execution_id=execution_id
            )
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Track cost
            await self.cost_tracker.track_usage(
                user_id=user_id,
                tenant_id=tenant_id,
                tool_name=selected_tool["name"],
                duration=duration,
                execution_id=execution_id
            )
            
            # Update metrics
            await self._update_metrics(selected_tool["name"], duration, True)
            
            return result
            
        except Exception as e:
            # Update failure metrics
            await self._update_metrics(selected_tool["name"], 0, False)
            
            logger.error(
                f"Tool execution failed: {str(e)}",
                extra={
                    "tool": selected_tool["name"],
                    "execution_id": execution_id,
                    "error": str(e)
                }
            )
            
            # Try fallback tool if available
            if len(available_tools) > 1:
                logger.info(f"Attempting fallback tool for {capability_value}")
                return await self._execute_with_fallback(
                    available_tools=available_tools[1:],
                    params=params,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    execution_id=execution_id,
                    original_error=e
                )
            
            raise ToolExecutionError(
                message=f"Tool execution failed: {str(e)}",
                tool=selected_tool["name"]
            )
    
    async def _select_tool(
        self,
        available_tools: List[Dict],
        params: Dict[str, Any]
    ) -> Dict:
        """Select appropriate tool using load balancing"""
        
        # Filter by version if specified
        if "tool_version" in params:
            available_tools = [
                t for t in available_tools
                if t.get("version") == params["tool_version"]
            ]
        
        if not available_tools:
            raise ToolExecutionError(
                message="No tools available after filtering",
                tool="unknown"
            )
        
        # Use load balancing strategy
        strategy = params.get("load_balancing", "least_loaded")
        load_balancer = self.load_balancers.get(strategy, self._least_loaded_load_balancer)
        
        return await load_balancer(available_tools)
    

    async def _execute_tool(
        self,
        tool: Dict,
        params: Dict[str, Any],
        user_id: str,
        tenant_id: str,
        execution_id: str
    ) -> Dict[str, Any]:
        """Execute tool and stream output"""
        
        execution_params = {
            "tool_name": tool["name"],
            "tool_version": tool.get("version", "latest"),
            "command": tool.get("command", tool["name"]),
            "args": self._prepare_tool_args(tool, params),
            "timeout": params.get("timeout", tool.get("default_timeout", 300)),
            "environment": {
                "ESO_USER_ID": user_id,
                "ESO_TENANT_ID": tenant_id,
                "ESO_EXECUTION_ID": execution_id,
                **params.get("environment", {})
            }
        }
        
        # Execute in worker
        result = await self.worker_pool.execute(execution_params)
        
        # Stream output to memory bus for real-time viewing
        if hasattr(self, 'memory_bus') and self.memory_bus:
            await self.memory_bus.publish(
                topic=f"execution:{execution_id}:output",
                agent_id="tool_router",
                message={
                    "tool": tool["name"],
                    "output": result.get("stdout", "")[-1000:],  # Last 1000 chars
                    "timestamp": datetime.utcnow().isoformat()
                },
                persist=False
            )
        
        return result
    
    async def _execute_with_fallback(
        self,
        available_tools: List[Dict],
        params: Dict[str, Any],
        user_id: str,
        tenant_id: str,
        execution_id: str,
        original_error: Exception
    ) -> Dict[str, Any]:
        """Execute with fallback tool"""
        
        errors = [str(original_error)]
        
        for tool in available_tools:
            try:
                logger.info(f"Trying fallback tool: {tool['name']}")
                return await self._execute_tool(
                    tool=tool,
                    params=params,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    execution_id=execution_id
                )
            except Exception as e:
                errors.append(str(e))
                continue
        
        # All fallbacks failed
        raise ToolExecutionError(
            message=f"All tools failed: {'; '.join(errors)}",
            tool="multiple"
        )
    
    def _prepare_tool_args(self, tool: Dict, params: Dict[str, Any]) -> List[str]:
        """Prepare command-line arguments for tool"""
        
        args = []
        
        # Add base command if present
        if "base_command" in tool and tool["base_command"]:
            if isinstance(tool["base_command"], list):
                args.extend(tool["base_command"])
            else:
                args.append(tool["base_command"])
        
        # Handle target specially (often positional)
        target = params.get("target") or params.get("url") or params.get("host")
        
        # Map parameters to arguments
        param_mapping = tool.get("param_mapping", {})
        
        for param_name, param_value in params.items():
            if param_name in param_mapping and param_value is not None:
                mapped = param_mapping[param_name]
                
                if mapped is None:
                    # Positional argument - handle at the end
                    continue
                elif isinstance(mapped, str):
                    args.append(mapped)
                    if not isinstance(param_value, bool):
                        args.append(str(param_value))
                    elif param_value is True:
                        # It's a flag, already added
                        pass
                elif isinstance(mapped, list):
                    args.extend(mapped)
                    if not isinstance(param_value, bool):
                        args.append(str(param_value))
        
        # Add target at the end for tools that expect positional target
        if target and tool["name"] in ["nmap", "nuclei"]:
            args.append(target)
        
        # Tool-specific defaults
        if tool["name"] == "nmap":
            if not any(arg in str(args) for arg in ["-sS", "-sT", "-sV"]):
                args.extend(["-sV"])
        
        elif tool["name"] == "nuclei":
            pass  # nuclei uses default templates if none specified
        
        elif tool["name"] == "nikto":
            # nikto -h <target>
            if target and "-h" not in args:
                args.extend(["-h", target])
        
        elif tool["name"] == "ffuf":
            # ffuf -u <target>/FUZZ -w <wordlist>
            if target:
                fuzz_url = params.get("url", f"{target}/FUZZ")
                if "FUZZ" not in fuzz_url:
                    fuzz_url = f"{fuzz_url}/FUZZ"
                if "-u" not in args:
                    args.extend(["-u", fuzz_url])
                wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
                if "-w" not in args:
                    args.extend(["-w", wordlist])
                # Output as CSV for parsing
                if "-of" not in args:
                    args.extend(["-of", "csv"])
        
        elif tool["name"] == "whatweb":
            # whatweb <target>
            if target and target not in args:
                args.append(target)
            if "--color" not in args:
                args.extend(["--color", "never"])
            if "-a" not in args:
                args.extend(["-a", str(params.get("aggression", 3))])
        
        logger.debug(f"Prepared args for {tool['name']}: {args}")
        return args
    
    async def _update_metrics(self, tool_name: str, duration: float, success: bool):
        """Update tool execution metrics"""
        
        if tool_name not in self.metrics:
            self.metrics[tool_name] = {
                "executions": 0,
                "successes": 0,
                "failures": 0,
                "total_duration": 0,
                "avg_duration": 0
            }
        
        metrics = self.metrics[tool_name]
        metrics["executions"] += 1
        
        if success:
            metrics["successes"] += 1
            metrics["total_duration"] += duration
            metrics["avg_duration"] = metrics["total_duration"] / metrics["successes"]
        else:
            metrics["failures"] += 1
    
    # Load balancing strategies
    
    async def _round_robin_load_balancer(self, tools: List[Dict]) -> Dict:
        """Round-robin load balancing"""
        # Simple implementation - in production, track index per tool type
        import random
        return random.choice(tools)
    
    async def _least_loaded_load_balancer(self, tools: List[Dict]) -> Dict:
        """Select least loaded worker for each tool"""
        
        # Get current load for each tool
        tool_loads = []
        for tool in tools:
            load = await self.worker_pool.get_tool_load(tool["name"])
            tool_loads.append((tool, load))
        
        # Select tool with lowest load
        return min(tool_loads, key=lambda x: x[1])[0]
    
    async def _random_load_balancer(self, tools: List[Dict]) -> Dict:
        """Random load balancing"""
        import random
        return random.choice(tools)
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get tool router metrics"""
        return self.metrics