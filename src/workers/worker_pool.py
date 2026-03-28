# src/workers/worker_pool.py
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
import uuid
import docker
from docker.errors import DockerException, NotFound

from src.workers.container_manager import ContainerManager
from src.workers.network_manager import NetworkManager
from src.workers.resource_monitor import ResourceMonitor
from src.core.config import get_settings
from src.utils.logging import logger
from src.core.exceptions import WorkerExecutionError

settings = get_settings()


class WorkerPool:
    """
    Enterprise Worker Pool with Docker isolation
    
    Features:
    - Dynamic worker creation per tool
    - Auto-scaling based on load
    - Resource limits (CPU/Memory)
    - Health checking and recovery
    - Network isolation
    - Container lifecycle management
    """
    
    def __init__(
        self,
        container_manager: ContainerManager,
        network_manager: NetworkManager,
        resource_monitor: ResourceMonitor
    ):
        self.container_manager = container_manager
        self.network_manager = network_manager
        self.resource_monitor = resource_monitor
        
        # Worker pools per tool
        self.worker_pools: Dict[str, List[Dict]] = {}
        
        # Worker status tracking
        self.worker_status: Dict[str, Dict] = {}
        
        # Task queue per worker
        self.task_queues: Dict[str, asyncio.Queue] = {}
        
        # Recovery tracking
        self._recovery_attempts: Dict[str, int] = {}
        
        # Tool registry reference (will be set later)
        self.tool_registry = None
        
        # Configuration
        self.min_workers_per_tool = getattr(settings, 'min_workers_per_tool', 1)
        self.max_workers_per_tool = getattr(settings, 'max_workers_per_tool', 5)
        self.scale_up_threshold = getattr(settings, 'scale_up_threshold', 0.7)
        self.scale_down_threshold = getattr(settings, 'scale_down_threshold', 0.2)
        
        # Background tasks will be started on first use
        self._background_tasks_started = False
        
        logger.info("✅ Worker Pool initialized")
    
    def _ensure_background_tasks(self):
        """Start background tasks on first use (when event loop is running)"""
        if not self._background_tasks_started:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._health_check_loop())
                loop.create_task(self._auto_scaler_loop())
                self._background_tasks_started = True
                logger.info("✅ Worker Pool background tasks started")
            except RuntimeError:
                logger.warning("No running event loop, deferring background tasks")
    
    async def initialize_pool(self, tool_name: str, tool_config: Dict):
        """Initialize worker pool for a tool"""

        self._ensure_background_tasks()
        
        if tool_name in self.worker_pools:
            logger.debug(f"Worker pool for {tool_name} already exists")
            return
        
        self.worker_pools[tool_name] = []
        
        # Create initial workers
        for i in range(self.min_workers_per_tool):
            await self._create_worker(tool_name, tool_config)
        
        logger.info(f"✅ Initialized worker pool for {tool_name} with {self.min_workers_per_tool} worker(s)")
    
    async def _create_worker(self, tool_name: str, tool_config: Dict) -> Dict:
        """Create a new worker container"""
        
        worker_id = f"worker_{tool_name}_{uuid.uuid4().hex[:8]}"
        
        try:
            # Ensure the pool exists
            if tool_name not in self.worker_pools:
                self.worker_pools[tool_name] = []
            
            # Get image from config or use default
            image = tool_config.get("image", f"{tool_name}:latest")
            
            # Create container on default bridge network (for internet access)
            container_id = await self.container_manager.create_container(
                image=image,
                name=worker_id,
                command=["sleep", "infinity"],  # Keep container alive
                resource_limits=tool_config.get("resource_requirements", {}),
                environment={
                    "WORKER_ID": worker_id,
                    "TOOL_NAME": tool_name,
                    "DEBIAN_FRONTEND": "noninteractive"
                },
                labels={
                    "eso.worker": "true",
                    "eso.tool": tool_name,
                    "eso.managed": "true"
                }
            )
            
            # Create isolated network for inter-worker communication
            # Container stays on default bridge for internet access
            network_config = await self.network_manager.create_network(worker_id)
            
            # Connect container to isolated network (in addition to default bridge)
            await self.network_manager.connect_container(
                container_id=container_id,
                network_config=network_config
            )
            
            # Create worker record
            worker = {
                "worker_id": worker_id,
                "container_id": container_id,
                "tool_name": tool_name,
                "tool_config": tool_config,
                "status": "available",
                "created_at": datetime.utcnow(),
                "last_health_check": datetime.utcnow(),
                "tasks_completed": 0,
                "total_execution_time": 0,
                "current_task": None,
                "network_config": network_config,
                "image": image
            }
            
            self.worker_pools[tool_name].append(worker)
            self.worker_status[worker_id] = worker
            
            # Create task queue
            self.task_queues[worker_id] = asyncio.Queue()
            
            logger.info(f"✅ Created worker {worker_id} for tool {tool_name}")
            return worker
            
        except Exception as e:
            logger.error(f"❌ Failed to create worker: {e}")
            raise
    
    async def _get_available_worker(self, tool_name: str) -> Optional[Dict]:
        """Get an available worker for the tool"""
        
        if tool_name not in self.worker_pools:
            return None
        
        # Find available worker
        available_workers = [
            w for w in self.worker_pools[tool_name]
            if w["status"] == "available"
        ]
        
        if not available_workers:
            return None
        
        # Select least loaded
        return min(available_workers, key=lambda w: w["tasks_completed"])
    
    async def execute(self, execution_params: Dict) -> Dict[str, Any]:
        """
        Execute a task on a worker - REAL DOCKER EXECUTION
        """
        tool_name = execution_params["tool_name"]
        logger.info(f"🐳 Executing {tool_name} in isolated worker")
        
        # Ensure we have a worker pool for this tool
        if tool_name not in self.worker_pools:
            logger.info(f"📦 Creating worker pool for {tool_name} on-demand")
            tool_config = {}
            if self.tool_registry:
                tool_config = await self.tool_registry.get_tool(tool_name) or {}
            await self.initialize_pool(tool_name, tool_config)
        
        # Get an available worker
        worker = await self._get_available_worker(tool_name)
        
        if not worker:
            # Scale up if needed
            current_count = len(self.worker_pools.get(tool_name, []))
            if current_count < self.max_workers_per_tool:
                logger.info(f"📈 Scaling up {tool_name} - creating new worker")
                tool_config = {}
                if self.tool_registry:
                    tool_config = await self.tool_registry.get_tool(tool_name) or {}
                worker = await self._create_worker(tool_name, tool_config)
            else:
                # Wait for a worker with timeout
                logger.info(f"⏳ Waiting for available {tool_name} worker...")
                for i in range(30):  # 30 second timeout
                    await asyncio.sleep(1)
                    worker = await self._get_available_worker(tool_name)
                    if worker:
                        logger.info(f"✅ Worker available after {i+1}s")
                        break
        
        if not worker:
            raise WorkerExecutionError(
                message=f"No workers available for {tool_name} after scaling",
                worker_id="none"
            )
        
        # Execute using the worker's container
        start_time = datetime.utcnow()
        worker["status"] = "busy"
        worker["current_task"] = execution_params.get("execution_id")
        
        try:
            # Prepare the command
            args = execution_params.get("args", [])
            command = execution_params.get("command", tool_name)
            
            # Build full command
            if args and len(args) > 0:
                cmd = [command] + args
            else:
                cmd = [command]
            
            # Log is handled by container_manager.execute_in_container
            
            # Execute in the container
            result = await self.container_manager.execute_in_container(
                container_id=worker["container_id"],
                command=cmd[0],
                args=cmd[1:] if len(cmd) > 1 else [],
                timeout=execution_params.get("timeout", 300),
                environment=execution_params.get("environment", {})
            )
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Update metrics
            worker["tasks_completed"] += 1
            worker["total_execution_time"] += duration
            
            # Add metadata
            result["worker_id"] = worker["worker_id"]
            result["tool_name"] = tool_name
            result["execution_method"] = "docker_worker"
            result["duration"] = duration
            result["success"] = result.get("exit_code", 1) == 0
            
            logger.info(f"✅ Task completed on worker {worker['worker_id']} in {duration:.2f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Worker execution failed: {e}")
            worker["status"] = "unhealthy"
            raise
        finally:
            if worker["status"] != "unhealthy":
                worker["status"] = "available"
                worker["current_task"] = None
    
    async def _health_check_loop(self):
        """Periodic health check of workers"""
        
        await asyncio.sleep(30)  # Initial delay
        
        while True:
            try:
                for tool_name, workers in self.worker_pools.items():
                    for worker in workers:
                        # Skip if permanently failed
                        if worker.get("permanent_failure", False):
                            continue
                        
                        # Check health
                        healthy = await self.container_manager.check_health(
                            worker["container_id"]
                        )
                        
                        if not healthy:
                            logger.warning(f"⚠️ Worker {worker['worker_id']} unhealthy")
                            worker["status"] = "unhealthy"
                            worker["last_health_check"] = datetime.utcnow()
                            
                            # Try to recover
                            await self._recover_worker(worker)
                        else:
                            worker["last_health_check"] = datetime.utcnow()
                            
                            # Reset if was unhealthy
                            if worker["status"] == "unhealthy" and not worker.get("current_task"):
                                worker["status"] = "available"
                
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"❌ Health check error: {e}")
                await asyncio.sleep(120)
    
    async def _recover_worker(self, worker: Dict):
        """Recover unhealthy worker"""
        
        try:
            logger.info(f"🔄 Attempting to recover worker {worker['worker_id']}")
            
            # Remove old container
            try:
                await self.container_manager.stop_container(worker["container_id"])
                await self.container_manager.remove_container(worker["container_id"])
            except Exception as e:
                logger.debug(f"Container cleanup error: {e}")
            
            # Clean up network
            await self.network_manager.cleanup_network(worker["network_config"])
            
            # Create new worker
            tool_config = worker.get("tool_config", {})
            new_worker = await self._create_worker(worker["tool_name"], tool_config)
            
            # Replace in pool
            idx = self.worker_pools[worker["tool_name"]].index(worker)
            self.worker_pools[worker["tool_name"]][idx] = new_worker
            
            logger.info(f"✅ Recovered worker {worker['worker_id']} -> {new_worker['worker_id']}")
            
        except Exception as e:
            logger.error(f"❌ Worker recovery failed: {e}")
    
    async def _auto_scaler_loop(self):
        """Auto-scale worker pools based on load"""
        
        while True:
            try:
                for tool_name, workers in self.worker_pools.items():
                    total_workers = len(workers)
                    if total_workers == 0:
                        continue
                    
                    busy_workers = len([w for w in workers if w["status"] == "busy"])
                    load_ratio = busy_workers / total_workers
                    
                    # Scale up
                    if load_ratio >= self.scale_up_threshold and total_workers < self.max_workers_per_tool:
                        scale_up_count = min(
                            self.max_workers_per_tool - total_workers,
                            1  # Add one at a time
                        )
                        
                        logger.info(f"📈 Scaling up {tool_name} by {scale_up_count} worker(s)")
                        
                        for _ in range(scale_up_count):
                            tool_config = {}
                            if self.tool_registry:
                                tool_config = await self.tool_registry.get_tool(tool_name) or {}
                            await self._create_worker(tool_name, tool_config)
                    
                    # Scale down
                    elif load_ratio <= self.scale_down_threshold and total_workers > self.min_workers_per_tool:
                        scale_down_count = min(
                            total_workers - self.min_workers_per_tool,
                            1  # Remove one at a time
                        )
                        
                        logger.info(f"📉 Scaling down {tool_name} by {scale_down_count} worker(s)")
                        
                        for _ in range(scale_down_count):
                            await self._remove_idle_worker(tool_name)
                
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"❌ Auto-scaler error: {e}")
                await asyncio.sleep(120)
    
    async def _remove_idle_worker(self, tool_name: str):
        """Remove an idle worker"""
        
        workers = self.worker_pools.get(tool_name, [])
        
        # Find idle worker (available with no tasks)
        idle_workers = [
            w for w in workers
            if w["status"] == "available" and w["tasks_completed"] > 0
        ]
        
        if idle_workers:
            # Remove oldest idle worker
            worker = min(idle_workers, key=lambda w: w["created_at"])
            
            try:
                await self.container_manager.stop_container(worker["container_id"])
                await self.container_manager.remove_container(worker["container_id"])
                await self.network_manager.cleanup_network(worker["network_config"])
                
                workers.remove(worker)
                self.worker_status.pop(worker["worker_id"], None)
                self.task_queues.pop(worker["worker_id"], None)
                
                logger.info(f"✅ Removed idle worker {worker['worker_id']}")
                
            except Exception as e:
                logger.error(f"❌ Failed to remove worker: {e}")
    
    async def get_tool_load(self, tool_name: str) -> float:
        """Get current load for tool (0-1)"""
        
        workers = self.worker_pools.get(tool_name, [])
        if not workers:
            return 0.0
        
        busy = len([w for w in workers if w["status"] == "busy"])
        return busy / len(workers)
    
    async def get_worker_stats(self, worker_id: str) -> Optional[Dict]:
        """Get worker statistics"""
        return self.worker_status.get(worker_id)
    
    async def get_pool_stats(self, tool_name: str) -> Dict[str, Any]:
        """Get worker pool statistics"""
        
        workers = self.worker_pools.get(tool_name, [])
        
        if not workers:
            return {
                "tool_name": tool_name,
                "total_workers": 0,
                "available_workers": 0,
                "busy_workers": 0,
                "unhealthy_workers": 0
            }
        
        return {
            "tool_name": tool_name,
            "total_workers": len(workers),
            "available_workers": len([w for w in workers if w["status"] == "available"]),
            "busy_workers": len([w for w in workers if w["status"] == "busy"]),
            "unhealthy_workers": len([w for w in workers if w["status"] == "unhealthy"]),
            "total_tasks_completed": sum(w["tasks_completed"] for w in workers),
            "avg_execution_time": (
                sum(w["total_execution_time"] for w in workers) / 
                sum(w["tasks_completed"] for w in workers)
                if sum(w["tasks_completed"] for w in workers) > 0 else 0
            )
        }
    
    async def cleanup_all(self):
        """Clean up all worker containers"""
        logger.info("🧹 Cleaning up all worker containers...")
        
        for tool_name, workers in list(self.worker_pools.items()):
            for worker in workers:
                try:
                    await self.container_manager.stop_container(worker["container_id"])
                    await self.container_manager.remove_container(worker["container_id"])
                    await self.network_manager.cleanup_network(worker["network_config"])
                    logger.info(f"✅ Cleaned up worker {worker['worker_id']}")
                except Exception as e:
                    logger.error(f"❌ Failed to cleanup worker {worker['worker_id']}: {e}")
        
        self.worker_pools.clear()
        self.worker_status.clear()
        self.task_queues.clear()
        
        logger.info("✅ All worker containers cleaned up")