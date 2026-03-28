# src/workers/container_manager.py
from typing import Dict, List, Optional, Any
import asyncio
import docker
from docker.errors import DockerException, NotFound, APIError
from datetime import datetime
import tempfile
import os
import tarfile
import io

from src.core.config import get_settings
from src.utils.logging import logger

settings = get_settings()


class ContainerManager:
    """
    Enterprise Container Manager
    
    Manages:
    - Docker container lifecycle
    - Resource limits (CPU, memory, disk)
    - Command execution in containers
    - File transfer
    - Health checking
    """
    
    def __init__(self):
        self.docker_client = None
        self._connect_docker()
        
        # Track active containers
        self.active_containers: Dict[str, Dict] = {}
        
        logger.info("✅ Container Manager initialized")
    
    def _connect_docker(self):
        """Connect to Docker daemon"""
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            logger.info("✅ Connected to Docker daemon")
        except DockerException as e:
            logger.error(f"❌ Failed to connect to Docker: {e}")
            raise
    
    async def create_container(
        self,
        image: str,
        name: str,
        command: Optional[List[str]] = None,
        resource_limits: Optional[Dict] = None,
        environment: Optional[Dict] = None,
        volumes: Optional[Dict] = None,
        network: Optional[str] = None,
        labels: Optional[Dict] = None,
        privileged: bool = False
    ) -> str:
        """Create a new container"""
        
        try:
            # Ensure image exists
            await self._ensure_image(image)
            
            # Prepare resource limits
            resource_config = self._prepare_resource_limits(resource_limits or {})
            
            # Default to long-running command if none provided
            if command is None:
                command = ["sleep", "infinity"]
            
            logger.info(f"📦 Creating container {name} with image {image}")
            
            # Create container
            container = self.docker_client.containers.create(
                image=image,
                command=command,
                name=name,
                entrypoint=[],  # Override image entrypoint so we can use sleep/exec
                environment=environment,
                volumes=volumes,
                network=network,
                labels=labels,
                detach=True,
                stdin_open=True,
                tty=True,
                privileged=privileged,
                **resource_config
            )
            # Start the container
            container.start()
            
            # Wait a moment for container to be ready
            await asyncio.sleep(2)
            
            # Track container
            self.active_containers[container.id] = {
                "id": container.id,
                "name": name,
                "image": image,
                "created_at": datetime.utcnow(),
                "status": "running",
                "container": container
            }
            
            logger.info(f"✅ Created and started container: {name} ({container.id[:12]})")
            return container.id
            
        except Exception as e:
            logger.error(f"❌ Failed to create container: {e}")
            raise

    async def execute_in_container(
        self,
        container_id: str,
        command: str,
        args: List[str],
        timeout: int = 300,
        environment: Optional[Dict] = None,
        workdir: str = "/"
    ) -> Dict[str, Any]:
        """Execute command in a running container - FIXED OUTPUT CAPTURE"""
        
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Ensure container is running
            if container.status != "running":
                logger.warning(f"⚠️ Container {container_id[:12]} not running, starting it")
                container.start()
                await asyncio.sleep(2)
            
            # Prepare full command
            full_cmd = [command] + args
            cmd_str = ' '.join(full_cmd)
            
            logger.info(f"🔧 Executing in container {container_id[:12]}: {cmd_str}")
            
            # Execute with timeout
            start_time = datetime.utcnow()
            
            try:
                # Run command and capture output properly
                exec_result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: container.exec_run(
                            cmd=full_cmd,
                            environment=environment,
                            demux=True,  # Separate stdout/stderr
                            workdir=workdir,
                            user="root",
                            stream=False  # Capture all output at once
                        )
                    ),
                    timeout=timeout
                )
                
            except asyncio.TimeoutError:
                logger.error(f"⏱️ Command timed out after {timeout}s")
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout} seconds",
                    "duration": timeout,
                    "success": False,
                    "command": cmd_str,
                    "timed_out": True
                }
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Parse result - demux=True returns (stdout, stderr) tuple
            exit_code = exec_result.exit_code
            output = exec_result.output
            
            # Handle output properly
            stdout = ""
            stderr = ""
            
            if output:
                if isinstance(output, tuple) and len(output) == 2:
                    # stdout is first element, stderr is second
                    if output[0]:
                        stdout = output[0].decode('utf-8', errors='ignore')
                    if output[1]:
                        stderr = output[1].decode('utf-8', errors='ignore')
                elif isinstance(output, bytes):
                    stdout = output.decode('utf-8', errors='ignore')
                elif isinstance(output, str):
                    stdout = output
            
            # Log output for debugging
            logger.info(f"Command exit code: {exit_code}")
            logger.info(f"Stdout length: {len(stdout)} chars")
            logger.info(f"Stderr length: {len(stderr)} chars")
            
            if stdout:
                preview = stdout[:500] + "..." if len(stdout) > 500 else stdout
                logger.debug(f"📤 stdout preview: {preview}")
            
            if stderr:
                preview = stderr[:500] + "..." if len(stderr) > 500 else stderr
                logger.debug(f"📤 stderr preview: {preview}")
            
            return {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "duration": duration,
                "success": exit_code == 0,
                "command": cmd_str,
                "timed_out": False
            }
            
        except Exception as e:
            logger.error(f"❌ Container execution failed: {e}")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration": 0,
                "success": False,
                "command": f"{command} {' '.join(args)}",
                "error": str(e)
            }
    
    async def stop_container(self, container_id: str, timeout: int = 10):
        """Stop a container"""
        
        try:
            container = self.docker_client.containers.get(container_id)
            container.stop(timeout=timeout)
            
            if container_id in self.active_containers:
                self.active_containers[container_id]["status"] = "stopped"
            
            logger.info(f"✅ Stopped container: {container_id[:12]}")
            
        except NotFound:
            logger.debug(f"Container {container_id[:12]} not found")
        except Exception as e:
            logger.error(f"❌ Failed to stop container: {e}")
    
    async def remove_container(self, container_id: str, force: bool = True):
        """Remove a container"""
        
        try:
            container = self.docker_client.containers.get(container_id)
            container.remove(force=force)
            
            self.active_containers.pop(container_id, None)
            
            logger.info(f"✅ Removed container: {container_id[:12]}")
            
        except NotFound:
            logger.debug(f"Container {container_id[:12]} not found")
        except Exception as e:
            logger.error(f"❌ Failed to remove container: {e}")
    
    async def check_health(self, container_id: str) -> bool:
        """Check container health"""
        
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Check if container exists and is running
            if container.status != "running":
                return False
            
            # Try to execute a simple command to verify responsiveness
            try:
                exec_result = container.exec_run(
                    cmd=["echo", "health"],
                    demux=True
                )
                return exec_result.exit_code == 0
            except:
                # If exec fails but container is running, still consider healthy
                return True
            
        except NotFound:
            return False
        except Exception as e:
            logger.debug(f"Health check error for {container_id[:12]}: {e}")
            return False
    
    async def copy_to_container(
        self,
        container_id: str,
        source_path: str,
        dest_path: str
    ):
        """Copy file to container"""
        
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Create tar archive
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tar.add(source_path, arcname=os.path.basename(source_path))
            
            tar_stream.seek(0)
            
            # Copy to container
            container.put_archive(
                path=dest_path,
                data=tar_stream
            )
            
            logger.info(f"✅ Copied {source_path} to container {container_id[:12]}:{dest_path}")
            
        except Exception as e:
            logger.error(f"❌ Failed to copy to container: {e}")
    
    async def copy_from_container(
        self,
        container_id: str,
        source_path: str,
        dest_path: str
    ):
        """Copy file from container"""
        
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Get archive from container
            data, stat = container.get_archive(source_path)
            
            # Extract to destination
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                for chunk in data:
                    tmp_file.write(chunk)
                tmp_path = tmp_file.name
            
            # Extract tar
            with tarfile.open(tmp_path, 'r') as tar:
                tar.extractall(path=dest_path)
            
            # Cleanup
            os.unlink(tmp_path)
            
            logger.info(f"✅ Copied from container {container_id[:12]}:{source_path} to {dest_path}")
            
        except Exception as e:
            logger.error(f"❌ Failed to copy from container: {e}")
    
    async def get_container_logs(
        self,
        container_id: str,
        tail: int = 100
    ) -> str:
        """Get container logs"""
        
        try:
            container = self.docker_client.containers.get(container_id)
            logs = container.logs(tail=tail).decode('utf-8', errors='ignore')
            return logs
            
        except Exception as e:
            logger.error(f"❌ Failed to get container logs: {e}")
            return ""
    
    async def _ensure_image(self, image: str):
        """Ensure Docker image exists locally"""
        
        try:
            self.docker_client.images.get(image)
            logger.debug(f"Image {image} exists locally")
        except docker.errors.ImageNotFound:
            logger.info(f"📦 Pulling image: {image}")
            
            # Pull image
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.docker_client.images.pull(image)
            )
            logger.info(f"✅ Image {image} pulled successfully")
    
    def _prepare_resource_limits(self, limits: Dict) -> Dict:
        """Prepare resource limits for container creation"""
        
        resource_config = {}
        
        # CPU limits
        if "cpu" in limits:
            cpu_count = float(limits["cpu"])
            resource_config["cpu_period"] = 100000
            resource_config["cpu_quota"] = int(cpu_count * 100000)
            resource_config["cpu_shares"] = int(cpu_count * 1024)
        
        # Memory limits
        if "memory" in limits:
            memory_bytes = self._parse_memory_string(limits["memory"])
            resource_config["mem_limit"] = memory_bytes
            resource_config["mem_reservation"] = int(memory_bytes * 0.8)
            resource_config["mem_swappiness"] = 0
        
        return resource_config
    
    def _parse_memory_string(self, memory_str: str) -> int:
        """Parse memory string to bytes"""
        
        units = {
            "Ki": 1024,
            "Mi": 1024**2,
            "Gi": 1024**3,
            "Ti": 1024**4,
            "KB": 1000,
            "MB": 1000**2,
            "GB": 1000**3
        }
        
        for unit, multiplier in units.items():
            if memory_str.endswith(unit):
                numeric = float(memory_str[:-len(unit)])
                return int(numeric * multiplier)
        
        return int(memory_str)
    
    async def cleanup_all(self):
        """Clean up all containers"""
        logger.info("🧹 Cleaning up all containers...")
        
        for container_id in list(self.active_containers.keys()):
            try:
                await self.stop_container(container_id)
                await self.remove_container(container_id)
            except Exception as e:
                logger.error(f"❌ Failed to cleanup container {container_id[:12]}: {e}")
        
        logger.info("✅ All containers cleaned up")