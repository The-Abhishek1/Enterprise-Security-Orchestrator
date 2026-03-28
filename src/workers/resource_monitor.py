# src/workers/resource_monitor.py
from typing import Dict, Optional
import psutil
import docker
from datetime import datetime

from src.utils.logging import logger


class ResourceMonitor:
    """
    Monitor resource usage of workers and host
    
    Features:
    - CPU usage tracking
    - Memory usage tracking
    - Disk I/O monitoring
    - Network I/O monitoring
    - Container-level metrics
    """
    
    def __init__(self):
        self.docker_client = None
        self._connect_docker()
        
        self.stats_cache: Dict[str, Dict] = {}
        
        logger.info("✅ Resource Monitor initialized")
    
    def _connect_docker(self):
        """Connect to Docker daemon"""
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
    
    async def get_host_stats(self) -> Dict:
        """Get host system statistics"""
        
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "memory_available": psutil.virtual_memory().available,
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def get_container_stats(self, container_id: str) -> Optional[Dict]:
        """Get container resource statistics"""
        
        if not self.docker_client:
            return None
        
        try:
            container = self.docker_client.containers.get(container_id)
            stats = container.stats(stream=False)
            
            # Calculate CPU usage
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                        stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']
            
            cpu_percent = 0.0
            if system_delta > 0 and cpu_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * \
                             len(stats['cpu_stats']['cpu_usage'].get('percpu_usage', [1])) * 100.0
            
            # Memory usage
            memory_stats = stats['memory_stats']
            memory_usage = memory_stats.get('usage', 0)
            memory_limit = memory_stats.get('limit', 0)
            memory_percent = (memory_usage / memory_limit * 100) if memory_limit > 0 else 0
            
            # Network stats
            networks = stats.get('networks', {})
            network_rx = sum(net.get('rx_bytes', 0) for net in networks.values())
            network_tx = sum(net.get('tx_bytes', 0) for net in networks.values())
            
            result = {
                "container_id": container_id[:12],
                "cpu_percent": round(cpu_percent, 2),
                "memory_usage": memory_usage,
                "memory_limit": memory_limit,
                "memory_percent": round(memory_percent, 2),
                "network_rx_bytes": network_rx,
                "network_tx_bytes": network_tx,
                "block_read": stats.get('blkio_stats', {}).get('io_service_bytes_recursive', [{}])[0].get('value', 0),
                "block_write": stats.get('blkio_stats', {}).get('io_service_bytes_recursive', [{}])[-1].get('value', 0),
                "pid": stats.get('pids_stats', {}).get('current', 0),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Cache stats
            self.stats_cache[container_id] = result
            
            return result
            
        except Exception as e:
            logger.debug(f"Failed to get stats for container {container_id[:12]}: {e}")
            return self.stats_cache.get(container_id)
    
    async def get_worker_stats(self, worker_id: str, container_id: str) -> Dict:
        """Get worker statistics"""
        
        container_stats = await self.get_container_stats(container_id)
        
        return {
            "worker_id": worker_id,
            "container_id": container_id[:12],
            "container_stats": container_stats,
            "host_stats": await self.get_host_stats()
        }
    
    async def check_resource_limits(
        self,
        container_id: str,
        cpu_limit: float,
        memory_limit: int
    ) -> Dict:
        """Check if container is within resource limits"""
        
        stats = await self.get_container_stats(container_id)
        if not stats:
            return {"within_limits": True, "reason": "No stats available"}
        
        issues = []
        
        if stats["cpu_percent"] > cpu_limit * 100:
            issues.append(f"CPU usage ({stats['cpu_percent']}%) exceeds limit ({cpu_limit*100}%)")
        
        if stats["memory_usage"] > memory_limit:
            issues.append(f"Memory usage exceeds limit")
        
        return {
            "within_limits": len(issues) == 0,
            "issues": issues,
            "current": {
                "cpu_percent": stats["cpu_percent"],
                "memory_usage": stats["memory_usage"]
            },
            "limits": {
                "cpu_limit": cpu_limit,
                "memory_limit": memory_limit
            }
        }