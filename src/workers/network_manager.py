# src/workers/network_manager.py - Enhanced version

from typing import Dict, Optional, List
import uuid
import docker
from docker.errors import DockerException, NotFound, APIError
from datetime import datetime
import random
import re

from src.utils.logging import logger


class NetworkManager:
    """
    Network isolation for workers with improved conflict resolution
    
    Features:
    - Isolated networks per worker
    - Unique bridge names to avoid conflicts
    - Subnet management with collision detection
    - Network cleanup and recovery
    - Existing network detection and reuse
    """
    
    def __init__(self):
        self.docker_client = None
        self._connect_docker()
        
        self.networks: Dict[str, Dict] = {}
        self.used_subnets = set()
        self.used_bridge_names = set()
        
        # Load existing networks on startup
        self._load_existing_networks()
        
        logger.info("✅ Network Manager initialized")
    
    def _connect_docker(self):
        """Connect to Docker daemon"""
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
    
    def _load_existing_networks(self):
        """Load existing ESO networks to avoid conflicts"""
        try:
            networks = self.docker_client.networks.list(
                filters={"label": "eso.managed=true"}
            )
            
            for network in networks:
                # Extract bridge name from labels
                bridge_name = network.attrs.get("Labels", {}).get("eso.bridge")
                if bridge_name:
                    self.used_bridge_names.add(bridge_name)
                
                # Extract subnet from IPAM
                ipam = network.attrs.get("IPAM", {})
                configs = ipam.get("Config", [])
                for config in configs:
                    subnet = config.get("Subnet")
                    if subnet:
                        self.used_subnets.add(subnet)
                        
            logger.debug(f"Loaded {len(networks)} existing ESO networks")
        except Exception as e:
            logger.debug(f"Could not load existing networks: {e}")
    
    def _generate_unique_bridge_name(self, worker_id: str) -> str:
        """Generate a unique bridge name"""
        base = f"eso-{worker_id[:8]}"
        bridge_name = base
        
        # Ensure uniqueness
        counter = 0
        while bridge_name in self.used_bridge_names:
            counter += 1
            bridge_name = f"{base}-{counter}"
            if counter > 100:  # Safety limit
                bridge_name = f"{base}-{random.randint(1000, 9999)}"
                break
        
        self.used_bridge_names.add(bridge_name)
        return bridge_name
    
    def _generate_unique_subnet(self) -> str:
        """Generate a unique subnet with collision avoidance"""
        # Use 10.x.x.x/24 range to avoid overlaps
        max_attempts = 1000
        attempt = 0
        
        while attempt < max_attempts:
            # Generate random /24 subnet
            second_octet = random.randint(0, 255)
            third_octet = random.randint(0, 255)
            subnet = f"10.{second_octet}.{third_octet}.0/24"
            
            # Check if subnet is available
            if subnet not in self.used_subnets and not self._subnet_in_use(subnet):
                self.used_subnets.add(subnet)
                return subnet
            
            attempt += 1
        
        # If we can't find a unique subnet, use timestamp-based
        timestamp = int(datetime.utcnow().timestamp()) % 1000
        subnet = f"10.{timestamp//256}.{timestamp%256}.0/24"
        logger.warning(f"Using fallback subnet: {subnet}")
        return subnet
    
    def _subnet_in_use(self, subnet: str) -> bool:
        """Check if subnet is already in use by Docker"""
        try:
            networks = self.docker_client.networks.list()
            for network in networks:
                ipam = network.attrs.get("IPAM", {})
                configs = ipam.get("Config", [])
                for config in configs:
                    if config.get("Subnet") == subnet:
                        return True
            return False
        except:
            return False
    
    async def create_network(self, worker_id: str) -> Dict:
        """Create isolated network for worker"""
        
        network_name = f"eso-net-{worker_id}"
        bridge_name = self._generate_unique_bridge_name(worker_id)
        subnet = self._generate_unique_subnet()
        gateway = subnet.replace('0/24', '1')
        
        try:
            # Check if network already exists
            try:
                existing = self.docker_client.networks.get(network_name)
                if existing:
                    logger.debug(f"Network {network_name} already exists")
                    
                    # Update used bridge name if available
                    existing_bridge = existing.attrs.get("Labels", {}).get("eso.bridge")
                    if existing_bridge:
                        self.used_bridge_names.add(existing_bridge)
                    
                    # Update used subnet
                    ipam = existing.attrs.get("IPAM", {})
                    configs = ipam.get("Config", [])
                    for config in configs:
                        existing_subnet = config.get("Subnet")
                        if existing_subnet:
                            self.used_subnets.add(existing_subnet)
                    
                    network_config = {
                        "network_id": existing.id,
                        "network_name": network_name,
                        "worker_id": worker_id,
                        "subnet": existing_subnet or subnet,
                        "bridge_name": existing_bridge or bridge_name,
                        "created_at": datetime.utcnow().isoformat()
                    }
                    self.networks[worker_id] = network_config
                    return network_config
            except NotFound:
                pass
            
            # Create network with isolation
            network = self.docker_client.networks.create(
                name=network_name,
                driver="bridge",
                ipam=docker.types.IPAMConfig(
                    pool_configs=[
                        docker.types.IPAMPool(
                            subnet=subnet,
                            gateway=gateway
                        )
                    ]
                ),
                options={
                    "com.docker.network.bridge.name": bridge_name,
                    "com.docker.network.bridge.enable_icc": "true",
                    "com.docker.network.bridge.enable_ip_masquerade": "true"  # Tools need internet to reach targets
                },
                labels={
                    "eso.worker": worker_id,
                    "eso.managed": "true",
                    "eso.bridge": bridge_name
                }
            )
            
            network_config = {
                "network_id": network.id,
                "network_name": network_name,
                "worker_id": worker_id,
                "subnet": subnet,
                "bridge_name": bridge_name,
                "created_at": datetime.utcnow().isoformat()
            }
            
            self.networks[worker_id] = network_config
            
            logger.info(f"✅ Created network {network_name} for worker {worker_id} (bridge: {bridge_name}, subnet: {subnet})")
            return network_config
            
        except APIError as e:
            error_msg = str(e)
            
            # Handle specific Docker errors
            if "network with name" in error_msg and "already exists" in error_msg:
                # Network already exists, try to get it
                try:
                    network = self.docker_client.networks.get(network_name)
                    network_config = {
                        "network_id": network.id,
                        "network_name": network_name,
                        "worker_id": worker_id,
                        "subnet": subnet,
                        "created_at": datetime.utcnow().isoformat()
                    }
                    self.networks[worker_id] = network_config
                    logger.info(f"✅ Using existing network {network_name}")
                    return network_config
                except:
                    pass
            
            elif "networks have same bridge name" in error_msg:
                # Bridge name conflict - retry with new bridge name
                logger.warning(f"Bridge name conflict, retrying with new name...")
                # Clear the conflicting bridge name from used set
                self.used_bridge_names.discard(bridge_name)
                # Retry recursively (with limit)
                return await self.create_network(worker_id)
            
            elif "Pool overlaps with other one" in error_msg:
                # Subnet conflict - retry with new subnet
                logger.warning(f"Subnet conflict, retrying with new subnet...")
                # Clear the conflicting subnet from used set
                if subnet in self.used_subnets:
                    self.used_subnets.remove(subnet)
                # Retry recursively (with limit)
                return await self.create_network(worker_id)
            
            logger.error(f"❌ Failed to create network: {e}")
            # Return a config without network - worker can still function
            return {
                "network_name": network_name,
                "worker_id": worker_id,
                "error": str(e),
                "created_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"❌ Failed to create network: {e}")
            return {
                "network_name": network_name,
                "worker_id": worker_id,
                "error": str(e),
                "created_at": datetime.utcnow().isoformat()
            }
    
    async def connect_container(
        self,
        container_id: str,
        network_config: Dict
    ):
        """Connect container to network"""
        
        # If network creation failed, skip connection
        if "error" in network_config:
            logger.warning(f"Skipping network connection for {container_id[:12]} due to previous error")
            return
        
        try:
            network = self.docker_client.networks.get(network_config["network_name"])
            network.connect(container_id)
            
            logger.info(f"✅ Connected container {container_id[:12]} to network {network_config['network_name']}")
            
        except Exception as e:
            logger.error(f"❌ Failed to connect container to network: {e}")
    
    async def disconnect_container(
        self,
        container_id: str,
        network_config: Dict
    ):
        """Disconnect container from network"""
        
        if "error" in network_config:
            return
        
        try:
            network = self.docker_client.networks.get(network_config["network_name"])
            network.disconnect(container_id, force=True)
            
            logger.info(f"✅ Disconnected container {container_id[:12]} from network")
            
        except Exception as e:
            logger.error(f"❌ Failed to disconnect container: {e}")
    
    async def cleanup_network(self, network_config: Dict):
        """Remove network"""
        
        if "error" in network_config:
            return
        
        try:
            network = self.docker_client.networks.get(network_config["network_name"])
            
            # Get bridge name from labels
            bridge_name = network.attrs.get("Labels", {}).get("eso.bridge")
            if bridge_name:
                self.used_bridge_names.discard(bridge_name)
            
            # Get subnet from config
            subnet = network_config.get("subnet")
            if subnet:
                self.used_subnets.discard(subnet)
            
            # Disconnect any remaining containers
            for container in network.containers:
                try:
                    network.disconnect(container['Id'], force=True)
                except:
                    pass
            
            network.remove()
            
            self.networks.pop(network_config["worker_id"], None)
            
            logger.info(f"✅ Removed network {network_config['network_name']}")
            
        except NotFound:
            logger.debug(f"Network {network_config['network_name']} not found")
        except Exception as e:
            logger.error(f"❌ Failed to remove network: {e}")
    
    async def cleanup_all_networks(self):
        """Clean up all ESO networks"""
        logger.info("🧹 Cleaning up all ESO networks...")
        
        try:
            networks = self.docker_client.networks.list(
                filters={"label": "eso.managed=true"}
            )
            
            for network in networks:
                try:
                    # Disconnect all containers
                    for container in network.containers:
                        try:
                            network.disconnect(container['Id'], force=True)
                        except:
                            pass
                    
                    network.remove()
                    logger.info(f"✅ Removed network: {network.name}")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to remove network {network.name}: {e}")
            
            self.networks.clear()
            self.used_bridge_names.clear()
            self.used_subnets.clear()
            
        except Exception as e:
            logger.error(f"❌ Failed to clean up networks: {e}")
    
    async def get_network_stats(self, worker_id: str) -> Dict:
        """Get network statistics"""
        
        network_config = self.networks.get(worker_id, {})
        
        if "error" in network_config:
            return {
                "worker_id": worker_id,
                "status": "error",
                "error": network_config["error"]
            }
        
        return {
            "worker_id": worker_id,
            "network_name": network_config.get("network_name"),
            "subnet": network_config.get("subnet"),
            "status": "connected" if network_config else "disconnected"
        }