# src/tools/tool_discovery.py
import os
import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
import docker
from docker.errors import DockerException, NotFound, APIError

from src.utils.logging import logger


class ToolDiscovery:
    """
    Dynamically discover tools from multiple sources:
    - Docker images with labels
    - YAML configuration files
    - Directory structure
    - Default tools
    """
    
    def __init__(self, tools_config_dir: str = "config/tools"):
        self.docker_client = None
        self._connect_docker()
        self.tools_config_dir = Path(tools_config_dir)
        self.tools_config_dir.mkdir(parents=True, exist_ok=True)
        
    def _connect_docker(self):
        """Connect to Docker daemon if available"""
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            logger.info("✅ Connected to Docker daemon for tool discovery")
        except DockerException as e:
            logger.warning(f"⚠️ Docker not available for tool discovery: {e}")
            self.docker_client = None
    
    async def discover_tools(self) -> List[Dict[str, Any]]:
        """Discover available tools from multiple sources
        
        Priority order (higher wins):
        1. YAML config files (hand-curated, most reliable)
        2. Docker image labels (auto-discovered)
        3. Built-in defaults (fallback)
        """
        tools = []
        discovered_names = set()
        
        # Method 1 (highest priority): Load from config files
        config_tools = await self._discover_from_config()
        for tool in config_tools:
            if tool["name"] not in discovered_names:
                tools.append(tool)
                discovered_names.add(tool["name"])
                logger.info(f"⚙️ Loaded tool from config: {tool['name']} (capabilities: {tool.get('capabilities', [])})")
        
        # Method 2: Scan directories for tool definitions
        dir_tools = await self._discover_from_directories()
        for tool in dir_tools:
            if tool["name"] not in discovered_names:
                tools.append(tool)
                discovered_names.add(tool["name"])
                logger.debug(f"📁 Discovered tool from directory: {tool['name']}")
        
        # Method 3: Scan Docker images with labels (fills gaps)
        if self.docker_client:
            docker_tools = await self._discover_from_docker()
            for tool in docker_tools:
                if tool["name"] not in discovered_names:
                    tools.append(tool)
                    discovered_names.add(tool["name"])
                    logger.debug(f"🔍 Discovered tool from Docker: {tool['name']}")
        
        # Method 4: Built-in defaults (only for tools not yet found)
        if not tools:
            tools = self._get_default_tools()
            logger.info("📦 No tools found, using built-in defaults")
        else:
            # Fill in any missing tools from defaults
            default_tools = self._get_default_tools()
            for default_tool in default_tools:
                if default_tool["name"] not in discovered_names:
                    tools.append(default_tool)
                    discovered_names.add(default_tool["name"])
                    logger.debug(f"📦 Added default tool: {default_tool['name']}")
        
        logger.info(f"✅ Discovered {len(tools)} tools")
        return tools
    
    async def _discover_from_docker(self) -> List[Dict]:
        """Discover tools from Docker images with eso.tool labels"""
        tools = []
        
        try:
            images = self.docker_client.images.list()
            
            for image in images:
                labels = image.labels or {}
                
                if labels.get("eso.tool") == "true":
                    # Parse capabilities from comma-separated string
                    capabilities_str = labels.get("eso.tool.capabilities", "")
                    capabilities = [c.strip() for c in capabilities_str.split(",") if c.strip()]
                    
                    # Parse resource requirements
                    resource_req = {
                        "cpu": labels.get("eso.tool.cpu", "0.5"),
                        "memory": labels.get("eso.tool.memory", "512Mi"),
                        "disk": labels.get("eso.tool.disk", "100Mi")
                    }
                    
                    tool = {
                        "name": labels.get("eso.tool.name", image.tags[0].split(":")[0] if image.tags else "unknown"),
                        "version": labels.get("eso.tool.version", "latest"),
                        "capabilities": capabilities,
                        "image": image.tags[0] if image.tags else f"{labels.get('eso.tool.name')}:latest",
                        "description": labels.get("eso.tool.description", ""),
                        "command": labels.get("eso.tool.command", ""),
                        "resource_requirements": resource_req,
                        "default_timeout": int(labels.get("eso.tool.timeout", "300")),
                        "cacheable": labels.get("eso.tool.cacheable", "true").lower() == "true",
                        "discovery_source": "docker_label"
                    }
                    
                    # Add param mapping if available
                    param_mapping_str = labels.get("eso.tool.param_mapping", "")
                    if param_mapping_str:
                        try:
                            tool["param_mapping"] = json.loads(param_mapping_str)
                        except:
                            pass
                    
                    tools.append(tool)
                    
        except Exception as e:
            logger.error(f"Error discovering tools from Docker: {e}")
        
        return tools
    
    async def _discover_from_directories(self) -> List[Dict]:
        """Discover tools from directory structure"""
        tools = []
        
        # Scan for tool.yaml files in subdirectories
        for tool_dir in self.tools_config_dir.iterdir():
            if tool_dir.is_dir():
                # Check for tool.yaml or tool.yml
                yaml_file = tool_dir / "tool.yaml"
                if not yaml_file.exists():
                    yaml_file = tool_dir / "tool.yml"
                
                if yaml_file.exists():
                    try:
                        with open(yaml_file, 'r') as f:
                            tool_config = yaml.safe_load(f)
                            
                        # Add source info
                        tool_config["discovery_source"] = str(yaml_file)
                        tool_config["config_path"] = yaml_file
                        
                        tools.append(tool_config)
                        
                    except Exception as e:
                        logger.error(f"Error loading {yaml_file}: {e}")
        
        return tools
    
    async def _discover_from_config(self) -> List[Dict]:
        """Discover tools from YAML/JSON config files in root directory"""
        tools = []
        
        # Look for .yaml, .yml, .json files
        for config_file in self.tools_config_dir.glob("*.*"):
            if config_file.suffix in ['.yaml', '.yml', '.json']:
                try:
                    with open(config_file, 'r') as f:
                        if config_file.suffix in ['.yaml', '.yml']:
                            tool_config = yaml.safe_load(f)
                        else:
                            tool_config = json.load(f)
                    
                    # Handle both single tool and list of tools
                    if isinstance(tool_config, list):
                        for tool in tool_config:
                            tool["discovery_source"] = str(config_file)
                            tool["config_path"] = config_file
                            tools.append(tool)
                    else:
                        tool_config["discovery_source"] = str(config_file)
                        tool_config["config_path"] = config_file
                        tools.append(tool_config)
                    
                except Exception as e:
                    logger.error(f"Error loading tool config {config_file}: {e}")
        
        return tools
    
    def _get_default_tools(self) -> List[Dict]:
        """Provide default tools if no discovery works"""
        return [
            {
                "name": "nmap",
                "version": "7.94",
                "capabilities": ["port_scan", "service_detection", "os_detection"],
                "image": "instrumentisto/nmap:latest",
                "command": "nmap",
                "description": "Network discovery and port scanning",
                "resource_requirements": {
                    "cpu": "0.5",
                    "memory": "512Mi",
                    "disk": "100Mi"
                },
                "default_timeout": 600,
                "cacheable": True,
                "param_mapping": {
                    "ports": "-p",
                    "scan_type": "-s",
                    "timing": "-T",
                    "output_format": "-oX"
                },
                "discovery_source": "default"
            },
            {
                "name": "nuclei",
                "version": "3.1.0",
                "capabilities": ["vuln_scan", "template_based"],
                "image": "projectdiscovery/nuclei:latest",
                "command": "nuclei",
                "description": "Vulnerability scanner",
                "resource_requirements": {
                    "cpu": "1.0",
                    "memory": "1Gi",
                    "disk": "500Mi"
                },
                "default_timeout": 1200,
                "cacheable": True,
                "param_mapping": {
                    "templates": "-t",
                    "severity": "-severity",
                    "rate_limit": "-rl"
                },
                "discovery_source": "default"
            },
            {
                "name": "gobuster",
                "version": "3.6",
                "capabilities": ["directory_bruteforce", "dns_enumeration"],
                "image": "gobuster:latest",
                "command": "gobuster",
                "description": "Directory/file brute-forcing",
                "resource_requirements": {
                    "cpu": "0.5",
                    "memory": "512Mi",
                    "disk": "200Mi"
                },
                "default_timeout": 900,
                "cacheable": True,
                "param_mapping": {
                    "mode": None,
                    "wordlist": "-w",
                    "threads": "-t",
                    "extensions": "-x"
                },
                "discovery_source": "default"
            }
        ]