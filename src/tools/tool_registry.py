# src/tools/tool_registry.py
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import yaml
from pathlib import Path

from src.utils.logging import logger


class ToolRegistry:
    """
    Enterprise Tool Registry
    
    Manages:
    - Tool definitions and metadata
    - Tool versions
    - Tool capabilities
    - Dynamic discovery
    - Tool health status
    """
    
    def __init__(self):
        self.tools: Dict[str, Dict] = {}
        self.capability_index: Dict[str, List[str]] = {}
        self.version_index: Dict[str, Dict[str, List[str]]] = {}
        self.tool_configs: Dict[str, Path] = {}
        
        logger.info("✅ Tool Registry initialized")
    
    def register_tool(self, tool_config: Dict, config_path: Optional[Path] = None) -> None:
        """Register a tool with the registry"""
        
        tool_name = tool_config["name"]
        
        # Store tool
        self.tools[tool_name] = tool_config
        
        if config_path:
            self.tool_configs[tool_name] = config_path
        
        # Index by capability
        for capability in tool_config.get("capabilities", []):
            if capability not in self.capability_index:
                self.capability_index[capability] = []
            if tool_name not in self.capability_index[capability]:
                self.capability_index[capability].append(tool_name)
        
        # Index by version
        for version in tool_config.get("versions", [tool_config.get("version", "latest")]):
            if version not in self.version_index:
                self.version_index[version] = {}
            
            version_tools = self.version_index[version]
            for capability in tool_config.get("capabilities", []):
                if capability not in version_tools:
                    version_tools[capability] = []
                if tool_name not in version_tools[capability]:
                    version_tools[capability].append(tool_name)
        
        logger.debug(f"📦 Registered tool: {tool_name} v{tool_config.get('version', 'latest')}")
    
    async def find_tools_by_capability(
        self,
        capability: str,
        tenant_id: Optional[str] = None,
        version: Optional[str] = None
    ) -> List[Dict]:
        """Find tools that provide a specific capability"""
        
        if version and version in self.version_index:
            # Search by version first
            version_capabilities = self.version_index[version]
            tool_names = version_capabilities.get(capability, [])
        else:
            # Search by capability
            tool_names = self.capability_index.get(capability, [])
        
        tools = []
        for tool_name in tool_names:
            tool = self.tools.get(tool_name)
            if tool:
                # Apply tenant-specific filtering
                if tenant_id:
                    if not await self._tenant_has_access(tenant_id, tool_name):
                        continue
                
                tools.append(tool.copy())
        
        return tools
    
    async def get_tool(self, tool_name: str, version: Optional[str] = None) -> Optional[Dict]:
        """Get tool by name and optional version"""
        
        tool = self.tools.get(tool_name)
        if not tool:
            return None
        
        if version and version != tool.get("default_version", tool.get("version")):
            # Create version-specific copy
            tool = tool.copy()
            tool["version"] = version
            
            # Adjust image tag for version
            if "image" in tool:
                base_image = tool["image"].split(":")[0]
                tool["image"] = f"{base_image}:{version}"
        
        return tool.copy()
    
    async def _tenant_has_access(self, tenant_id: str, tool_name: str) -> bool:
        """Check if tenant has access to tool"""
        # In production, check against tenant's subscription/plan
        return True
    
    async def get_all_tools(self) -> List[Dict]:
        """Get all registered tools"""
        return list(self.tools.values())
    
    async def get_tool_versions(self, tool_name: str) -> List[str]:
        """Get all available versions of a tool"""
        
        tool = self.tools.get(tool_name)
        if tool:
            return tool.get("versions", [tool.get("version", "latest")])
        
        return []
    
    async def reload_tool(self, tool_name: str) -> bool:
        """Reload tool configuration from file"""
        
        if tool_name not in self.tool_configs:
            return False
        
        config_path = self.tool_configs[tool_name]
        try:
            with open(config_path, 'r') as f:
                if config_path.suffix == '.yaml' or config_path.suffix == '.yml':
                    tool_config = yaml.safe_load(f)
                else:
                    tool_config = json.load(f)
            
            # Update registry
            self.tools[tool_name] = tool_config
            logger.info(f"🔄 Reloaded tool: {tool_name}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to reload tool {tool_name}: {e}")
            return False
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics"""
        return {
            "total_tools": len(self.tools),
            "total_capabilities": len(self.capability_index),
            "tools_by_capability": {
                cap: len(tools) for cap, tools in self.capability_index.items()
            },
            "tools": list(self.tools.keys())
        }