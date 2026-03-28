# src/tools/tool_registration.py
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.tools.tool_discovery import ToolDiscovery
from src.tools.tool_registry import ToolRegistry
from src.workers.worker_pool import WorkerPool
from src.utils.logging import logger


class ToolRegistrationService:
    """
    Service for dynamic tool registration
    
    Features:
    - Automatic discovery on startup
    - Hot reloading of tool configurations
    - Worker pool initialization
    - Periodic re-scanning
    """
    
    def __init__(
        self,
        tool_registry: ToolRegistry,
        worker_pool: WorkerPool,
        discovery: Optional[ToolDiscovery] = None
    ):
        self.tool_registry = tool_registry
        self.worker_pool = worker_pool
        self.discovery = discovery or ToolDiscovery()
        self.watched_paths: List[Path] = []
        
    async def register_all_tools(self) -> int:
        """Discover and register all available tools"""
        
        # Discover tools
        discovered_tools = await self.discovery.discover_tools()
        
        # Register each tool
        registered_count = 0
        for tool in discovered_tools:
            try:
                await self.register_tool(tool)
                registered_count += 1
            except Exception as e:
                logger.error(f"Failed to register tool {tool.get('name')}: {e}")
        
        logger.info(f"✅ Registered {registered_count} tools")
        return registered_count
    
    async def register_tool(self, tool_config: Dict[str, Any]) -> bool:
            """Register a single tool"""
            
            try:
                # Register in tool registry (metadata only — no Docker operations)
                self.tool_registry.register_tool(
                    tool_config,
                    config_path=tool_config.get("config_path")
                )
                
                # DON'T initialize worker pool here — it will be created on-demand
                # when the first task needs this tool. This avoids pulling images
                # and creating containers at startup time.
                logger.info(f"✅ Registered tool: {tool_config['name']} v{tool_config.get('version', 'latest')} (workers on-demand)")
                return True
                
            except Exception as e:
                logger.error(f"❌ Failed to register tool {tool_config.get('name')}: {e}")
                return False
    
    async def scan_for_new_tools(self) -> List[str]:
        """Scan for newly added tools"""
        
        current_tools = set(self.tool_registry.tools.keys())
        discovered_tools = await self.discovery.discover_tools()
        discovered_names = {t["name"] for t in discovered_tools}
        
        # Find new tools
        new_tools = discovered_names - current_tools
        registered_tools = []
        
        for tool_name in new_tools:
            tool_config = next(t for t in discovered_tools if t["name"] == tool_name)
            success = await self.register_tool(tool_config)
            if success:
                registered_tools.append(tool_name)
        
        if registered_tools:
            logger.info(f"🆕 Discovered and registered new tools: {registered_tools}")
        
        return registered_tools
    
    async def reload_tool(self, tool_name: str) -> bool:
        """Reload a specific tool configuration"""
        
        # Find tool config
        discovered_tools = await self.discovery.discover_tools()
        tool_config = next((t for t in discovered_tools if t["name"] == tool_name), None)
        
        if not tool_config:
            logger.warning(f"Tool {tool_name} not found in discovery")
            return False
        
        # Re-register
        return await self.register_tool(tool_config)
    
    async def watch_for_changes(self, interval: int = 60):
        """Watch for changes in tool configurations"""
        
        while True:
            try:
                await asyncio.sleep(interval)
                await self.scan_for_new_tools()
                
                # Check for modifications in existing tools
                for tool_name, config_path in self.tool_registry.tool_configs.items():
                    if config_path and config_path.exists():
                        # Check if file has been modified
                        # In production, use file watchers like inotify
                        pass
                        
            except Exception as e:
                logger.error(f"Error in tool watcher: {e}")