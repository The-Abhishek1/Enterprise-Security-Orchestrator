"""
tool_registration.py — Fixed tool registration.

CRITICAL BUG FIXED:
  tool_discovery stores image as "docker_image"
  worker_pool reads tool_config.get("image", f"{tool_name}:latest")
  → was pulling "nmap:latest" from Docker Hub (doesn't exist)
  Fix: copy docker_image → image so WorkerPool uses eso-worker-nmap:latest
"""
from typing import List, Dict, Any, Optional
from src.tools.tool_discovery import ToolDiscovery
from src.tools.tool_registry import ToolRegistry
from src.workers.worker_pool import WorkerPool
from src.utils.logging import logger


class ToolRegistrationService:

    def __init__(self, tool_registry, worker_pool, discovery=None):
        self.tool_registry = tool_registry
        self.worker_pool   = worker_pool
        self.discovery     = discovery or ToolDiscovery()

    async def register_all_tools(self) -> int:
        discovered = await self.discovery.discover_tools()
        # FIX: cannot use await inside sum() generator — use explicit for loop
        registered = 0
        for t in discovered:
            if await self.register_tool(t):
                registered += 1
        logger.info(f"✅ Registered {registered}/{len(discovered)} tools")
        return registered

    async def register_tool(self, tool_config: Dict[str, Any]) -> bool:
        try:
            docker_image = (
                tool_config.get("docker_image") or
                tool_config.get("image") or
                f"eso-worker-{tool_config.get('name', 'unknown')}:latest"
            )
            tool_config["image"]        = docker_image
            tool_config["docker_image"] = docker_image

            self.tool_registry.register_tool(tool_config, config_path=tool_config.get("config_path"))

            ok   = tool_config.get("image_available", False)
            icon = "✅" if ok else "⚠️  image missing — run: bash build_workers.sh"
            logger.info(f"  {tool_config['name']:12s} → {docker_image} {icon}")
            return True
        except Exception as e:
            logger.error(f"❌ {tool_config.get('name')}: {e}")
            return False

    async def scan_for_new_tools(self) -> List[str]:
        current    = set(self.tool_registry.tools.keys())
        discovered = await self.discovery.discover_tools()
        registered = []
        for cfg in discovered:
            if cfg["name"] not in current:
                if await self.register_tool(cfg):
                    registered.append(cfg["name"])
        if registered:
            logger.info(f"🆕 Hot-registered: {registered}")
        return registered

    async def reload_tool(self, tool_name: str) -> bool:
        discovered = await self.discovery.discover_tools()
        cfg = next((t for t in discovered if t["name"] == tool_name), None)
        return await self.register_tool(cfg) if cfg else False
