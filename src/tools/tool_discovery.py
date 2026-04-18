"""
tool_discovery.py — dynamic tool registration.
discover_tools() is called by tool_registration.py on startup.
"""
import asyncio
from pathlib import Path
from typing import Dict, List, Optional

from src.utils.logging import logger

try:
    import yaml
    _has_yaml = True
except ImportError:
    _has_yaml = False

try:
    import docker
    _has_docker = True
except ImportError:
    _has_docker = False


DEFAULT_MANIFESTS = {
    "nmap": {
        "name": "nmap", "display_name": "Nmap",
        "description": "Port scanning, service detection, OS fingerprinting",
        "version": "7.94",
        "capabilities": ["port_scan", "network_scan", "os_detection", "service_detection"],
        "tier_required": "free",
        "docker_image": "eso-worker-nmap:latest",
        "default_flags": "-sT -sV --top-ports 1000 -T4 --open",
        "max_duration": 300, "output_format": "text",
    },
    "nuclei": {
        "name": "nuclei", "display_name": "Nuclei",
        "description": "Template-based vulnerability scanner with CVE database",
        "version": "3.x",
        "capabilities": ["vuln_scan", "cve_detection", "misconfig_scan"],
        "tier_required": "pro",
        "docker_image": "eso-worker-nuclei:latest",
        "default_flags": "-severity critical,high,medium -t cves/ -t exposures/",
        "max_duration": 600, "output_format": "text",
    },
    "gobuster": {
        "name": "gobuster", "display_name": "Gobuster",
        "description": "Directory and DNS brute-forcing", "version": "3.x",
        "capabilities": ["directory_bruteforce", "dns_enumeration"],
        "tier_required": "pro", "docker_image": "eso-worker-gobuster:latest",
        "default_flags": "dir -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50 -q --no-error",
        "max_duration": 300, "output_format": "text",
    },
    "nikto": {
        "name": "nikto", "display_name": "Nikto",
        "description": "Web server vulnerability scanner", "version": "2.x",
        "capabilities": ["web_vuln_scan", "server_misconfiguration"],
        "tier_required": "pro", "docker_image": "eso-worker-nikto:latest",
        "default_flags": "-nointeractive -maxtime 120 -Format txt",
        "max_duration": 300, "output_format": "text",
    },
    "whatweb": {
        "name": "whatweb", "display_name": "WhatWeb",
        "description": "Web technology fingerprinting", "version": "0.5.x",
        "capabilities": ["tech_detection", "web_fingerprint"],
        "tier_required": "pro", "docker_image": "eso-worker-whatweb:latest",
        "default_flags": "-a 3 --colour=never", "max_duration": 120, "output_format": "text",
    },
    "ffuf": {
        "name": "ffuf", "display_name": "FFUF",
        "description": "Fast web fuzzer", "version": "2.x",
        "capabilities": ["directory_bruteforce", "parameter_fuzzing", "vhost_discovery"],
        "tier_required": "enterprise", "docker_image": "eso-worker-ffuf:latest",
        "default_flags": "-fc 404 -t 100", "max_duration": 300, "output_format": "json",
    },
    "sqlmap": {
        "name": "sqlmap", "display_name": "SQLMap",
        "description": "SQL injection testing", "version": "1.8.x",
        "capabilities": ["sql_injection", "database_extraction"],
        "tier_required": "enterprise", "docker_image": "eso-worker-sqlmap:latest",
        "default_flags": "--batch --level=2 --risk=2 --random-agent",
        "max_duration": 600, "output_format": "text",
    },
}

TIER_ORDER = {"free": 0, "pro": 1, "enterprise": 2, "admin": 3}


class ToolDiscovery:
    """Discovers security tools dynamically. Compatible with tool_registration.py."""

    def __init__(self, workers_dir: str = "docker/workers"):
        self.workers_dir = Path(workers_dir)
        self._docker_client = None
        self._available_images: set = set()

    def _get_docker(self):
        if not _has_docker:
            return None
        if not self._docker_client:
            try:
                self._docker_client = docker.from_env()
            except Exception:
                pass
        return self._docker_client

    async def _scan_docker_images(self):
        client = self._get_docker()
        if not client:
            return
        try:
            loop = asyncio.get_event_loop()
            images = await loop.run_in_executor(None, lambda: client.images.list())
            self._available_images = set()
            for img in images:
                for tag in (img.tags or []):
                    self._available_images.add(tag)
        except Exception as e:
            logger.debug(f"Docker image scan failed: {e}")

    def _load_manifest(self, path: Path, tool_name: str) -> Dict:
        if not _has_yaml:
            raise ImportError("pyyaml not installed")
        with open(path) as f:
            manifest = yaml.safe_load(f)
        for field in ["name", "capabilities", "docker_image"]:
            if field not in manifest:
                raise ValueError(f"tool.yaml missing: {field}")
        manifest.setdefault("tier_required", "pro")
        manifest.setdefault("max_duration", 300)
        manifest.setdefault("output_format", "text")
        manifest.setdefault("default_flags", "")
        return manifest

    async def discover_tools(self) -> List[Dict]:
        """
        Discover all available tools. Returns list of tool config dicts.
        Called by tool_registration.py on startup and hot-reload.
        """
        await self._scan_docker_images()
        tools: List[Dict] = []
        found_names: set = set()

        if self.workers_dir.exists():
            for tool_dir in sorted(self.workers_dir.iterdir()):
                if not tool_dir.is_dir():
                    continue
                tool_name = tool_dir.name
                manifest = None

                manifest_path = tool_dir / "tool.yaml"
                if manifest_path.exists():
                    try:
                        manifest = self._load_manifest(manifest_path, tool_name)
                        logger.info(f"Discovered: {tool_name} (tool.yaml)")
                    except Exception as e:
                        logger.warning(f"Bad tool.yaml for {tool_name}: {e}")

                if manifest is None and (tool_dir / "Dockerfile").exists():
                    if tool_name in DEFAULT_MANIFESTS:
                        manifest = DEFAULT_MANIFESTS[tool_name].copy()
                        logger.info(f"Discovered: {tool_name} (Dockerfile)")

                if manifest:
                    manifest["image_available"] = (
                        manifest.get("docker_image", "") in self._available_images
                    )
                    tools.append(manifest)
                    found_names.add(manifest["name"])

        for name, manifest in DEFAULT_MANIFESTS.items():
            if name not in found_names:
                m = manifest.copy()
                m["image_available"] = m.get("docker_image", "") in self._available_images
                tools.append(m)
                found_names.add(name)

        logger.info(f"discover_tools: {len(tools)} tools found")
        return tools

    async def discover(self, tool_registry) -> List[str]:
        """Register tools directly into a registry. Returns registered names."""
        tools = await self.discover_tools()
        registered = []
        for tool in tools:
            try:
                tool_registry.register_tool(tool)
                registered.append(tool["name"])
            except Exception as e:
                logger.error(f"Failed to register {tool.get('name')}: {e}")
        return registered

    def get_tools_for_tier(self, tier: str) -> List[str]:
        tier_level = TIER_ORDER.get(tier, 0)
        return [
            name for name, m in DEFAULT_MANIFESTS.items()
            if TIER_ORDER.get(m.get("tier_required", "pro"), 1) <= tier_level
        ]

    async def check_tool_health(self, tool_name: str) -> Dict:
        client = self._get_docker()
        if not client:
            return {"healthy": False, "reason": "Docker not available"}
        manifest = DEFAULT_MANIFESTS.get(tool_name, {})
        image = manifest.get("docker_image", f"eso-worker-{tool_name}:latest")
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: client.images.get(image))
            return {"healthy": True, "image": image}
        except Exception:
            return {"healthy": False, "reason": f"Image not found: {image}"}


# Singleton
tool_discovery = ToolDiscovery()
