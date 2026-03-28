# src/services/target_validator.py

"""
Target Validator — prevents users from scanning targets they don't own.
Enterprise requirement: legal compliance + abuse prevention.
"""

from typing import List, Optional
import re
import ipaddress

from src.core.config import get_settings
from src.utils.logging import logger

settings = get_settings()


class TargetValidator:
    """Validates scan targets against allowlist/denylist rules."""
    
    # Targets that should NEVER be scanned
    GLOBAL_DENYLIST = [
        "*.gov", "*.mil", "*.edu",
        "localhost", "127.0.0.1", "0.0.0.0",
        "*.internal", "*.local",
        "169.254.*",  # Link-local
        "*.amazonaws.com",  # AWS metadata
        "metadata.google.internal",
    ]
    
    def __init__(self):
        self.allowed_patterns = self._load_patterns("ALLOWED_TARGETS")
        self.denied_patterns = self._load_patterns("DENIED_TARGETS")
        
        # Always include global denylist
        for pattern in self.GLOBAL_DENYLIST:
            if pattern not in self.denied_patterns:
                self.denied_patterns.append(pattern)
    
    def validate(self, target: str) -> dict:
        """
        Validate a scan target.
        Returns: {"allowed": bool, "reason": str}
        """
        if not target or not target.strip():
            return {"allowed": False, "reason": "Target cannot be empty"}
        
        target = target.strip().lower()
        
        # Remove protocol prefix for validation
        clean = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        
        # Check denylist first
        for pattern in self.denied_patterns:
            if self._matches(clean, pattern):
                logger.warning(f"🚫 Target denied: {target} matches {pattern}")
                return {"allowed": False, "reason": f"Target matches denied pattern: {pattern}"}
        
        # Check private IP ranges
        try:
            ip = ipaddress.ip_address(clean)
            if ip.is_private and not self._is_allowed_private(clean):
                return {"allowed": False, "reason": f"Private IP address {clean} — add to ALLOWED_TARGETS to permit"}
            if ip.is_loopback:
                return {"allowed": False, "reason": "Loopback addresses are not allowed"}
        except ValueError:
            pass  # Not an IP, it's a hostname — continue
        
        # If allowlist is configured, target must match
        if self.allowed_patterns:
            for pattern in self.allowed_patterns:
                if self._matches(clean, pattern):
                    return {"allowed": True, "reason": "Target matches allowlist"}
            return {"allowed": False, "reason": "Target not in allowlist"}
        
        # In development mode with no allowlist, allow everything not denied
        if settings.environment.value == "development":
            return {"allowed": True, "reason": "Development mode — no restrictions"}
        
        # Production with no allowlist — require explicit allowlist
        return {"allowed": False, "reason": "No allowlist configured — set ALLOWED_TARGETS in production"}
    
    def _matches(self, target: str, pattern: str) -> bool:
        """Check if target matches a glob-like pattern."""
        pattern = pattern.strip().lower()
        
        # Exact match
        if target == pattern:
            return True
        
        # Wildcard match: *.example.com
        if pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            return target.endswith(suffix) or target == pattern[2:]
        
        # CIDR match: 10.0.0.0/8
        if '/' in pattern:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                ip = ipaddress.ip_address(target)
                return ip in network
            except ValueError:
                return False
        
        # Wildcard anywhere: 192.168.*
        if '*' in pattern:
            regex = pattern.replace('.', r'\.').replace('*', '.*')
            return bool(re.fullmatch(regex, target))
        
        return False
    
    def _is_allowed_private(self, ip_str: str) -> bool:
        """Check if a private IP is explicitly in the allowlist."""
        for pattern in self.allowed_patterns:
            if self._matches(ip_str, pattern):
                return True
        return False
    
    def _load_patterns(self, env_var: str) -> List[str]:
        """Load comma-separated patterns from config."""
        raw = getattr(settings, env_var.lower(), None)
        if not raw:
            import os
            raw = os.environ.get(env_var, "")
        if not raw:
            return []
        return [p.strip() for p in raw.split(",") if p.strip()]


# Singleton
target_validator = TargetValidator()
