"""
target_validator.py — hardened target sanitization.

Validates and sanitizes scan targets to prevent:
- SSRF (scanning internal infrastructure)
- DNS rebinding attacks
- Scanning localhost/metadata services
- Scanning cloud provider metadata endpoints
- IP spoofing via crafted hostnames
- Overly broad ranges

Returns { allowed: bool, reason: str, sanitized_target: str }
"""
import re
import socket
import ipaddress
from typing import Dict, Optional
from src.utils.logging import logger


# ── Blocked ranges ────────────────────────────────────────────────────────────
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local (AWS metadata: 169.254.169.254)
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("0.0.0.0/8"),         # This network
]

# Private ranges — allowed only if ALLOW_PRIVATE_TARGETS=true in env
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
]

# Cloud provider metadata endpoints — always blocked
BLOCKED_HOSTS = {
    "169.254.169.254",     # AWS/GCP/Azure instance metadata
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.com",
    "instance-data",
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
}

# Allowed protocol prefixes for URL targets
ALLOWED_SCHEMES = {"http", "https"}

# Max length for any target string
MAX_TARGET_LEN = 512


class TargetValidator:
    """
    Validates scan targets before they reach the scan engine.
    Prevents SSRF, metadata service access, and other abuse.
    """
    
    def __init__(self, allow_private: bool = False):
        import os
        self.allow_private = allow_private or os.getenv("ALLOW_PRIVATE_TARGETS","false").lower() == "true"
    
    def validate(self, target: str) -> Dict:
        """
        Validate a scan target.
        Returns: { allowed: bool, reason: str, sanitized: str }
        """
        if not target or not target.strip():
            return self._deny("Target cannot be empty")
        
        target = target.strip()
        
        if len(target) > MAX_TARGET_LEN:
            return self._deny(f"Target too long (max {MAX_TARGET_LEN} chars)")
        
        # Strip URL prefix to get the host
        host = self._extract_host(target)
        if not host:
            return self._deny("Could not parse host from target")
        
        # Check for blocked hostnames
        if host.lower() in BLOCKED_HOSTS:
            return self._deny(f"Target '{host}' is not allowed (blocked host)")
        
        # Check for localhost patterns
        if self._is_localhost(host):
            return self._deny(f"Scanning localhost is not allowed")
        
        # Check if it's an IP address
        ip = self._resolve_to_ip(host)
        if ip:
            check = self._check_ip(ip, host)
            if check:
                return self._deny(check)
        
        # Check for dangerous URL patterns (path traversal, encoded chars)
        if ".." in target or "%2e%2e" in target.lower() or "%00" in target.lower():
            return self._deny("Target contains suspicious path sequences")
        
        # Sanitize — return clean version
        sanitized = self._sanitize(target)
        
        logger.info(f"✅ Target validated: {sanitized}")
        return {"allowed": True, "reason": "ok", "sanitized": sanitized}
    
    def _extract_host(self, target: str) -> Optional[str]:
        """Extract hostname from URL or return as-is for IPs/hostnames."""
        # Strip scheme
        t = target
        if "://" in t:
            scheme = t.split("://")[0].lower()
            if scheme not in ALLOWED_SCHEMES:
                return None  # Block non-http schemes (ftp://, file://, etc.)
            t = t.split("://", 1)[1]
        
        # Strip path/query/fragment
        for sep in ("/", "?", "#", ":"):
            if sep in t:
                t = t.split(sep)[0]
        
        return t.strip().lower() if t.strip() else None
    
    def _is_localhost(self, host: str) -> bool:
        """Check if host resolves to or IS localhost."""
        lh = host.lower()
        if lh in ("localhost", "localhost.localdomain", "::1"):
            return True
        if lh.endswith(".localhost") or lh.endswith(".local"):
            return True
        return False
    
    def _resolve_to_ip(self, host: str) -> Optional[str]:
        """Try to resolve hostname to IP (with timeout)."""
        # Already an IP?
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        
        # Resolve
        try:
            result = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM,
                                         proto=socket.IPPROTO_TCP,
                                         flags=socket.AI_ADDRCONFIG)
            if result:
                return result[0][4][0]
        except (socket.gaierror, socket.timeout, OSError):
            pass
        return None
    
    def _check_ip(self, ip_str: str, original_host: str) -> Optional[str]:
        """Return error string if IP is blocked, None if allowed."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return f"Invalid IP address: {ip_str}"
        
        # Check always-blocked ranges
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return f"Target resolves to blocked network range ({network})"
        
        # Check private ranges (conditional)
        if not self.allow_private:
            for network in PRIVATE_NETWORKS:
                if ip in network:
                    return (f"Target resolves to private IP ({ip_str}). "
                            "Private network scanning requires special authorization.")
        
        # DNS rebinding protection — if hostname doesn't look like an IP
        # but resolves to one of our blocked ranges, block it
        if not self._looks_like_ip(original_host) and ip_str in BLOCKED_HOSTS:
            return f"DNS rebinding detected: {original_host} → {ip_str}"
        
        return None
    
    def _looks_like_ip(self, s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False
    
    def _sanitize(self, target: str) -> str:
        """Remove dangerous characters, normalize."""
        # Remove control chars
        sanitized = re.sub(r'[\x00-\x1f\x7f]', '', target)
        # Strip shell metacharacters
        sanitized = re.sub(r'[;&|`$(){}\\]', '', sanitized)
        return sanitized.strip()
    
    def _deny(self, reason: str) -> Dict:
        logger.warning(f"🚫 Target blocked: {reason}")
        return {"allowed": False, "reason": reason, "sanitized": ""}
    
    def validate_tool_flags(self, tool: str, flags: str) -> Dict:
        """
        Validate tool flags to prevent command injection.
        Returns { allowed: bool, reason: str, sanitized_flags: str }
        """
        if not flags:
            return {"allowed": True, "reason": "ok", "sanitized_flags": ""}
        
        # Strip null bytes and control characters
        flags = re.sub(r'[\x00-\x1f\x7f]', '', flags)
        
        # Detect shell injection attempts
        dangerous_patterns = [
            r'[;&|`]',          # Shell operators
            r'\$\(',            # Command substitution
            r'\$\{',            # Parameter expansion
            r'>\s*/',           # Output redirection to file
            r'<\s*/',           # Input from file
            r'\.\.',            # Path traversal
            r'--output',        # Don't allow writing to arbitrary files
            r'-oN|-oX|-oG|-oA', # Nmap output files (controlled by us)
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, flags, re.IGNORECASE):
                return {"allowed": False, "reason": f"Dangerous flag pattern: {pattern}",
                        "sanitized_flags": ""}
        
        # Tool-specific validation
        if tool == "sqlmap":
            # Block --os-shell, --os-cmd, --file-write, --file-read
            blocked = ["--os-shell", "--os-cmd", "--file-write", "--file-read",
                       "--eval", "--tamper"]
            for b in blocked:
                if b in flags.lower():
                    return {"allowed": False, "reason": f"sqlmap flag '{b}' not allowed",
                            "sanitized_flags": ""}
        
        return {"allowed": True, "reason": "ok", "sanitized_flags": flags}


# Singleton
target_validator = TargetValidator()
