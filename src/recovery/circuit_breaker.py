# src/recovery/circuit_breaker.py
from typing import Dict, Optional
from datetime import datetime, timedelta
import asyncio

from src.utils.logging import logger


class CircuitBreaker:
    """
    Circuit Breaker pattern implementation
    
    States:
    - CLOSED: Normal operation, requests allowed
    - OPEN: Circuit is open, requests fail fast
    - HALF_OPEN: Testing if service recovered
    """
    
    def __init__(self):
        self.circuits: Dict[str, Dict] = {}
        
        # Default configuration
        self.default_failure_threshold = 5
        self.default_timeout_seconds = 60
        self.default_half_open_max_calls = 3
        
        logger.info("✅ Circuit Breaker initialized")
    
    async def allow_request(self, circuit_key: str) -> bool:
        """Check if request should be allowed"""
        
        circuit = self._get_circuit(circuit_key)
        
        if circuit["state"] == "CLOSED":
            return True
        
        elif circuit["state"] == "OPEN":
            # Check if timeout has elapsed
            if datetime.utcnow() >= circuit["next_attempt"]:
                circuit["state"] = "HALF_OPEN"
                circuit["half_open_calls"] = 0
                logger.info(f"Circuit {circuit_key} transitioned to HALF_OPEN")
                return True
            return False
        
        elif circuit["state"] == "HALF_OPEN":
            # Allow limited requests in half-open state
            if circuit["half_open_calls"] < circuit["half_open_max_calls"]:
                circuit["half_open_calls"] += 1
                return True
            return False
        
        return False
    
    async def record_success(self, circuit_key: str):
        """Record successful request"""
        
        circuit = self._get_circuit(circuit_key)
        
        if circuit["state"] == "HALF_OPEN":
            # Success in half-open means service recovered
            circuit["state"] = "CLOSED"
            circuit["failure_count"] = 0
            logger.info(f"Circuit {circuit_key} recovered, closed")
        
        elif circuit["state"] == "CLOSED":
            # Reset failure count on success
            circuit["failure_count"] = 0
    
    async def record_failure(self, circuit_key: str):
        """Record failed request"""
        
        circuit = self._get_circuit(circuit_key)
        
        if circuit["state"] == "CLOSED":
            circuit["failure_count"] += 1
            
            if circuit["failure_count"] >= circuit["failure_threshold"]:
                circuit["state"] = "OPEN"
                circuit["next_attempt"] = datetime.utcnow() + timedelta(
                    seconds=circuit["timeout_seconds"]
                )
                logger.warning(f"Circuit {circuit_key} opened after {circuit['failure_count']} failures")
        
        elif circuit["state"] == "HALF_OPEN":
            # Failure in half-open means service still down
            circuit["state"] = "OPEN"
            circuit["next_attempt"] = datetime.utcnow() + timedelta(
                seconds=circuit["timeout_seconds"]
            )
            circuit["half_open_calls"] = 0
            logger.warning(f"Circuit {circuit_key} reopened after half-open failure")
    
    def _get_circuit(self, circuit_key: str) -> Dict:
        """Get or create circuit"""
        
        if circuit_key not in self.circuits:
            self.circuits[circuit_key] = {
                "state": "CLOSED",
                "failure_count": 0,
                "failure_threshold": self.default_failure_threshold,
                "timeout_seconds": self.default_timeout_seconds,
                "next_attempt": datetime.utcnow(),
                "half_open_calls": 0,
                "half_open_max_calls": self.default_half_open_max_calls
            }
        
        return self.circuits[circuit_key]
    
    async def get_state(self, circuit_key: str) -> Dict:
        """Get circuit state"""
        
        circuit = self._get_circuit(circuit_key)
        
        return {
            "circuit_key": circuit_key,
            "state": circuit["state"],
            "failure_count": circuit["failure_count"],
            "failure_threshold": circuit["failure_threshold"],
            "next_attempt": circuit["next_attempt"].isoformat() if circuit["state"] == "OPEN" else None
        }
    
    async def reset_circuit(self, circuit_key: str):
        """Manually reset circuit"""
        
        if circuit_key in self.circuits:
            self.circuits[circuit_key] = {
                "state": "CLOSED",
                "failure_count": 0,
                "failure_threshold": self.default_failure_threshold,
                "timeout_seconds": self.default_timeout_seconds,
                "next_attempt": datetime.utcnow(),
                "half_open_calls": 0,
                "half_open_max_calls": self.default_half_open_max_calls
            }
            logger.info(f"Circuit {circuit_key} manually reset")