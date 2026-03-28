# src/recovery/fallback_manager.py
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
import asyncio

from src.utils.logging import logger


class FallbackManager:
    """
    Enterprise Fallback Manager
    
    Manages fallback strategies for failed operations:
    - Alternative tools
    - Different parameters
    - Cached results
    - Default responses
    - Graceful degradation
    """
    
    def __init__(self):
        self.fallback_strategies: Dict[str, List[Dict]] = {}
        self.cache: Dict[str, Any] = {}
        
        logger.info("✅ Fallback Manager initialized")
    
    async def register_fallback(
        self,
        operation_type: str,
        strategy: Dict,
        priority: int = 10
    ):
        """Register a fallback strategy"""
        
        if operation_type not in self.fallback_strategies:
            self.fallback_strategies[operation_type] = []
        
        self.fallback_strategies[operation_type].append({
            **strategy,
            "priority": priority,
            "registered_at": datetime.utcnow().isoformat()
        })
        
        # Sort by priority
        self.fallback_strategies[operation_type].sort(key=lambda x: x["priority"])
        
        logger.debug(f"Registered fallback for {operation_type}")
    
    async def execute_fallback(
        self,
        operation_type: str,
        original_params: Dict,
        error: Exception,
        context: Optional[Dict] = None
    ) -> Optional[Any]:
        """Execute fallback strategies for failed operation"""
        
        if operation_type not in self.fallback_strategies:
            logger.warning(f"No fallback strategies for {operation_type}")
            return None
        
        strategies = self.fallback_strategies[operation_type]
        
        for strategy in strategies:
            try:
                logger.info(f"Trying fallback strategy: {strategy.get('name', 'unknown')}")
                
                result = await self._execute_strategy(
                    strategy=strategy,
                    original_params=original_params,
                    error=error,
                    context=context
                )
                
                if result is not None:
                    logger.info(f"Fallback strategy succeeded: {strategy.get('name')}")
                    return result
                    
            except Exception as e:
                logger.warning(f"Fallback strategy failed: {e}")
                continue
        
        logger.error(f"All fallback strategies failed for {operation_type}")
        return None
    
    async def _execute_strategy(
        self,
        strategy: Dict,
        original_params: Dict,
        error: Exception,
        context: Optional[Dict]
    ) -> Optional[Any]:
        """Execute a specific fallback strategy"""
        
        strategy_type = strategy.get("type")
        
        if strategy_type == "alternative_tool":
            return await self._alternative_tool_fallback(strategy, original_params, context)
        
        elif strategy_type == "cached_result":
            return await self._cached_result_fallback(strategy, original_params, context)
        
        elif strategy_type == "default_response":
            return await self._default_response_fallback(strategy, original_params, context)
        
        elif strategy_type == "reduced_scope":
            return await self._reduced_scope_fallback(strategy, original_params, context)
        
        elif strategy_type == "function":
            # Custom function fallback
            func = strategy.get("function")
            if func and callable(func):
                return await func(original_params, error, context)
        
        return None
    
    async def _alternative_tool_fallback(
        self,
        strategy: Dict,
        original_params: Dict,
        context: Optional[Dict]
    ) -> Optional[Any]:
        """Fallback to alternative tool"""
        
        alternative_tool = strategy.get("tool")
        if not alternative_tool:
            return None
        
        # Modify params to use alternative tool
        modified_params = original_params.copy()
        modified_params["tool"] = alternative_tool
        
        logger.info(f"Using alternative tool: {alternative_tool}")
        
        # Return modified params for retry
        return {"fallback_type": "alternative_tool", "params": modified_params}
    
    async def _cached_result_fallback(
        self,
        strategy: Dict,
        original_params: Dict,
        context: Optional[Dict]
    ) -> Optional[Any]:
        """Fallback to cached result"""
        
        cache_key = self._generate_cache_key(original_params)
        
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
            max_age = strategy.get("max_age", 3600)
            
            if age <= max_age:
                logger.info(f"Using cached result from {age:.0f}s ago")
                return cached["data"]
        
        return None
    
    async def _default_response_fallback(
        self,
        strategy: Dict,
        original_params: Dict,
        context: Optional[Dict]
    ) -> Optional[Any]:
        """Fallback to default response"""
        
        default_response = strategy.get("response")
        
        if default_response:
            logger.info("Using default response")
            return {
                "fallback_type": "default_response",
                "data": default_response,
                "message": "Default response due to execution failure"
            }
        
        return None
    
    async def _reduced_scope_fallback(
        self,
        strategy: Dict,
        original_params: Dict,
        context: Optional[Dict]
    ) -> Optional[Any]:
        """Fallback with reduced scope"""
        
        reduced_params = original_params.copy()
        
        # Apply scope reduction
        if "ports" in reduced_params:
            # Reduce port range
            reduced_params["ports"] = "80,443"
        
        if "templates" in reduced_params:
            # Use fewer templates
            templates = reduced_params["templates"]
            if isinstance(templates, list) and len(templates) > 5:
                reduced_params["templates"] = templates[:3]
        
        logger.info("Using reduced scope fallback")
        
        return {"fallback_type": "reduced_scope", "params": reduced_params}
    
    def _generate_cache_key(self, params: Dict) -> str:
        """Generate cache key from parameters"""
        import hashlib
        import json
        
        key_string = json.dumps(params, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    async def cache_result(self, params: Dict, result: Any, ttl: int = 3600):
        """Cache a result for future use"""
        
        cache_key = self._generate_cache_key(params)
        
        self.cache[cache_key] = {
            "data": result,
            "timestamp": datetime.utcnow(),
            "ttl": ttl
        }
        
        # Limit cache size
        if len(self.cache) > 1000:
            # Remove oldest entries
            oldest_keys = sorted(
                self.cache.keys(),
                key=lambda k: self.cache[k]["timestamp"]
            )[:100]
            for key in oldest_keys:
                del self.cache[key]