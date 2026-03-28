# src/recovery/retry_manager.py
from typing import Callable, Any, Dict, Optional, Type
import asyncio
import random
from datetime import datetime

from src.recovery.circuit_breaker import CircuitBreaker
from src.recovery.fallback_manager import FallbackManager
from src.recovery.escalation_manager import EscalationManager
from src.utils.logging import logger
from src.core.exceptions import RetryExhaustedError


class RetryManager:
    """
    Enterprise Retry Manager
    
    Features:
    - Configurable retry strategies
    - Exponential backoff with jitter
    - Circuit breaker integration
    - Fallback mechanisms
    - Escalation policies
    """
    
    def __init__(
        self,
        circuit_breaker: Optional[CircuitBreaker] = None,
        fallback_manager: Optional[FallbackManager] = None,
        escalation_manager: Optional[EscalationManager] = None
    ):
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.fallback_manager = fallback_manager or FallbackManager()
        self.escalation_manager = escalation_manager or EscalationManager()
        
        # Default retry configuration
        self.default_max_retries = 3
        self.default_base_delay = 1.0  # seconds
        self.default_max_delay = 30.0  # seconds
        self.default_jitter = 0.1  # 10% jitter
        
        logger.info("✅ Retry Manager initialized")
    
    async def execute_with_retry(
        self,
        func: Callable,
        *args,
        max_retries: Optional[int] = None,
        base_delay: Optional[float] = None,
        max_delay: Optional[float] = None,
        jitter: Optional[float] = None,
        retryable_exceptions: Optional[tuple] = None,
        circuit_breaker_key: Optional[str] = None,
        fallback_func: Optional[Callable] = None,
        escalation_policy: Optional[str] = None,
        context: Optional[Dict] = None,
        **kwargs
    ) -> Any:
        """
        Execute function with retry logic
        
        Args:
            func: Function to execute
            *args: Positional arguments for function
            max_retries: Maximum number of retries
            base_delay: Initial delay between retries
            max_delay: Maximum delay between retries
            jitter: Random jitter factor (0-1)
            retryable_exceptions: Tuple of exceptions that should trigger retry
            circuit_breaker_key: Key for circuit breaker (if None, circuit breaker disabled)
            fallback_func: Fallback function if all retries fail
            escalation_policy: Escalation policy name
            context: Additional context for logging
            **kwargs: Keyword arguments for function
            
        Returns:
            Function result
            
        Raises:
            RetryExhaustedError: If all retries fail
        """
        
        # Set defaults
        max_retries = max_retries or self.default_max_retries
        base_delay = base_delay or self.default_base_delay
        max_delay = max_delay or self.default_max_delay
        jitter = jitter or self.default_jitter
        retryable_exceptions = retryable_exceptions or (Exception,)
        
        attempt = 0
        last_exception = None
        
        # Check circuit breaker
        if circuit_breaker_key and not await self.circuit_breaker.allow_request(circuit_breaker_key):
            logger.warning(f"Circuit breaker open for {circuit_breaker_key}, trying fallback")
            if fallback_func:
                return await self._execute_fallback(fallback_func, *args, **kwargs)
            raise Exception(f"Circuit breaker open for {circuit_breaker_key}")
        
        while attempt <= max_retries:
            try:
                if attempt > 0:
                    # Calculate delay with exponential backoff and jitter
                    delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
                    
                    # Add jitter
                    if jitter > 0:
                        jitter_amount = delay * jitter * random.random()
                        delay = delay + jitter_amount
                    
                    logger.info(
                        f"Retry attempt {attempt}/{max_retries} after {delay:.2f}s",
                        extra={"context": context}
                    )
                    
                    await asyncio.sleep(delay)
                
                # Execute function
                result = await func(*args, **kwargs)
                
                # Record success in circuit breaker
                if circuit_breaker_key:
                    await self.circuit_breaker.record_success(circuit_breaker_key)
                
                return result
                
            except retryable_exceptions as e:
                last_exception = e
                attempt += 1
                
                logger.warning(
                    f"Attempt {attempt}/{max_retries} failed: {str(e)}",
                    extra={"context": context}
                )
                
                # Record failure in circuit breaker
                if circuit_breaker_key:
                    await self.circuit_breaker.record_failure(circuit_breaker_key)
                
            except Exception as e:
                # Non-retryable exception
                logger.error(f"Non-retryable exception: {str(e)}")
                raise
        
        # All retries exhausted
        logger.error(f"All {max_retries} retry attempts exhausted")
        
        # Try fallback
        if fallback_func:
            logger.info("Attempting fallback function")
            return await self._execute_fallback(fallback_func, *args, **kwargs)
        
        # Escalate if policy defined
        if escalation_policy:
            await self.escalation_manager.escalate(
                policy=escalation_policy,
                error=last_exception,
                context=context
            )
        
        raise RetryExhaustedError(
            f"All {max_retries} retry attempts failed",
            last_error=str(last_exception) if last_exception else "Unknown"
        )
    
    async def _execute_fallback(self, fallback_func: Callable, *args, **kwargs) -> Any:
        """Execute fallback function"""
        try:
            result = await fallback_func(*args, **kwargs)
            logger.info("Fallback function executed successfully")
            return result
        except Exception as e:
            logger.error(f"Fallback function failed: {e}")
            raise
    
    async def execute_with_timeout(
        self,
        func: Callable,
        timeout: float,
        *args,
        **kwargs
    ) -> Any:
        """Execute function with timeout"""
        try:
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=timeout
            )
            return result
        except asyncio.TimeoutError:
            logger.error(f"Function timed out after {timeout}s")
            raise TimeoutError(f"Execution timed out after {timeout}s")