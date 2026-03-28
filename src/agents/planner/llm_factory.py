# src/agents/planner/llm_factory.py
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
import aiohttp
import json
import asyncio

from src.core.config import get_settings
from src.utils.logging import logger

settings = get_settings()


class BaseLLMClient(ABC):
    """Base class for LLM clients"""
    
    def __init__(self, model_name: str, temperature: float = 0.7, max_tokens: int = 2000):
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
    
    @abstractmethod
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate text from prompt"""
        pass
    
    @abstractmethod
    async def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """Generate JSON from prompt"""
        pass


class OpenAIClient(BaseLLMClient):
    """OpenAI API client"""
    
    def __init__(self, api_key: str, model_name: str = "gpt-4", **kwargs):
        super().__init__(model_name, **kwargs)
        self.api_key = api_key
        self.base_url = "https://api.openai.com/v1/chat/completions"
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.base_url, headers=headers, json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"OpenAI API error: {error_text}")
                
                result = await response.json()
                return result["choices"][0]["message"]["content"]
    
    async def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """Generate JSON response"""
        system = (system_prompt or "") + "\nYou must respond with valid JSON only."
        response = await self.generate(prompt, system)
        
        # Extract JSON from response
        try:
            # Try to parse entire response as JSON
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            import re
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Try to find JSON object
            json_match = re.search(r'(\{[\s\S]*\})', response)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            raise ValueError(f"Could not parse JSON from response: {response[:200]}")


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude API client"""
    
    def __init__(self, api_key: str, model_name: str = "claude-3-opus-20240229", **kwargs):
        super().__init__(model_name, **kwargs)
        self.api_key = api_key
        self.base_url = "https://api.anthropic.com/v1/messages"
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        
        data = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "system": system_prompt,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.base_url, headers=headers, json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Anthropic API error: {error_text}")
                
                result = await response.json()
                return result["content"][0]["text"]
    
    async def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        system = (system_prompt or "") + "\nYou must respond with valid JSON only."
        response = await self.generate(prompt, system)
        
        # Extract JSON (similar to OpenAI implementation)
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            json_match = re.search(r'(\{[\s\S]*\})', response)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            raise ValueError(f"Could not parse JSON from response: {response[:200]}")


class LocalLLMClient(BaseLLMClient):
    """Local LLM client (Ollama)"""
    
    def __init__(self, base_url: str = "http://localhost:11434", model_name: str = "qwen2.5:3b", **kwargs):
        super().__init__(model_name, **kwargs)
        self.base_url = base_url.rstrip('/')
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        url = f"{self.base_url}/api/generate"
        
        data = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Local LLM error: {error_text}")
                
                result = await response.json()
                return result["response"]
    
    async def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        system = (system_prompt or "") + "\nYou must respond with valid JSON only."
        response = await self.generate(prompt, system)
        
        # Extract JSON (similar to OpenAI implementation)
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            import re
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            json_match = re.search(r'(\{[\s\S]*\})', response)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # If all else fails, return empty dict
            logger.warning(f"Could not parse JSON from LLM response: {response[:200]}")
            return {}


class LLMFactory:
    """Factory for creating LLM clients"""
    
    def __init__(self):
        self.clients = {}
        self.default_provider = settings.llm_provider.value
        logger.info(f"✅ LLM Factory initialized with default provider: {self.default_provider}")
    
    def get_client(
        self,
        provider: Optional[str] = None,
        model_name: Optional[str] = None,
        **kwargs
    ) -> BaseLLMClient:
        """Get LLM client for specified provider"""
        
        provider = provider or self.default_provider
        cache_key = f"{provider}:{model_name}"
        
        if cache_key in self.clients:
            return self.clients[cache_key]
        
        # Create client based on provider
        if provider == "openai":
            client = OpenAIClient(
                api_key=kwargs.get("api_key", settings.openai_api_key),
                model_name=model_name or "gpt-4",
                **kwargs
            )
        elif provider == "anthropic":
            client = AnthropicClient(
                api_key=kwargs.get("api_key", settings.anthropic_api_key),
                model_name=model_name or "claude-3-opus-20240229",
                **kwargs
            )
        elif provider == "local":
            client = LocalLLMClient(
                base_url=kwargs.get("base_url", settings.local_llm_url),
                model_name=model_name or settings.local_llm_model,
                **kwargs
            )
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")
        
        self.clients[cache_key] = client
        logger.info(f"✅ Created LLM client for {provider}: {client.model_name}")
        
        return client
    
    async def test_connection(self, provider: Optional[str] = None) -> bool:
        """Test connection to LLM provider"""
        try:
            client = self.get_client(provider)
            response = await client.generate("Say 'OK' if you can hear me.", "Respond with only the word OK.")
            return "OK" in response
        except Exception as e:
            logger.error(f"LLM connection test failed: {e}")
            return False


# Global LLM factory
llm_factory = LLMFactory()