# src/agents/collaboration/memory_bus.py
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio
import uuid

from src.memory.memory_service import MemoryService
from src.utils.logging import logger


class AgentMemoryBus:
    """
    Memory Bus for Agent Collaboration
    
    Features:
    - Pub/sub messaging between agents
    - Message persistence
    - Topic-based routing
    - History replay
    """
    
    def __init__(self, memory_service: MemoryService):
        self.memory_service = memory_service
        self.subscribers: Dict[str, List[str]] = {}  # topic -> [agent_ids]
        self.queues: Dict[str, asyncio.Queue] = {}
        self.history: Dict[str, List[Dict]] = {}
        
        logger.info("✅ Agent Memory Bus initialized")
    
    async def publish(
        self,
        topic: str,
        agent_id: str,
        message: Dict[str, Any],
        persist: bool = True
    ):
        """Publish message to topic"""
        
        # Create message with metadata
        enriched_message = {
            "id": f"msg_{uuid.uuid4().hex[:8]}",
            "topic": topic,
            "sender": agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            **message
        }
        
        # Store in history if persist
        if persist:
            if topic not in self.history:
                self.history[topic] = []
            self.history[topic].append(enriched_message)
            
            # Limit history size
            if len(self.history[topic]) > 100:
                self.history[topic] = self.history[topic][-100:]
        
        # Deliver to subscribers
        if topic in self.subscribers:
            for subscriber in self.subscribers[topic]:
                # Create queue for subscriber if needed
                queue_key = f"{topic}:{subscriber}"
                if queue_key not in self.queues:
                    self.queues[queue_key] = asyncio.Queue()
                
                # Put message in queue
                try:
                    self.queues[queue_key].put_nowait(enriched_message)
                except asyncio.QueueFull:
                    logger.warning(f"Queue full for {subscriber} on {topic}")
        
        logger.debug(f"📢 Published message to {topic} from {agent_id}")
    
    async def subscribe(self, agent_id: str, topics: List[str]):
        """Subscribe agent to topics"""
        
        for topic in topics:
            if topic not in self.subscribers:
                self.subscribers[topic] = []
            
            if agent_id not in self.subscribers[topic]:
                self.subscribers[topic].append(agent_id)
                
                # Create queue for this subscription
                queue_key = f"{topic}:{agent_id}"
                self.queues[queue_key] = asyncio.Queue(maxsize=100)
        
        logger.info(f"📋 Agent {agent_id} subscribed to {topics}")
    
    async def unsubscribe(self, agent_id: str, topic: Optional[str] = None):
        """Unsubscribe agent from topics"""
        
        if topic:
            # Unsubscribe from specific topic
            if topic in self.subscribers and agent_id in self.subscribers[topic]:
                self.subscribers[topic].remove(agent_id)
                
                # Remove queue
                queue_key = f"{topic}:{agent_id}"
                self.queues.pop(queue_key, None)
        else:
            # Unsubscribe from all topics
            topics_to_remove = []
            for topic, subscribers in self.subscribers.items():
                if agent_id in subscribers:
                    subscribers.remove(agent_id)
                    queue_key = f"{topic}:{agent_id}"
                    self.queues.pop(queue_key, None)
                    
                    if not subscribers:
                        topics_to_remove.append(topic)
            
            # Remove empty topics
            for topic in topics_to_remove:
                self.subscribers.pop(topic, None)
    
    async def receive(self, agent_id: str, topic: str, timeout: Optional[float] = None) -> Optional[Dict]:
        """Receive next message for agent on topic"""
        
        queue_key = f"{topic}:{agent_id}"
        if queue_key not in self.queues:
            return None
        
        try:
            if timeout:
                message = await asyncio.wait_for(
                    self.queues[queue_key].get(),
                    timeout=timeout
                )
            else:
                message = await self.queues[queue_key].get()
            
            return message
            
        except asyncio.TimeoutError:
            return None
    
    async def get_topic_history(self, topic: str, limit: int = 10) -> List[Dict]:
        """Get message history for topic"""
        
        if topic in self.history:
            return self.history[topic][-limit:]
        
        return []
    
    async def get_agent_messages(self, agent_id: str, limit: int = 10) -> List[Dict]:
        """Get all messages for agent across topics"""
        
        messages = []
        
        for topic, history in self.history.items():
            for msg in history:
                if msg.get("recipient") == agent_id or msg.get("sender") == agent_id:
                    messages.append(msg)
        
        # Sort by timestamp
        messages.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return messages[:limit]
    
    async def clear_topic(self, topic: str):
        """Clear all messages for topic"""
        
        self.history.pop(topic, None)
        
        # Clear queues for this topic
        for key in list(self.queues.keys()):
            if key.startswith(f"{topic}:"):
                while not self.queues[key].empty():
                    try:
                        self.queues[key].get_nowait()
                    except asyncio.QueueEmpty:
                        break