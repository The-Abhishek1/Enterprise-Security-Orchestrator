# src/core/database.py
import asyncpg
from asyncpg import Pool
import redis.asyncio as redis
import aio_pika
from typing import Optional

from src.core.config import get_settings
from src.utils.logging import logger

settings = get_settings()


class DatabaseManager:
    """Manages database connections"""
    
    def __init__(self):
        self.pg_pool: Optional[Pool] = None
        self.redis_client: Optional[redis.Redis] = None
        self.rabbitmq_connection: Optional[aio_pika.Connection] = None
        self.rabbitmq_channel: Optional[aio_pika.Channel] = None
    
    async def initialize(self) -> None:
        """Initialize all database connections"""
        await self._init_postgres()
        await self._init_redis()
        await self._init_rabbitmq()
        logger.info("✅ All database connections initialized")
    
    async def _init_postgres(self) -> None:
        """Initialize PostgreSQL connection pool"""
        try:
            self.pg_pool = await asyncpg.create_pool(
                dsn=settings.postgres_dsn,
                min_size=settings.db_pool_min_size,
                max_size=settings.db_pool_max_size,
                timeout=settings.db_pool_timeout,
                command_timeout=60
            )
            
            # Test connection
            async with self.pg_pool.acquire() as conn:
                await conn.execute("SELECT 1")
            
            logger.info("✅ PostgreSQL connection pool initialized")
            
        except Exception as e:
            logger.error(f"❌ PostgreSQL initialization failed: {e}")
            raise
    
    async def _init_redis(self) -> None:
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.from_url(
                settings.redis_dsn,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True,
                health_check_interval=30
            )
            
            await self.redis_client.ping()
            logger.info("✅ Redis connection initialized")
            
        except Exception as e:
            logger.error(f"❌ Redis initialization failed: {e}")
            raise
    
    async def _init_rabbitmq(self) -> None:
        """Initialize RabbitMQ connection"""
        try:
            self.rabbitmq_connection = await aio_pika.connect_robust(
                settings.rabbitmq_dsn
            )
            
            self.rabbitmq_channel = await self.rabbitmq_connection.channel()
            
            # Declare exchanges
            await self.rabbitmq_channel.declare_exchange(
                "task_exchange",
                aio_pika.ExchangeType.TOPIC,
                durable=True
            )
            
            await self.rabbitmq_channel.declare_exchange(
                "result_exchange",
                aio_pika.ExchangeType.TOPIC,
                durable=True
            )
            
            logger.info("✅ RabbitMQ connection initialized")
            
        except Exception as e:
            logger.error(f"❌ RabbitMQ initialization failed: {e}")
            raise
    
    async def close(self) -> None:
        """Close all database connections"""
        
        # Close PostgreSQL
        if self.pg_pool:
            await self.pg_pool.close()
            logger.info("✅ PostgreSQL connection closed")
        
        # Close Redis
        if self.redis_client:
            await self.redis_client.close()
            logger.info("✅ Redis connection closed")
        
        # Close RabbitMQ
        if self.rabbitmq_channel:
            await self.rabbitmq_channel.close()
        
        if self.rabbitmq_connection:
            await self.rabbitmq_connection.close()
            logger.info("✅ RabbitMQ connection closed")
    
    async def execute_postgres(self, query: str, *args) -> asyncpg.Record:
        """Execute PostgreSQL query"""
        async with self.pg_pool.acquire() as conn:
            return await conn.execute(query, *args)
    
    async def fetch_postgres(self, query: str, *args) -> list:
        """Fetch from PostgreSQL"""
        async with self.pg_pool.acquire() as conn:
            return await conn.fetch(query, *args)
    
    async def fetchrow_postgres(self, query: str, *args) -> asyncpg.Record:
        """Fetch single row from PostgreSQL"""
        async with self.pg_pool.acquire() as conn:
            return await conn.fetchrow(query, *args)


# Global database manager
db_manager = DatabaseManager()


async def init_database() -> DatabaseManager:
    """Initialize database connections"""
    await db_manager.initialize()
    return db_manager


async def close_database() -> None:
    """Close database connections"""
    await db_manager.close()