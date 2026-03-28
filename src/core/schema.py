# src/core/schema.py

"""
Database schema initialization.
Creates tables on startup if they don't exist.
"""

from src.utils.logging import logger


SCHEMA_SQL = """
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    tenant_id VARCHAR(64) DEFAULT 'default',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    key_id VARCHAR(64) UNIQUE NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    permissions TEXT[] DEFAULT ARRAY['read', 'execute'],
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Scan history table
CREATE TABLE IF NOT EXISTS scan_history (
    id SERIAL PRIMARY KEY,
    process_id VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(64) NOT NULL REFERENCES users(user_id),
    tenant_id VARCHAR(64) DEFAULT 'default',
    goal TEXT NOT NULL,
    target VARCHAR(500),
    status VARCHAR(20) NOT NULL,
    total_tasks INTEGER DEFAULT 0,
    completed_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0,
    dynamic_tasks INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    risk_score FLOAT DEFAULT 0.0,
    risk_level VARCHAR(20) DEFAULT 'none',
    tools_used TEXT[] DEFAULT ARRAY[]::TEXT[],
    llm_calls INTEGER DEFAULT 0,
    duration_seconds FLOAT DEFAULT 0.0,
    report TEXT,
    error TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scan_history_user ON scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_status ON scan_history(status);
CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
"""


async def init_schema(pg_pool):
    """Create tables if they don't exist."""
    if not pg_pool:
        logger.warning("⚠️ No PostgreSQL pool — skipping schema init")
        return False
    
    try:
        async with pg_pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)
        logger.info("✅ Database schema initialized")
        return True
    except Exception as e:
        logger.error(f"❌ Schema initialization failed: {e}")
        return False
