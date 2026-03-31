# src/core/schema.py

"""
Database schema — auto-creates tables on startup.
Includes: users, api_keys, scan_history, findings.
"""

from src.utils.logging import logger
import hashlib


SCHEMA_SQL = """
-- Users
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

-- API keys
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

-- Scan history
CREATE TABLE IF NOT EXISTS scan_history (
    id SERIAL PRIMARY KEY,
    process_id VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(64) NOT NULL,
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

-- Findings (individual findings linked to scans)
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    finding_id VARCHAR(64) UNIQUE NOT NULL,
    process_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'info',
    source VARCHAR(50),
    port INTEGER,
    protocol VARCHAR(10),
    service VARCHAR(100),
    version VARCHAR(200),
    state VARCHAR(20),
    finding TEXT,
    template VARCHAR(200),
    path VARCHAR(500),
    status_code INTEGER,
    risk_score FLOAT DEFAULT 0.0,
    validated BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    impact TEXT,
    raw_data JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scan_history_user ON scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_status ON scan_history(status);
CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_history_target ON scan_history(target);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_findings_process ON findings(process_id);
CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_port ON findings(port);
"""

# Dev user — auto-created so dev mode scans can save to DB
DEV_USER_SQL = """
INSERT INTO users (user_id, email, username, password_hash, role, tenant_id)
VALUES ('dev_user_123', 'dev@example.com', 'dev', $1, 'admin', 'default')
ON CONFLICT (user_id) DO NOTHING;
"""


async def init_schema(pg_pool):
    """Create tables and seed dev user."""
    if not pg_pool:
        logger.warning("⚠️ No PostgreSQL pool — skipping schema init")
        return False

    try:
        async with pg_pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)

            # Seed dev user
            dev_hash = hashlib.sha256(b"dev_password").hexdigest()
            await conn.execute(DEV_USER_SQL, dev_hash)

        logger.info("✅ Database schema initialized (tables + dev user)")
        return True
    except Exception as e:
        logger.error(f"❌ Schema initialization failed: {e}")
        return False
