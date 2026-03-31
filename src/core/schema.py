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

-- Audit logs (persisted to DB)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    audit_id VARCHAR(64) UNIQUE NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    action VARCHAR(200) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'default',
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB,
    status VARCHAR(20) DEFAULT 'success',
    error TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Target rules (allowlist/denylist per tenant)
CREATE TABLE IF NOT EXISTS target_rules (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) DEFAULT 'default',
    pattern VARCHAR(500) NOT NULL,
    rule_type VARCHAR(10) NOT NULL CHECK (rule_type IN ('allow', 'deny')),
    reason TEXT,
    created_by VARCHAR(64),
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
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_target_rules_tenant ON target_rules(tenant_id);

-- Scan templates (reusable scan configs)
CREATE TABLE IF NOT EXISTS scan_templates (
    id SERIAL PRIMARY KEY,
    template_id VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'default',
    name VARCHAR(200) NOT NULL,
    description TEXT,
    target VARCHAR(500) NOT NULL,
    goal TEXT NOT NULL,
    parameters JSONB DEFAULT '{}',
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Scheduled scans (cron-like recurring scans)
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id SERIAL PRIMARY KEY,
    schedule_id VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'default',
    template_id VARCHAR(64) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    last_process_id VARCHAR(64),
    run_count INTEGER DEFAULT 0,
    max_runs INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_templates_user ON scan_templates(user_id);
CREATE INDEX IF NOT EXISTS idx_schedules_user ON scheduled_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_schedules_next ON scheduled_scans(next_run_at);
CREATE INDEX IF NOT EXISTS idx_schedules_active ON scheduled_scans(is_active);

-- Teams (collaboration workspaces)
CREATE TABLE IF NOT EXISTS teams (
    id SERIAL PRIMARY KEY,
    team_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    owner_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'default',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Team members
CREATE TABLE IF NOT EXISTS team_members (
    id SERIAL PRIMARY KEY,
    team_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    role VARCHAR(20) DEFAULT 'member',
    invited_by VARCHAR(64),
    joined_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(team_id, user_id)
);

-- Finding comments (collaboration on findings)
CREATE TABLE IF NOT EXISTS finding_comments (
    id SERIAL PRIMARY KEY,
    comment_id VARCHAR(64) UNIQUE NOT NULL,
    finding_id VARCHAR(64) NOT NULL,
    process_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    username VARCHAR(100),
    content TEXT NOT NULL,
    comment_type VARCHAR(20) DEFAULT 'manual',
    created_at TIMESTAMP DEFAULT NOW()
);

-- AI chat history per finding
CREATE TABLE IF NOT EXISTS ai_chats (
    id SERIAL PRIMARY KEY,
    chat_id VARCHAR(64) UNIQUE NOT NULL,
    finding_id VARCHAR(64),
    process_id VARCHAR(64),
    user_id VARCHAR(64) NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    chat_type VARCHAR(30) DEFAULT 'explain',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_teams_owner ON teams(owner_id);
CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_comments_finding ON finding_comments(finding_id);
CREATE INDEX IF NOT EXISTS idx_comments_process ON finding_comments(process_id);
CREATE INDEX IF NOT EXISTS idx_ai_chats_finding ON ai_chats(finding_id);
CREATE INDEX IF NOT EXISTS idx_ai_chats_user ON ai_chats(user_id);
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
