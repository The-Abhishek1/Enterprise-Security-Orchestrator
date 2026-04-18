"""
Database schema — full hardened version with tiers, scan quotas, feature flags.
"""
from src.utils.logging import logger
import hashlib

SCHEMA_SQL = """
-- ═══════════════════════════════════════════════
-- USERS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',         -- user | pro | enterprise | admin
    tier VARCHAR(20) DEFAULT 'free',         -- free | pro | enterprise | admin
    tenant_id VARCHAR(64) DEFAULT 'default',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    scans_today INTEGER DEFAULT 0,
    scans_today_reset TIMESTAMP DEFAULT NOW(),
    total_scans INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- TIER DEFINITIONS (what each tier can do)
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS tier_config (
    id SERIAL PRIMARY KEY,
    tier VARCHAR(20) UNIQUE NOT NULL,
    scans_per_day INTEGER NOT NULL DEFAULT 3,
    max_concurrent INTEGER NOT NULL DEFAULT 1,
    allowed_tools TEXT[] DEFAULT ARRAY['nmap'],
    max_scan_duration INTEGER DEFAULT 300,   -- seconds
    proposals_enabled BOOLEAN DEFAULT FALSE,
    scheduling_enabled BOOLEAN DEFAULT FALSE,
    teams_enabled BOOLEAN DEFAULT FALSE,
    pdf_reports_enabled BOOLEAN DEFAULT FALSE,
    ai_analysis_enabled BOOLEAN DEFAULT FALSE,
    api_access_enabled BOOLEAN DEFAULT FALSE,
    attack_surface_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- API KEYS
-- ═══════════════════════════════════════════════
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

-- ═══════════════════════════════════════════════
-- SCAN HISTORY
-- ═══════════════════════════════════════════════
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

-- ═══════════════════════════════════════════════
-- FINDINGS
-- ═══════════════════════════════════════════════
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
    target VARCHAR(500),
    created_at TIMESTAMP DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- AUDIT LOGS
-- ═══════════════════════════════════════════════
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

-- ═══════════════════════════════════════════════
-- TARGET RULES (allowlist / denylist)
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS target_rules (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) DEFAULT 'default',
    pattern VARCHAR(500) NOT NULL,
    rule_type VARCHAR(10) NOT NULL CHECK (rule_type IN ('allow', 'deny')),
    reason TEXT,
    created_by VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- SCHEDULES + TEMPLATES
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scan_templates (
    id SERIAL PRIMARY KEY,
    template_id VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'default',
    name VARCHAR(200) NOT NULL,
    description TEXT,
    target VARCHAR(500) NOT NULL,
    goal TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id SERIAL PRIMARY KEY,
    schedule_id VARCHAR(64) UNIQUE NOT NULL,
    template_id VARCHAR(64) NOT NULL REFERENCES scan_templates(template_id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'default',
    cron_expression VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    run_count INTEGER DEFAULT 0,
    max_runs INTEGER,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- TEAMS + MEMBERS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS teams (
    id SERIAL PRIMARY KEY,
    team_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    owner_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'default',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS team_members (
    id SERIAL PRIMARY KEY,
    team_id VARCHAR(64) NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member',
    joined_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(team_id, user_id)
);

-- ═══════════════════════════════════════════════
-- AI CHAT + FINDING COMMENTS
-- ═══════════════════════════════════════════════
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


-- ═══════════════════════════════════════════════
-- CVE DATABASE (synced from NVD / Xcloak)
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS cves (
    id           SERIAL PRIMARY KEY,
    cve_id       VARCHAR(30)  UNIQUE NOT NULL,   -- CVE-2024-12345
    description  TEXT,
    cvss_score   FLOAT        DEFAULT 0.0,
    cvss_vector  VARCHAR(100),
    severity     VARCHAR(20)  DEFAULT 'unknown', -- critical/high/medium/low
    published_at TIMESTAMP,
    modified_at  TIMESTAMP,
    "references" TEXT[],
    cpe_list     TEXT[],                         -- affected products
    -- Xcloak enrichment
    has_exploit  BOOLEAN      DEFAULT FALSE,
    exploit_ids  TEXT[],                         -- linked exploit IDs in Xcloak
    scan_count   INTEGER      DEFAULT 0,         -- how many times seen in scans
    last_seen_at TIMESTAMP,
    created_at   TIMESTAMP    DEFAULT NOW(),
    updated_at   TIMESTAMP    DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cves_severity   ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_last_seen  ON cves(last_seen_at DESC);

-- ═══════════════════════════════════════════════
-- CVE ↔ SCAN MAPPING (which scans found which CVEs)
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scan_cve_matches (
    id         SERIAL PRIMARY KEY,
    process_id VARCHAR(64) NOT NULL,
    cve_id     VARCHAR(30) NOT NULL,
    user_id    VARCHAR(64),
    target     VARCHAR(500),
    matched_at TIMESTAMP   DEFAULT NOW(),
    UNIQUE(process_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_cve_process ON scan_cve_matches(process_id);
CREATE INDEX IF NOT EXISTS idx_scan_cve_cve_id  ON scan_cve_matches(cve_id);

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

-- ═══════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_scan_history_user   ON scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_status ON scan_history(status);
CREATE INDEX IF NOT EXISTS idx_findings_user       ON findings(user_id);
CREATE INDEX IF NOT EXISTS idx_findings_process    ON findings(process_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_audit_user          ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action        ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_teams_owner         ON teams(owner_id);
CREATE INDEX IF NOT EXISTS idx_team_members_team   ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user   ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_ai_chats_finding    ON ai_chats(finding_id);
CREATE INDEX IF NOT EXISTS idx_ai_chats_user       ON ai_chats(user_id);

-- ── Payments table (Razorpay) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payments (
    id           SERIAL PRIMARY KEY,
    payment_id   TEXT UNIQUE NOT NULL,
    order_id     TEXT NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    tier         TEXT NOT NULL,
    amount       INTEGER NOT NULL,      -- in paise
    status       TEXT NOT NULL DEFAULT 'captured',
    paid_at      TIMESTAMP DEFAULT NOW(),
    created_at   TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_paid ON payments(paid_at DESC);
"""

# Default tier configs
TIER_SEED_SQL = """
INSERT INTO tier_config (tier, scans_per_day, max_concurrent, allowed_tools,
    max_scan_duration, proposals_enabled, scheduling_enabled, teams_enabled,
    pdf_reports_enabled, ai_analysis_enabled, api_access_enabled, attack_surface_enabled)
VALUES
    ('free',       3,   1, ARRAY['nmap'],                                        300,  false, false, false, false, false, false, false),
    ('pro',        20,  2, ARRAY['nmap','nuclei','whatweb','nikto','gobuster'],   900,  true,  true,  false, true,  true,  true,  true),
    ('enterprise', 100, 5, ARRAY['nmap','nuclei','whatweb','nikto','gobuster','ffuf','sqlmap'], 1800, true, true, true, true, true, true, true),
    ('admin',      9999,10,ARRAY['nmap','nuclei','whatweb','nikto','gobuster','ffuf','sqlmap'], 3600, true, true, true, true, true, true, true)
ON CONFLICT (tier) DO UPDATE SET
    scans_per_day = EXCLUDED.scans_per_day,
    max_concurrent = EXCLUDED.max_concurrent,
    allowed_tools = EXCLUDED.allowed_tools,
    max_scan_duration = EXCLUDED.max_scan_duration,
    proposals_enabled = EXCLUDED.proposals_enabled,
    scheduling_enabled = EXCLUDED.scheduling_enabled,
    teams_enabled = EXCLUDED.teams_enabled,
    pdf_reports_enabled = EXCLUDED.pdf_reports_enabled,
    ai_analysis_enabled = EXCLUDED.ai_analysis_enabled,
    api_access_enabled = EXCLUDED.api_access_enabled,
    attack_surface_enabled = EXCLUDED.attack_surface_enabled;
"""

DEV_USER_SQL = """
INSERT INTO users (user_id, email, username, password_hash, role, tier, tenant_id)
VALUES ('dev_user_123', 'dev@example.com', 'dev', $1, 'admin', 'admin', 'default')
ON CONFLICT (user_id) DO UPDATE
  SET role='admin', tier='admin', password_hash=EXCLUDED.password_hash, updated_at=NOW();
"""


def _make_dev_hash() -> str:
    """Hash dev_password with bcrypt if available, else sha256."""
    try:
        import bcrypt
        return bcrypt.hashpw(b"dev_password", bcrypt.gensalt()).decode()
    except ImportError:
        return hashlib.sha256(b"dev_password").hexdigest()


async def init_schema(pg_pool):
    if not pg_pool:
        logger.warning("⚠️ No PostgreSQL pool — skipping schema init")
        return False
    try:
        async with pg_pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)
            await conn.execute(TIER_SEED_SQL)
            dev_hash = _make_dev_hash()
            await conn.execute(DEV_USER_SQL, dev_hash)
        logger.info("✅ Database schema initialized (tables + tiers + dev user)")
        return True
    except Exception as e:
        logger.error(f"❌ Schema initialization failed: {e}")
        return False
