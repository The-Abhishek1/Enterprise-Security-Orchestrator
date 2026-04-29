#!/usr/bin/env python3
"""
ESO Database Init — single source of truth.
Creates all tables, seeds tiers, creates dev user.
Safe to re-run — uses IF NOT EXISTS + ADD COLUMN IF NOT EXISTS.

Usage:
    python3 scripts/db_init.py
    make db-init
"""
import asyncio
import asyncpg
import hashlib
import os
import sys


def load_env():
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, val = line.partition('=')
            os.environ.setdefault(key.strip(), val.strip())

load_env()

DSN = os.environ.get('POSTGRES_DSN', 'postgresql://eso:eso_secret@localhost:5432/orchestrator')

# ── Complete schema — every table the application needs ──────────────────────
SCHEMA_SQL = """
-- ═══════════════════════════════════════════════
-- USERS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS users (
    id                  SERIAL PRIMARY KEY,
    user_id             VARCHAR(64)  UNIQUE NOT NULL,
    email               VARCHAR(255) UNIQUE NOT NULL,
    username            VARCHAR(100) UNIQUE NOT NULL,
    password_hash       VARCHAR(255) NOT NULL,
    role                VARCHAR(20)  DEFAULT 'user',
    tier                VARCHAR(20)  DEFAULT 'free',
    tenant_id           VARCHAR(64)  DEFAULT 'default',
    is_active           BOOLEAN      DEFAULT TRUE,
    is_verified         BOOLEAN      DEFAULT FALSE,
    reset_token         VARCHAR(255),
    reset_token_expires TIMESTAMP,
    scans_today         INTEGER      DEFAULT 0,
    scans_today_reset   TIMESTAMP    DEFAULT NOW(),
    total_scans         INTEGER      DEFAULT 0,
    created_at          TIMESTAMP    DEFAULT NOW(),
    updated_at          TIMESTAMP    DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- TIER CONFIG
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS tier_config (
    id                      SERIAL PRIMARY KEY,
    tier                    VARCHAR(20) UNIQUE NOT NULL,
    scans_per_day           INTEGER     NOT NULL DEFAULT 3,
    max_concurrent          INTEGER     NOT NULL DEFAULT 1,
    allowed_tools           TEXT[]      DEFAULT ARRAY['nmap'],
    max_scan_duration       INTEGER     DEFAULT 300,
    proposals_enabled       BOOLEAN     DEFAULT FALSE,
    scheduling_enabled      BOOLEAN     DEFAULT FALSE,
    teams_enabled           BOOLEAN     DEFAULT FALSE,
    pdf_reports_enabled     BOOLEAN     DEFAULT FALSE,
    ai_analysis_enabled     BOOLEAN     DEFAULT FALSE,
    api_access_enabled      BOOLEAN     DEFAULT FALSE,
    attack_surface_enabled  BOOLEAN     DEFAULT FALSE,
    created_at              TIMESTAMP   DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- API KEYS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS api_keys (
    id           SERIAL PRIMARY KEY,
    key_id       VARCHAR(64)  UNIQUE NOT NULL,
    key_hash     VARCHAR(255) NOT NULL,
    key_prefix   VARCHAR(12)  NOT NULL,
    user_id      VARCHAR(64)  NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name         VARCHAR(100) NOT NULL,
    permissions  TEXT[]       DEFAULT ARRAY['read', 'execute'],
    is_active    BOOLEAN      DEFAULT TRUE,
    last_used_at TIMESTAMP,
    expires_at   TIMESTAMP,
    created_at   TIMESTAMP    DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- SCAN HISTORY
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scan_history (
    id               SERIAL PRIMARY KEY,
    process_id       VARCHAR(64)  UNIQUE NOT NULL,
    user_id          VARCHAR(64)  NOT NULL,
    tenant_id        VARCHAR(64)  DEFAULT 'default',
    goal             TEXT         NOT NULL,
    target           VARCHAR(500),
    status           VARCHAR(20)  NOT NULL,
    total_tasks      INTEGER      DEFAULT 0,
    completed_tasks  INTEGER      DEFAULT 0,
    failed_tasks     INTEGER      DEFAULT 0,
    dynamic_tasks    INTEGER      DEFAULT 0,
    findings_count   INTEGER      DEFAULT 0,
    risk_score       FLOAT        DEFAULT 0.0,
    risk_level       VARCHAR(20)  DEFAULT 'none',
    tools_used       TEXT[]       DEFAULT ARRAY[]::TEXT[],
    llm_calls        INTEGER      DEFAULT 0,
    duration_seconds FLOAT        DEFAULT 0.0,
    report           TEXT,
    error            TEXT,
    created_at       TIMESTAMP    DEFAULT NOW(),
    started_at       TIMESTAMP,
    completed_at     TIMESTAMP
);

-- ═══════════════════════════════════════════════
-- FINDINGS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS findings (
    id             SERIAL PRIMARY KEY,
    finding_id     VARCHAR(64)  UNIQUE NOT NULL,
    process_id     VARCHAR(64)  NOT NULL,
    user_id        VARCHAR(64)  NOT NULL,
    type           VARCHAR(50)  NOT NULL,
    severity       VARCHAR(20)  DEFAULT 'info',
    source         VARCHAR(50),
    port           INTEGER,
    protocol       VARCHAR(10),
    service        VARCHAR(100),
    version        VARCHAR(200),
    state          VARCHAR(20),
    finding        TEXT,
    template       VARCHAR(200),
    path           VARCHAR(500),
    status_code    INTEGER,
    risk_score     FLOAT        DEFAULT 0.0,
    validated      BOOLEAN      DEFAULT FALSE,
    false_positive BOOLEAN      DEFAULT FALSE,
    impact         TEXT,
    raw_data       JSONB,
    target         VARCHAR(500),
    created_at     TIMESTAMP    DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- AUDIT LOGS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS audit_logs (
    id            SERIAL PRIMARY KEY,
    audit_id      VARCHAR(64)  UNIQUE NOT NULL,
    timestamp     TIMESTAMP    DEFAULT NOW(),
    action        VARCHAR(200) NOT NULL,
    user_id       VARCHAR(64)  NOT NULL,
    tenant_id     VARCHAR(64)  DEFAULT 'default',
    resource_type VARCHAR(50),
    resource_id   VARCHAR(100),
    details       JSONB,
    status        VARCHAR(20)  DEFAULT 'success',
    error         TEXT,
    ip_address    VARCHAR(45),
    user_agent    TEXT
);

-- ═══════════════════════════════════════════════
-- TARGET RULES (allow / deny list)
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS target_rules (
    id         SERIAL PRIMARY KEY,
    tenant_id  VARCHAR(64)  DEFAULT 'default',
    pattern    VARCHAR(500) NOT NULL,
    rule_type  VARCHAR(10)  NOT NULL CHECK (rule_type IN ('allow', 'deny')),
    reason     TEXT,
    created_by VARCHAR(64),
    created_at TIMESTAMP    DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- SCAN TEMPLATES  (required by schedule_service)
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scan_templates (
    id          SERIAL PRIMARY KEY,
    template_id VARCHAR(64)  UNIQUE NOT NULL,
    user_id     VARCHAR(64)  NOT NULL,
    tenant_id   VARCHAR(64)  DEFAULT 'default',
    name        VARCHAR(200) NOT NULL,
    description TEXT,
    target      VARCHAR(500) NOT NULL,
    goal        TEXT         NOT NULL,
    parameters  TEXT         DEFAULT '{}',
    tags        TEXT[]       DEFAULT ARRAY[]::TEXT[],
    is_active   BOOLEAN      DEFAULT TRUE,
    created_at  TIMESTAMP    DEFAULT NOW(),
    updated_at  TIMESTAMP    DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- SCHEDULED SCANS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id              SERIAL PRIMARY KEY,
    schedule_id     VARCHAR(64)  UNIQUE NOT NULL,
    template_id     VARCHAR(64)  NOT NULL REFERENCES scan_templates(template_id) ON DELETE CASCADE,
    user_id         VARCHAR(64)  NOT NULL,
    tenant_id       VARCHAR(64)  DEFAULT 'default',
    cron_expression VARCHAR(100) NOT NULL,
    is_active       BOOLEAN      DEFAULT TRUE,
    run_count       INTEGER      DEFAULT 0,
    max_runs        INTEGER,
    last_run_at     TIMESTAMP,
    next_run_at     TIMESTAMP,
    created_at      TIMESTAMP    DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- TEAMS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS teams (
    id          SERIAL PRIMARY KEY,
    team_id     VARCHAR(64)  UNIQUE NOT NULL,
    name        VARCHAR(200) NOT NULL,
    description TEXT,
    owner_id    VARCHAR(64)  NOT NULL,
    tenant_id   VARCHAR(64)  DEFAULT 'default',
    created_at  TIMESTAMP    DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS team_members (
    id         SERIAL PRIMARY KEY,
    team_id    VARCHAR(64) NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
    user_id    VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role       VARCHAR(20) DEFAULT 'member',
    invited_by VARCHAR(64),
    joined_at  TIMESTAMP   DEFAULT NOW(),
    UNIQUE(team_id, user_id)
);

-- ═══════════════════════════════════════════════
-- FINDING COMMENTS & AI CHATS
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS finding_comments (
    id           SERIAL PRIMARY KEY,
    comment_id   VARCHAR(64) UNIQUE NOT NULL,
    finding_id   VARCHAR(64) NOT NULL,
    process_id   VARCHAR(64) NOT NULL,
    user_id      VARCHAR(64) NOT NULL,
    username     VARCHAR(100),
    content      TEXT        NOT NULL,
    comment_type VARCHAR(20) DEFAULT 'manual',
    created_at   TIMESTAMP   DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_chats (
    id         SERIAL PRIMARY KEY,
    chat_id    VARCHAR(64) UNIQUE NOT NULL,
    finding_id VARCHAR(64),
    process_id VARCHAR(64),
    user_id    VARCHAR(64) NOT NULL,
    question   TEXT        NOT NULL,
    answer     TEXT        NOT NULL,
    chat_type  VARCHAR(30) DEFAULT 'explain',
    created_at TIMESTAMP   DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- CVE DATABASE
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS cves (
    id           SERIAL PRIMARY KEY,
    cve_id       VARCHAR(30)  UNIQUE NOT NULL,
    description  TEXT,
    cvss_score   FLOAT        DEFAULT 0.0,
    cvss_vector  VARCHAR(100),
    severity     VARCHAR(20)  DEFAULT 'unknown',
    published_at TIMESTAMP,
    modified_at  TIMESTAMP,
    cve_refs     TEXT[],
    cpe_list     TEXT[],
    has_exploit  BOOLEAN      DEFAULT FALSE,
    exploit_ids  TEXT[],
    scan_count   INTEGER      DEFAULT 0,
    last_seen_at TIMESTAMP,
    created_at   TIMESTAMP    DEFAULT NOW(),
    updated_at   TIMESTAMP    DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_cve_matches (
    id         SERIAL PRIMARY KEY,
    process_id VARCHAR(64) NOT NULL,
    cve_id     VARCHAR(30) NOT NULL,
    user_id    VARCHAR(64),
    target     VARCHAR(500),
    matched_at TIMESTAMP   DEFAULT NOW(),
    UNIQUE(process_id, cve_id)
);

-- ═══════════════════════════════════════════════
-- PAYMENTS (Razorpay)
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS payments (
    id         SERIAL PRIMARY KEY,
    payment_id TEXT UNIQUE NOT NULL,
    order_id   TEXT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    tier       TEXT NOT NULL,
    amount     INTEGER  NOT NULL,
    status     TEXT     NOT NULL DEFAULT 'captured',
    paid_at    TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- ═══════════════════════════════════════════════
-- SITE SETTINGS (payment mode, feature flags)
-- ═══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS site_settings (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT         NOT NULL,
    updated_at TIMESTAMP    DEFAULT NOW()
);

INSERT INTO site_settings (key, value)
VALUES ('payment_mode', 'razorpay')
ON CONFLICT (key) DO NOTHING;

-- ═══════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_scan_history_user    ON scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_status  ON scan_history(status);
CREATE INDEX IF NOT EXISTS idx_findings_user        ON findings(user_id);
CREATE INDEX IF NOT EXISTS idx_findings_process     ON findings(process_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_audit_user           ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action         ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_teams_owner          ON teams(owner_id);
CREATE INDEX IF NOT EXISTS idx_team_members_team    ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user    ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_ai_chats_finding     ON ai_chats(finding_id);
CREATE INDEX IF NOT EXISTS idx_ai_chats_user        ON ai_chats(user_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity        ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_score      ON cves(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_scan_cve_process     ON scan_cve_matches(process_id);
CREATE INDEX IF NOT EXISTS idx_scan_cve_id          ON scan_cve_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_payments_user        ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_paid        ON payments(paid_at DESC);
"""

# ── ADD COLUMN IF NOT EXISTS — safe to run on existing DB ───────────────────
MIGRATION_SQL = """
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS reset_token         VARCHAR(255),
    ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMP;

ALTER TABLE scan_templates
    ADD COLUMN IF NOT EXISTS parameters  TEXT    DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS tags        TEXT[]  DEFAULT ARRAY[]::TEXT[],
    ADD COLUMN IF NOT EXISTS is_active   BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMP DEFAULT NOW();

ALTER TABLE team_members
    ADD COLUMN IF NOT EXISTS invited_by VARCHAR(64);
"""

# ── Tier seed ────────────────────────────────────────────────────────────────
TIER_SQL = """
INSERT INTO tier_config (
    tier, scans_per_day, max_concurrent, allowed_tools, max_scan_duration,
    proposals_enabled, scheduling_enabled, teams_enabled, pdf_reports_enabled,
    ai_analysis_enabled, api_access_enabled, attack_surface_enabled
) VALUES
    ('free',       3,    1,  ARRAY['nmap'],                                                      300,  false, false, false, false, false, false, false),
    ('pro',        20,   2,  ARRAY['nmap','nuclei','whatweb','nikto','gobuster'],                 900,  true,  true,  false, true,  true,  true,  true),
    ('enterprise', 100,  5,  ARRAY['nmap','nuclei','whatweb','nikto','gobuster','ffuf','sqlmap'], 1800, true,  true,  true,  true,  true,  true,  true),
    ('admin',      9999, 10, ARRAY['nmap','nuclei','whatweb','nikto','gobuster','ffuf','sqlmap'], 3600, true,  true,  true,  true,  true,  true,  true)
ON CONFLICT (tier) DO UPDATE SET
    scans_per_day          = EXCLUDED.scans_per_day,
    max_concurrent         = EXCLUDED.max_concurrent,
    allowed_tools          = EXCLUDED.allowed_tools,
    max_scan_duration      = EXCLUDED.max_scan_duration,
    proposals_enabled      = EXCLUDED.proposals_enabled,
    scheduling_enabled     = EXCLUDED.scheduling_enabled,
    teams_enabled          = EXCLUDED.teams_enabled,
    pdf_reports_enabled    = EXCLUDED.pdf_reports_enabled,
    ai_analysis_enabled    = EXCLUDED.ai_analysis_enabled,
    api_access_enabled     = EXCLUDED.api_access_enabled,
    attack_surface_enabled = EXCLUDED.attack_surface_enabled;
"""

DEV_USER_SQL = """
INSERT INTO users (user_id, email, username, password_hash, role, tier, tenant_id)
VALUES ('dev_user_123', 'dev@example.com', 'dev', $1, 'admin', 'admin', 'default')
ON CONFLICT (user_id) DO UPDATE SET
    role='admin', tier='admin',
    password_hash=EXCLUDED.password_hash,
    updated_at=NOW();
"""


async def main():
    host_part = DSN.split('@')[-1] if '@' in DSN else DSN
    print(f"🔌 Connecting to: {host_part}")
    try:
        conn = await asyncpg.connect(DSN)
    except Exception as e:
        print(f"❌ Cannot connect to PostgreSQL: {e}")
        print("   Make sure it's running: make infra")
        sys.exit(1)

    try:
        print("📐 Creating tables...")
        await conn.execute(SCHEMA_SQL)
        print("   ✓ All tables created")

        print("🔧 Applying column migrations...")
        await conn.execute(MIGRATION_SQL)
        print("   ✓ Column migrations applied")

        print("🎯 Seeding tier config...")
        await conn.execute(TIER_SQL)
        print("   ✓ Tiers seeded")

        print("👤 Seeding dev user...")
        try:
            import bcrypt
            dev_hash = bcrypt.hashpw(b"dev_password", bcrypt.gensalt()).decode()
        except ImportError:
            dev_hash = hashlib.sha256(b"dev_password").hexdigest()
        await conn.execute(DEV_USER_SQL, dev_hash)
        print("   ✓ dev@example.com / dev_password (admin tier)")

        # Summary
        tables = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        )
        tiers  = await conn.fetch(
            "SELECT tier, scans_per_day, max_concurrent, ai_analysis_enabled, proposals_enabled "
            "FROM tier_config ORDER BY scans_per_day"
        )

        print(f"\n📋 {len(tables)} tables: {', '.join(r['tablename'] for r in tables)}")
        print("\n🎯 Tier config:")
        for t in tiers:
            ai   = '✓ AI'        if t['ai_analysis_enabled'] else '✗ AI'
            prop = '✓ proposals' if t['proposals_enabled']   else '✗ proposals'
            print(f"   {t['tier']:12} {t['scans_per_day']:5} scans/day  "
                  f"{t['max_concurrent']} concurrent  {ai}  {prop}")

    except Exception as e:
        print(f"❌ Failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
    finally:
        await conn.close()

    print("\n✅ Database ready — start ESO with: make dev")


if __name__ == '__main__':
    asyncio.run(main())
