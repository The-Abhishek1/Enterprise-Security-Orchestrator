#!/usr/bin/env python3
"""
db_init.py — ESO PostgreSQL database initialiser
Run from ESO project root: ./venv/bin/python3 scripts/db_init.py
"""
import asyncio, os, sys

# Add project root to Python path so 'src' is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def load_env(path='.env'):
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"\''))
    except FileNotFoundError:
        pass

load_env('.env')

async def main():
    print('╔══════════════════════════════════════════╗')
    print('║       ESO Database Init Tool             ║')
    print('╚══════════════════════════════════════════╝')
    print('\n📦 ESO PostgreSQL (Docker)')
    print('─' * 40)

    try:
        from src.core.database import db_manager
        from src.core.schema   import init_schema

        await db_manager.initialize()

        if not db_manager.pg_pool:
            print('  ✗ Cannot connect to PostgreSQL')
            print('  → Run: make infra  (starts Docker services)')
            return

        # Run full schema (CREATE TABLE IF NOT EXISTS — safe on existing DBs)
        await init_schema(db_manager.pg_pool)
        print('  ✓ Full schema applied')

        # Idempotent ALTER TABLE — adds any columns missing from older DBs
        ALTERS = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token   TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires TIMESTAMP",
            """CREATE TABLE IF NOT EXISTS payments (
                id         SERIAL PRIMARY KEY,
                payment_id TEXT UNIQUE NOT NULL,
                order_id   TEXT NOT NULL,
                user_id    TEXT NOT NULL,
                tier       TEXT NOT NULL,
                amount     INTEGER NOT NULL,
                status     TEXT NOT NULL DEFAULT 'captured',
                paid_at    TIMESTAMP DEFAULT NOW(),
                created_at TIMESTAMP DEFAULT NOW()
            )""",
        ]

        async with db_manager.pg_pool.acquire() as conn:
            for stmt in ALTERS:
                try:
                    await conn.execute(stmt)
                except Exception as e:
                    if 'already exists' not in str(e).lower():
                        print(f'  ⚠  {str(e)[:80]}')

        print('  ✓ Column migrations applied')

        # Verify
        async with db_manager.pg_pool.acquire() as conn:
            tables = await conn.fetch(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
            )
            # Check reset_token exists
            col = await conn.fetchrow(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='users' AND column_name='reset_token'"
            )

        names = [t['tablename'] for t in tables]
        for t in ['users', 'tier_config', 'scan_history', 'findings', 'payments']:
            print(f'  {"✓" if t in names else "✗ MISSING"} {t}')
        print(f'  {"✓" if col else "✗ MISSING"} users.reset_token column')

        await db_manager.close()
        print('\n  ✅ ESO database ready')

    except ModuleNotFoundError as e:
        print(f'  ✗ Import error: {e}')
        print('  → Make sure you run from the ESO project root:')
        print('     cd ~/Projects/Enterprise-Security-Orchestrator')
        print('     ./venv/bin/python3 scripts/db_init.py')
    except Exception as e:
        print(f'  ✗ Failed: {e}')

asyncio.run(main())
