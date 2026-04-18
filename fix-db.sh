#!/bin/bash
# fix-db.sh — Wipe old volumes and reinitialise with new passwords
# Run from Enterprise-Security-Orchestrator directory

set -e
cd "$(dirname "$0")"

echo "🛑 Stopping containers..."
docker compose down

echo "🗑  Removing old volumes..."
docker volume rm \
    enterprise-security-orchestrator_postgres_data \
    enterprise-security-orchestrator_redis_data \
    enterprise-security-orchestrator_rabbitmq_data \
    2>/dev/null && echo "  Volumes removed" || echo "  (volumes not found — OK)"

echo "🚀 Starting fresh..."
docker compose up -d postgres redis rabbitmq

echo "⏳ Waiting 15s for services to be healthy..."
sleep 15

echo "🔍 Container status:"
docker compose ps

echo ""
echo "🗄  Initialising database schema..."
./venv/bin/python3 - << 'PYEOF'
import asyncio
from src.core.database import db_manager
from src.core.schema import init_schema

async def main():
    await db_manager.initialize()
    if db_manager.pg_pool:
        await init_schema(db_manager.pg_pool)
        print("✅ Schema created — tables, tiers, and dev user ready")
    else:
        print("❌ PostgreSQL still not connecting — check POSTGRES_PASSWORD in .env")
        print("   Run: docker compose logs postgres")

asyncio.run(main())
PYEOF

echo ""
echo "✅ Done. Run: make dev"
