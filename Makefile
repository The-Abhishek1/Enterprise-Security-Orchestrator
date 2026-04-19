.PHONY: setup dev build clean infra tools db-init db-reset db-check db-shell db-upgrade-user help

help: ## Show all commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Setup ──────────────────────────────────────────────────────────

setup: infra venv tools db-init ## Full first-time setup
	@echo "\n✅ Setup complete! Run: make dev"

venv: ## Create Python venv + install deps
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
	@echo "✅ venv ready"

infra: ## Start PostgreSQL, Redis, RabbitMQ via Docker
	@if [ ! -f .env ]; then echo "❌ .env not found — copy .env.example and fill in values" && exit 1; fi
	docker compose up -d postgres redis rabbitmq
	@echo "Waiting for services..."
	@sleep 10
	@echo "✅ Infrastructure ready"

tools: ## Build all 7 security tool Docker images
	bash build_workers.sh
	@echo "✅ Tool images built"

# ── Development ────────────────────────────────────────────────────

dev: ## Run backend in dev mode (hot reload)
	./venv/bin/uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload

dev-log: ## Run with structured JSON logging
	./venv/bin/uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload --log-config config/logging.json

# ── Docker (production) ────────────────────────────────────────────

build: ## Build backend Docker image
	docker compose build api
	bash build_workers.sh
	@echo "✅ All images built"

up: ## Start full stack in Docker
	@if [ ! -f .env ]; then echo "❌ .env not found" && exit 1; fi
	docker compose up -d
	@echo "✅ ESO running at http://localhost:8000"

down: ## Stop all containers
	docker compose down

restart: ## Restart just the API container
	docker compose restart api

logs: ## Tail API logs
	docker compose logs -f api

logs-all: ## Tail all service logs
	docker compose logs -f

ps: ## Show container status
	docker compose ps

# ── Database ───────────────────────────────────────────────────────

db-init: ## Create all ESO tables + apply migrations (safe to re-run)
	@./venv/bin/python3 scripts/db_init.py

db-reset: ## ⚠️  Drop ALL tables (irreversible)
	@read -p "Type 'yes' to drop all tables: " confirm; \
		[ "$$confirm" = "yes" ] || (echo "Aborted" && exit 1)
	docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c "\
		DROP TABLE IF EXISTS payments, ai_chats, finding_comments, team_members, teams, \
		scheduled_scans, scan_templates, target_rules, audit_logs, \
		findings, scan_history, api_keys, tier_config, users CASCADE;"
	@echo "Tables dropped. Run: make db-init"

db-check: ## Show tables, tiers, and users
	@echo "\n=== Tables ==="
	@docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c "\dt"
	@echo "\n=== Tier Config ==="
	@docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c \
		"SELECT tier, scans_per_day, max_concurrent, ai_analysis_enabled, pdf_reports_enabled FROM tier_config ORDER BY scans_per_day;"
	@echo "\n=== Users ==="
	@docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c \
		"SELECT user_id, username, email, role, tier, scans_today, total_scans FROM users;"

db-shell: ## Open PostgreSQL interactive shell
	docker exec -it $$(docker compose ps -q postgres) psql -U eso -d orchestrator

db-backup: ## Backup database to ./backups/
	@mkdir -p backups
	docker exec $$(docker compose ps -q postgres) pg_dump -U eso orchestrator \
		> backups/eso_$$(date +%Y%m%d_%H%M%S).sql
	@echo "✅ Backup saved to backups/"

db-upgrade-user: ## Upgrade a user tier: make db-upgrade-user USER=user_xxx TIER=pro
	@[ "$(USER)" ] || (echo "Usage: make db-upgrade-user USER=user_id TIER=pro|enterprise|admin" && exit 1)
	@[ "$(TIER)" ] || (echo "Usage: make db-upgrade-user USER=user_id TIER=pro|enterprise|admin" && exit 1)
	docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c \
		"UPDATE users SET tier='$(TIER)', updated_at=NOW() WHERE user_id='$(USER)' RETURNING user_id, username, tier;"
	@echo "✅ Done"

# ── Cleanup ────────────────────────────────────────────────────────

clean: ## Remove venv, caches
	rm -rf venv
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleaned"

clean-docker: ## Remove all ESO containers, volumes, images
	@read -p "Remove all ESO Docker data? (yes/no): " c; \
		[ "$$c" = "yes" ] || (echo "Aborted" && exit 1)
	docker compose down -v --remove-orphans
	bash cleanup_workers.sh 2>/dev/null || true
	@echo "✅ Docker data removed"

# ── Secrets ────────────────────────────────────────────────────────

gen-secrets: ## Generate new strong secrets for .env
	@echo "# Paste these into your .env file:"
	@echo "JWT_SECRET_KEY=$$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')"
	@echo "POSTGRES_PASSWORD=$$(python3 -c 'import secrets,string; chars=string.ascii_letters+string.digits+\"!@#\$\"; print(\"\".join(secrets.choice(chars) for _ in range(32)))')"
	@echo "REDIS_PASSWORD=$$(python3 -c 'import secrets,string; chars=string.ascii_letters+string.digits; print(\"\".join(secrets.choice(chars) for _ in range(24)))')"
	@echo "RABBITMQ_PASSWORD=$$(python3 -c 'import secrets,string; chars=string.ascii_letters+string.digits; print(\"\".join(secrets.choice(chars) for _ in range(24)))')"
