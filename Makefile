.PHONY: setup dev build clean infra tools frontend help db-init db-reset db-check db-shell db-upgrade-user

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ===== Setup =====

setup: infra venv tools db-init ## Full setup — infra + venv + tools + db
	@echo "\n✅ Setup complete! Run: make dev"

venv: ## Create Python venv and install deps
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
	@echo "✅ Python venv ready"

infra: ## Start PostgreSQL, Redis, RabbitMQ
	docker compose up -d postgres redis rabbitmq
	@echo "Waiting for services to be healthy..."
	@sleep 8
	@echo "✅ Infrastructure ready"

tools: ## Build all security tool Docker images
	bash build_workers.sh
	@echo "✅ Tool images built"

# ===== Development =====

dev: ## Run backend (dev mode with reload)
	./venv/bin/uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload


# ===== Docker (production) =====

build: ## Build all Docker images (backend + tools)
	docker compose build
	bash build_workers.sh
	@echo "✅ All images built"

up: ## Start everything in Docker
	docker compose up -d
	@echo "✅ ESO running at http://localhost:8000"
	@echo "   Frontend: http://localhost:3000"

down: ## Stop everything
	docker compose down

logs: ## Tail backend logs
	docker compose logs -f api

# ===== Database =====

db-init: ## Create all tables + seed tiers + dev user
	@echo "Initializing database..."
	@mkdir -p scripts
	@./venv/bin/python3 scripts/db_init.py

db-reset: ## Drop ALL tables (run db-init after to recreate)
	@echo "⚠️  Dropping all tables..."
	@docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c "\
		DROP TABLE IF EXISTS ai_chats, finding_comments, team_members, teams, \
		scheduled_scans, scan_templates, target_rules, audit_logs, \
		findings, scan_history, api_keys, tier_config, users CASCADE;"
	@echo "Tables dropped. Run: make db-init"

db-check: ## Verify tables, tiers, and users
	@echo "=== Tables ==="
	@docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c "\dt"
	@echo "\n=== Tier Config ==="
	@docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c \
		"SELECT tier, scans_per_day, max_concurrent, ai_analysis_enabled, proposals_enabled FROM tier_config ORDER BY scans_per_day;"
	@echo "\n=== Users ==="
	@docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c \
		"SELECT user_id, username, role, tier, scans_today, total_scans FROM users;"

db-shell: ## Open PostgreSQL shell
	docker exec -it $$(docker compose ps -q postgres) psql -U eso -d orchestrator

db-upgrade-user: ## Upgrade a user tier — usage: make db-upgrade-user USER=user_xxx TIER=pro
	@[ "$(USER)" ] || (echo "Usage: make db-upgrade-user USER=user_id TIER=pro|enterprise|admin" && exit 1)
	@[ "$(TIER)" ] || (echo "Usage: make db-upgrade-user USER=user_id TIER=pro|enterprise|admin" && exit 1)
	@docker exec $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c \
		"UPDATE users SET tier='$(TIER)', role='$(TIER)', updated_at=NOW() WHERE user_id='$(USER)' RETURNING user_id, username, tier;"
	@echo "✅ Done"

# ===== Cleanup =====

clean: ## Remove venv, node_modules, __pycache__
	rm -rf venv eso-frontend/node_modules eso-frontend/.next
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleaned"

workers-clean: ## Remove all ESO worker containers and networks
	bash cleanup_workers.sh
