.PHONY: setup dev build clean infra tools frontend help

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ===== Setup =====

setup: infra venv tools ## Full setup — infra + venv + tools
	@echo "\n✅ Setup complete! Run: make dev"

venv: ## Create Python venv and install deps
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
	@echo "✅ Python venv ready"

infra: ## Start PostgreSQL, Redis, RabbitMQ
	docker compose up -d postgres redis rabbitmq
	@echo "Waiting for services..."
	@sleep 5
	@echo "✅ Infrastructure ready"

tools: ## Build all security tool Docker images
	bash build_workers.sh
	@echo "✅ Tool images built"

# ===== Development =====

dev: ## Run backend (dev mode with reload)
	./venv/bin/uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload

frontend-install: ## Install frontend deps
	cd eso-frontend && npm install

frontend: ## Run frontend (dev mode)
	cd eso-frontend && npm run dev

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

db-reset: ## Drop and recreate all tables
	docker exec -it $$(docker compose ps -q postgres) psql -U eso -d orchestrator -c "DROP TABLE IF EXISTS findings, api_keys, scan_history, users, audit_logs, target_rules, scan_templates, scheduled_scans, teams, team_members, finding_comments, ai_chats CASCADE;"
	@echo "✅ Tables dropped — restart server to recreate"

db-shell: ## Open PostgreSQL shell
	docker exec -it $$(docker compose ps -q postgres) psql -U eso -d orchestrator

# ===== Cleanup =====

clean: ## Remove venv, node_modules, __pycache__
	rm -rf venv eso-frontend/node_modules eso-frontend/.next
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleaned"
