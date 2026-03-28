# Contributing to Enterprise Security Orchestrator

Thanks for your interest in contributing! This guide will help you get started.

## Ways to Contribute

### 🔧 Add a New Security Tool
The easiest way to contribute — each tool needs just 3 files:
1. `docker/workers/toolname/Dockerfile`
2. `config/tools/toolname.yaml`
3. Parser function in `src/engine/result_parser.py`

See the README "Adding New Tools" section for the template.

**Tools we'd love to see added:**
- amass (subdomain enumeration)
- subfinder (subdomain discovery)
- httpx (HTTP probing)
- dirsearch (directory scanner)
- wpscan (WordPress scanner)
- testssl.sh (SSL/TLS testing)
- feroxbuster (recursive content discovery)
- dnsrecon (DNS enumeration)

### 📊 Improve Result Parsers
Our parsers convert raw tool output into structured findings. They can always be more accurate. Look at `src/engine/result_parser.py`.

### 📄 Add Output Formats
Currently we support JSON API + PDF. We'd like:
- SARIF (Static Analysis Results Interchange Format)
- HTML report
- CSV/Excel export
- DefectDojo integration

### 🧪 Write Tests
We need tests for:
- Result parsers (unit tests with sample tool output)
- Risk engine scoring
- Target validator
- API endpoints

### 🐛 Fix Bugs
Check the Issues tab for bugs. Look for the `good-first-issue` label.

## Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/enterprise-security-orchestrator.git
cd enterprise-security-orchestrator

# Create virtual env
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Copy config
cp .env.example .env
# Edit .env with your OPENAI_API_KEY

# Start infrastructure
docker compose up -d postgres redis rabbitmq

# Build tool images
bash build_workers.sh

# Run dev server
uvicorn src.api.app:app --reload
```

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Test your changes locally
4. Update documentation if needed
5. Submit a PR with a clear description

### PR Title Format
```
feat: add amass tool for subdomain enumeration
fix: gobuster parser not matching v3.6 output
docs: add API authentication examples
refactor: simplify execution controller
```

## Code Style

- Python 3.11+
- Use type hints
- Keep functions focused and small
- Add logging with the project logger: `from src.utils.logging import logger`
- Follow existing patterns in the codebase

## Project Structure

```
src/
  api/            # FastAPI routes, middleware, models
  engine/         # Execution controller, parsers, risk engine, LLM agents
  agents/         # Planner, verifier
  tools/          # Tool registry, router, worker management
  workers/        # Docker container management
  services/       # User service, PDF reports, webhooks
  core/           # Config, database, schema
  models/         # DAG, execution models
  memory/         # Vector store, memory service
config/
  tools/          # YAML configs for each tool
docker/
  workers/        # Dockerfiles for each tool
```

## Questions?

Open an issue with the `question` label, or start a discussion in the Discussions tab.
