# 🛡️ Enterprise Security Orchestrator (ESO)

**AI-powered penetration testing platform** — submit a target, get a professional pentest report.

An LLM plans the attack, executes security tools in Docker containers, analyzes results, proposes follow-up actions (with your approval), and generates a detailed report — all through a simple API.

---

## How It Works

```
User Goal: "Scan example.com for vulnerabilities"
    ↓
🧠 Planner (GPT-4) → Creates task DAG (nmap → nuclei)
    ↓
✅ Verifier → Validates plan structure
    ↓
🐳 Tool Executor → Runs tools in isolated Docker containers
    ↓
📊 Result Parser → Structures raw output into findings
    ↓
🧠 Analysis Agent (LLM) → Validates findings, removes false positives
    ↓
⚖️ Risk Engine → CVSS-like scoring, prioritization
    ↓
🤖 Task Proposer (LLM) → "Found HTTP on port 80 → run gobuster?"
    ↓
⏸️ User Approval → You decide what runs next
    ↓
📄 Report Generator (LLM) → Professional pentest report
    ↓
📥 PDF Export → Downloadable report
```

## Features

- **LLM-Powered Planning** — GPT-4 breaks down goals into executable tasks
- **7 Security Tools** — nmap, nuclei, gobuster, sqlmap, nikto, ffuf, whatweb
- **Docker Isolation** — each tool runs in its own container with network isolation
- **AI Analysis** — LLM validates findings, removes false positives, assesses risk
- **Human-in-the-Loop** — AI proposes tasks, you approve before execution
- **CVSS-like Risk Scoring** — automated severity assessment
- **PDF Reports** — downloadable professional pentest reports
- **Auth & API Keys** — JWT auth, API keys for automation
- **Scan History** — PostgreSQL-backed history with full reports
- **Webhook Notifications** — Slack, Discord, or generic HTTP webhooks
- **Target Validation** — allowlist/denylist prevents unauthorized scanning
- **Extensible** — add new tools with just a Dockerfile + YAML config

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- OpenAI API key

### 1. Clone & Configure
```bash
git clone https://github.com/yourusername/enterprise-security-orchestrator.git
cd enterprise-security-orchestrator
cp .env.example .env
# Edit .env — add your OPENAI_API_KEY
```

### 2. Start Infrastructure
```bash
docker compose up -d postgres redis rabbitmq
```

### 3. Build Tool Images
```bash
bash build_workers.sh
```

### 4. Install & Run
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Run a Scan
```bash
# Submit scan
curl -X POST http://localhost:8000/api/v1/hybrid/execute \
  -H "Content-Type: application/json" \
  -d '{"goal": "Scan scanme.nmap.org for open ports and vulnerabilities", "target": "scanme.nmap.org"}'

# Check proposals (after ~60s)
curl http://localhost:8000/api/v1/hybrid/proposals/{process_id}

# Approve tasks
curl -X POST http://localhost:8000/api/v1/hybrid/approve/{process_id} \
  -H "Content-Type: application/json" \
  -d '{"approved": ["Vulnerability Scanning", "Directory Brute-Force"]}'

# Get status + report
curl http://localhost:8000/api/v1/hybrid/status/{process_id}

# Download PDF report
curl -o report.pdf http://localhost:8000/api/v1/hybrid/report/{process_id}/pdf
```

## API Reference

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Create account |
| POST | `/api/v1/auth/login` | Get JWT tokens |
| POST | `/api/v1/auth/api-keys` | Create API key |
| GET | `/api/v1/auth/me` | Current user profile |

### Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/hybrid/execute` | Start a scan |
| GET | `/api/v1/hybrid/status/{id}` | Scan status + report |
| GET | `/api/v1/hybrid/proposals/{id}` | Pending task proposals |
| POST | `/api/v1/hybrid/approve/{id}` | Approve/reject tasks |
| GET | `/api/v1/hybrid/report/{id}/pdf` | Download PDF report |
| GET | `/api/v1/auth/scans` | Scan history |

### Auth Methods
```bash
# JWT Bearer token
curl -H "Authorization: Bearer <token>" ...

# API Key
curl -H "X-API-Key: eso_abc123..." ...
```

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   API Layer                        │
│  FastAPI + JWT Auth + Rate Limiting                │
├──────────────────────────────────────────────────┤
│              Hybrid Scheduler                      │
│  Planning → Verification → Execution Controller    │
├──────────────────────────────────────────────────┤
│            Execution Controller                    │
│  ┌─────────┐ ┌──────────┐ ┌─────────────┐        │
│  │  Tool    │ │  Result  │ │  Analysis   │        │
│  │ Executor │→│  Parser  │→│ Agent (LLM) │        │
│  └─────────┘ └──────────┘ └─────────────┘        │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐       │
│  │   Risk   │ │   Task   │ │   Report    │        │
│  │  Engine  │ │ Proposer │ │ Generator   │        │
│  └──────────┘ └──────────┘ └─────────────┘        │
├──────────────────────────────────────────────────┤
│               Docker Workers                       │
│  nmap │ nuclei │ gobuster │ nikto │ ffuf │ ...    │
├──────────────────────────────────────────────────┤
│            PostgreSQL │ Redis │ RabbitMQ            │
└──────────────────────────────────────────────────┘
```

## Adding New Tools

Adding a new security tool requires 3 files:

### 1. Dockerfile (`docker/workers/mytool/Dockerfile`)
```dockerfile
FROM alpine:3.19
LABEL eso.tool="true" \
      eso.tool.name="mytool" \
      eso.tool.version="1.0" \
      eso.tool.command="mytool" \
      eso.tool.capabilities="my_capability"
RUN apk add --no-cache mytool
ENTRYPOINT []
CMD ["sleep", "infinity"]
```

### 2. Config (`config/tools/mytool.yaml`)
```yaml
name: mytool
version: "1.0"
capabilities:
  - my_capability
image: eso-worker-mytool:latest
command: mytool
description: What this tool does
default_timeout: 300
```

### 3. Parser (add to `src/engine/result_parser.py`)
```python
def _parse_mytool(self, output: str, exit_code: int) -> List[Dict]:
    findings = []
    for line in output.split('\n'):
        # Parse your tool's output format
        findings.append({
            "type": "finding",
            "finding": line,
            "severity": "info",
            "source": "mytool"
        })
    return findings
```

Then build: `bash build_workers.sh --tool mytool`

The LLM planner and task proposer will automatically learn to use the new tool from its config description.

## Configuration

See `.env.example` for all configuration options. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | required | OpenAI API key for LLM |
| `OPENAI_MODEL` | gpt-4 | LLM model to use |
| `MAX_SCAN_DURATION` | 1800 | Max seconds per scan |
| `MAX_DYNAMIC_TASKS` | 3 | Max AI-proposed tasks |
| `ALLOWED_TARGETS` | empty | Comma-separated allowlist |
| `DENIED_TARGETS` | empty | Comma-separated denylist |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Good First Issues
- Add a new security tool (Dockerfile + config + parser)
- Improve result parsers for better accuracy
- Add output formats (JSON, HTML, SARIF)
- Write tests for existing components

### Development Setup
```bash
git clone https://github.com/yourusername/enterprise-security-orchestrator.git
cd enterprise-security-orchestrator
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Start infrastructure
docker compose up -d postgres redis rabbitmq
# Build tools
bash build_workers.sh
# Run dev server
uvicorn src.api.app:app --reload
```

## License

MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is designed for **authorized security testing only**. Always obtain proper authorization before scanning any target. The authors are not responsible for misuse of this software.
