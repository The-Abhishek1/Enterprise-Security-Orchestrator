# src/services/ai_chat.py

"""
AI Chat Assistant — explain vulnerabilities, suggest fixes, generate PoCs.
Uses the configured LLM (OpenAI or Ollama).
"""

from typing import Dict, Optional
import uuid
import json

from src.agents.planner.llm_factory import llm_factory
from src.core.database import db_manager
from src.utils.logging import logger


PROMPTS = {
    "explain": """You are a cybersecurity expert. Explain this vulnerability finding in clear, concise language.
Include: what it is, why it matters, what an attacker could do with it, and the real-world risk level.

Finding:
{finding_text}

Context: Target={target}, Tool={source}, Severity={severity}, Port={port}, Service={service}

Explain in 3-5 paragraphs. Be specific, not generic.""",

    "remediate": """You are a cybersecurity remediation expert. Provide actionable steps to fix this vulnerability.
Include: immediate fix, long-term hardening, configuration changes, and which team should handle it.

Finding:
{finding_text}

Context: Target={target}, Tool={source}, Severity={severity}, Port={port}, Service={service}

Provide a numbered list of remediation steps. Be specific with commands, configs, or settings where possible.""",

    "poc": """You are a penetration tester writing a proof-of-concept for a security assessment report.
Generate a safe, demonstrable PoC that shows the vulnerability exists WITHOUT causing damage.

Finding:
{finding_text}

Context: Target={target}, Tool={source}, Severity={severity}, Port={port}, Service={service}

Provide:
1. Prerequisites/tools needed
2. Step-by-step reproduction
3. Expected output showing the vulnerability
4. How to verify it's exploitable
5. Impact assessment

IMPORTANT: This is for authorized security testing only. Include only safe demonstration steps.""",

    "general": """You are a cybersecurity AI assistant helping a security analyst. Answer their question about this finding.

Finding:
{finding_text}

Context: Target={target}, Tool={source}, Severity={severity}, Port={port}, Service={service}

User question: {question}

Provide a helpful, accurate answer.""",
}


class AIChatService:

    async def ask(
        self,
        chat_type: str,
        finding: Dict,
        user_id: str,
        question: str = None,
        target: str = None,
    ) -> Dict:
        """Ask the AI about a finding. Returns answer + saves to DB."""

        finding_text = finding.get("finding", "") or finding.get("type", "Unknown finding")
        source = finding.get("source", "unknown")
        severity = finding.get("severity", "info")
        port = finding.get("port", "N/A")
        service = finding.get("service", "N/A")

        # Build prompt
        prompt_template = PROMPTS.get(chat_type, PROMPTS["general"])
        prompt = prompt_template.format(
            finding_text=finding_text,
            target=target or "unknown",
            source=source,
            severity=severity,
            port=port,
            service=service,
            question=question or "",
        )

        # Call LLM
        try:
            client = llm_factory.get_client()
            answer = await client.generate(
                prompt=prompt,
                system_prompt="You are a cybersecurity expert assistant. Be specific, actionable, and professional."
            )
        except Exception as e:
            logger.error(f"AI chat failed: {e}")
            answer = f"AI analysis unavailable: {e}"

        # Save to DB
        chat_id = f"chat_{uuid.uuid4().hex[:12]}"
        q_text = question or f"[{chat_type}] {finding_text[:100]}"

        try:
            if db_manager and db_manager.pg_pool:
                async with db_manager.pg_pool.acquire() as c:
                    await c.execute(
                        """INSERT INTO ai_chats (chat_id,finding_id,process_id,user_id,question,answer,chat_type)
                           VALUES ($1,$2,$3,$4,$5,$6,$7)""",
                        chat_id,
                        finding.get("finding_id", ""),
                        finding.get("process_id", ""),
                        user_id,
                        q_text,
                        answer,
                        chat_type,
                    )
        except Exception as e:
            logger.debug(f"Failed to save chat: {e}")

        return {
            "chat_id": chat_id,
            "chat_type": chat_type,
            "question": q_text,
            "answer": answer,
            "finding_id": finding.get("finding_id"),
        }

    async def get_chat_history(self, finding_id: str = None, user_id: str = None, limit: int = 20) -> list:
        """Get previous AI chat messages for a finding or user."""
        if not db_manager or not db_manager.pg_pool:
            return []
        async with db_manager.pg_pool.acquire() as c:
            if finding_id:
                rows = await c.fetch(
                    "SELECT chat_id,question,answer,chat_type,created_at FROM ai_chats WHERE finding_id=$1 ORDER BY created_at DESC LIMIT $2",
                    finding_id, limit
                )
            else:
                rows = await c.fetch(
                    "SELECT chat_id,finding_id,question,answer,chat_type,created_at FROM ai_chats WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2",
                    user_id, limit
                )
        return [dict(r) for r in rows]


ai_chat_service = AIChatService()
