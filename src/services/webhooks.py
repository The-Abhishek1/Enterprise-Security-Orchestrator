# src/services/webhooks.py

"""
Webhook Notifications — notify external services when events occur.
Supports Slack, Discord, generic HTTP webhooks.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import json
import asyncio
import aiohttp

from src.utils.logging import logger


class WebhookService:
    """Send notifications to external services."""
    
    def __init__(self):
        self.webhooks: Dict[str, Dict] = {}  # user_id -> webhook config
    
    def register_webhook(self, user_id: str, url: str, events: List[str] = None, webhook_type: str = "generic"):
        """Register a webhook for a user."""
        self.webhooks[user_id] = {
            "url": url,
            "type": webhook_type,  # generic, slack, discord
            "events": events or ["scan_complete", "critical_finding"],
            "created_at": datetime.utcnow().isoformat()
        }
        logger.info(f"🔔 Webhook registered for {user_id}: {url}")
    
    async def notify_scan_complete(self, user_id: str, scan_data: Dict):
        """Notify when a scan completes."""
        webhook = self.webhooks.get(user_id)
        if not webhook or "scan_complete" not in webhook.get("events", []):
            return
        
        target = scan_data.get("target", "unknown")
        risk = scan_data.get("risk_level", "none")
        findings = scan_data.get("findings_count", 0)
        duration = scan_data.get("duration_seconds", 0)
        process_id = scan_data.get("process_id", "")
        
        if webhook["type"] == "slack":
            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"🔍 Scan Complete: {target}"}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Risk:* {risk.upper()}"},
                            {"type": "mrkdwn", "text": f"*Findings:* {findings}"},
                            {"type": "mrkdwn", "text": f"*Duration:* {duration:.0f}s"},
                            {"type": "mrkdwn", "text": f"*ID:* {process_id}"},
                        ]
                    }
                ]
            }
        elif webhook["type"] == "discord":
            payload = {
                "embeds": [{
                    "title": f"🔍 Scan Complete: {target}",
                    "color": 0x00ff00 if risk in ["none", "low"] else 0xff0000,
                    "fields": [
                        {"name": "Risk", "value": risk.upper(), "inline": True},
                        {"name": "Findings", "value": str(findings), "inline": True},
                        {"name": "Duration", "value": f"{duration:.0f}s", "inline": True},
                    ]
                }]
            }
        else:
            payload = {
                "event": "scan_complete",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "process_id": process_id,
                    "target": target,
                    "risk_level": risk,
                    "findings_count": findings,
                    "duration_seconds": duration
                }
            }
        
        await self._send(webhook["url"], payload)
    
    async def notify_critical_finding(self, user_id: str, finding: Dict, target: str):
        """Notify when a critical/high finding is discovered."""
        webhook = self.webhooks.get(user_id)
        if not webhook or "critical_finding" not in webhook.get("events", []):
            return
        
        severity = finding.get("severity", "unknown")
        description = finding.get("finding", "")[:200]
        
        if webhook["type"] == "slack":
            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"🚨 {severity.upper()} Finding on {target}"}
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": description}
                    }
                ]
            }
        else:
            payload = {
                "event": "critical_finding",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "target": target,
                    "severity": severity,
                    "finding": description
                }
            }
        
        await self._send(webhook["url"], payload)
    
    async def notify_approval_needed(self, user_id: str, process_id: str, proposals: List[Dict]):
        """Notify when user approval is needed for proposed tasks."""
        webhook = self.webhooks.get(user_id)
        if not webhook:
            return
        
        task_list = "\n".join(f"  • {p['task_name']} ({p['tool']})" for p in proposals)
        
        if webhook["type"] == "slack":
            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"⏸️ Approval Needed: {process_id}"}
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"Proposed tasks:\n{task_list}"}
                    }
                ]
            }
        else:
            payload = {
                "event": "approval_needed",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "process_id": process_id,
                    "proposals": proposals
                }
            }
        
        await self._send(webhook["url"], payload)
    
    async def _send(self, url: str, payload: Dict):
        """Send webhook request."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status >= 400:
                        logger.warning(f"⚠️ Webhook failed ({resp.status}): {url}")
                    else:
                        logger.info(f"🔔 Webhook sent: {url}")
        except Exception as e:
            logger.warning(f"⚠️ Webhook error: {e}")


# Singleton
webhook_service = WebhookService()
