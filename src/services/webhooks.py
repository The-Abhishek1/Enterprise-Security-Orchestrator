"""
webhooks_enhanced.py — replaces src/services/webhooks.py
Adds: notification_log per user, Discord support, retry logic.
"""
from typing import Dict, Any, Optional, List
from datetime import datetime
import json, asyncio, aiohttp
from src.utils.logging import logger


class WebhookService:
    def __init__(self):
        self.webhooks:          Dict[str, Dict] = {}
        self.notification_log:  Dict[str, List] = {}   # NEW: per-user log
        self._max_log           = 200

    def register_webhook(self, user_id: str, url: str,
                          events: List[str] = None,
                          webhook_type: str = "generic"):
        self.webhooks[user_id] = {
            "url": url, "type": webhook_type,
            "events": events or ["scan_complete","critical_finding"],
            "created_at": datetime.utcnow().isoformat()
        }
        logger.info(f"🔔 Webhook registered for {user_id}: {url[:40]}")

    def _log(self, user_id: str, event: str, status: str, detail: str = ""):
        log = self.notification_log.setdefault(user_id, [])
        log.append({"event": event, "status": status, "detail": detail,
                    "sent_at": datetime.utcnow().isoformat()})
        if len(log) > self._max_log:
            self.notification_log[user_id] = log[-self._max_log:]

    async def notify_scan_complete(self, user_id: str, scan_data: Dict):
        webhook = self.webhooks.get(user_id)
        if not webhook or "scan_complete" not in webhook.get("events",[]):
            return
        target   = scan_data.get("target","unknown")
        risk     = scan_data.get("risk_level","none")
        count    = scan_data.get("findings_count", 0)
        duration = scan_data.get("duration", 0)
        pid      = scan_data.get("process_id","")

        if webhook["type"] == "slack":
            color = {"critical":"#FF0000","high":"#FF6600","medium":"#FFA500",
                     "low":"#00AA00","none":"#36A64F"}.get(risk,"#808080")
            payload = {"attachments":[{"color":color,
                "pretext": f":shield: Scan complete on *{target}*",
                "fields":[
                    {"title":"Risk","value":risk.upper(),"short":True},
                    {"title":"Findings","value":str(count),"short":True},
                    {"title":"Duration","value":f"{duration:.0f}s","short":True},
                    {"title":"Process ID","value":pid,"short":False},
                ]}]}
        elif webhook["type"] == "discord":
            embed_color = {"critical":0xFF0000,"high":0xFF6600,"medium":0xFFA500,
                           "low":0x00AA00}.get(risk,0x808080)
            payload = {"embeds":[{"title":f"Scan Complete: {target}",
                "color":embed_color,
                "fields":[
                    {"name":"Risk","value":risk.upper(),"inline":True},
                    {"name":"Findings","value":str(count),"inline":True},
                    {"name":"Duration","value":f"{duration:.0f}s","inline":True},
                ]}]}
        else:
            payload = {"event":"scan_complete","target":target,"risk":risk,
                       "findings":count,"process_id":pid,"duration":duration}

        await self._send(user_id, webhook["url"], payload, "scan_complete")

    async def notify_critical_finding(self, user_id: str, finding: Dict, target: str):
        webhook = self.webhooks.get(user_id)
        if not webhook or "critical_finding" not in webhook.get("events",[]):
            return
        cves = ", ".join(finding.get("cve_ids",[]) or [])
        desc = finding.get("finding","")[:200]
        mit  = finding.get("mitigation","TBD")

        if webhook["type"] == "slack":
            payload = {"attachments":[{"color":"#FF0000",
                "pretext":f":rotating_light: *Critical finding on {target}*",
                "fields":[
                    {"title":"Type","value":finding.get("type","unknown"),"short":True},
                    {"title":"CVEs","value":cves or "N/A","short":True},
                    {"title":"Description","value":desc,"short":False},
                    {"title":"Fix","value":mit,"short":False},
                ]}]}
        elif webhook["type"] == "discord":
            payload = {"embeds":[{"title":f"⚠️ Critical Finding: {target}",
                "color":0xFF0000,
                "fields":[
                    {"name":"Type","value":finding.get("type","unknown"),"inline":True},
                    {"name":"CVEs","value":cves or "N/A","inline":True},
                    {"name":"Description","value":desc,"inline":False},
                    {"name":"Fix","value":mit,"inline":False},
                ]}]}
        else:
            payload = {"event":"critical_finding","target":target,
                       "finding": finding.get("type",""),"cves":cves,"mitigation":mit}

        await self._send(user_id, webhook["url"], payload, "critical_finding")

    async def _send(self, user_id: str, url: str, payload: Dict, event: str,
                    retries: int = 2):
        for attempt in range(retries + 1):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=5)) as r:
                        if r.status < 300:
                            self._log(user_id, event, "sent")
                            return
                        else:
                            detail = f"HTTP {r.status}"
                            logger.warning(f"Webhook {event} failed: {detail}")
            except Exception as e:
                detail = str(e)
                if attempt < retries:
                    await asyncio.sleep(2 ** attempt)
                    continue
            self._log(user_id, event, "failed", detail)

webhook_service = WebhookService()
