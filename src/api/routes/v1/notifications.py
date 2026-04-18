"""
notifications.py — Webhook/notification management per user.

POST /notifications/webhook        register webhook (Slack/Discord/generic)
GET  /notifications/webhook        get current webhook config
DELETE /notifications/webhook      remove webhook
POST /notifications/test           send test notification
GET  /notifications/history        list recent notifications sent
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from src.api.dependencies import get_current_user
from src.services.webhooks import webhook_service
from src.core.database import db_manager
from src.utils.logging import logger

router = APIRouter(prefix="/notifications", tags=["notifications"])


class WebhookRequest(BaseModel):
    url:          str
    webhook_type: str = "generic"          # slack | discord | generic
    events:       List[str] = ["scan_complete", "critical_finding"]
    # Slack-specific
    channel:      Optional[str] = None
    mention:      Optional[str] = None     # @username or @channel


class WebhookUpdateRequest(BaseModel):
    url:    Optional[str]       = None
    events: Optional[List[str]] = None


@router.post("/webhook")
async def register_webhook(req: WebhookRequest, current_user: dict = Depends(get_current_user)):
    webhook_service.register_webhook(
        user_id=current_user["sub"],
        url=req.url,
        events=req.events,
        webhook_type=req.webhook_type,
    )
    return {"status": "registered", "url": req.url, "events": req.events}


@router.get("/webhook")
async def get_webhook(current_user: dict = Depends(get_current_user)):
    w = webhook_service.webhooks.get(current_user["sub"])
    if not w:
        return {"configured": False}
    # Mask URL for security
    url = w.get("url","")
    masked = url[:20] + "..." + url[-10:] if len(url) > 35 else url
    return {"configured": True, "url_masked": masked, "events": w.get("events",[]), "type": w.get("type")}


@router.delete("/webhook")
async def delete_webhook(current_user: dict = Depends(get_current_user)):
    webhook_service.webhooks.pop(current_user["sub"], None)
    return {"status": "removed"}


@router.post("/test")
async def test_notification(current_user: dict = Depends(get_current_user)):
    webhook = webhook_service.webhooks.get(current_user["sub"])
    if not webhook:
        raise HTTPException(400, "No webhook configured. POST /notifications/webhook first.")
    await webhook_service.notify_scan_complete(current_user["sub"], {
        "target":         "test.example.com",
        "risk_level":     "medium",
        "findings_count": 3,
        "process_id":     "test_notification",
        "duration":       45,
    })
    return {"status": "test_sent", "url": webhook.get("url","")[:30] + "..."}


@router.get("/history")
async def notification_history(current_user: dict = Depends(get_current_user)):
    """Return last N notifications sent to this user\'s webhook."""
    history = webhook_service.notification_log.get(current_user["sub"], [])
    return {"notifications": history[-50:], "total": len(history)}
