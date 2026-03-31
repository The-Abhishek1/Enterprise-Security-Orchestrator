# src/api/routes/v1/ai_chat.py

"""AI Chat Assistant — ask AI about vulnerabilities."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from src.api.dependencies import get_current_user
from src.services.ai_chat import ai_chat_service
from src.services.user_service import user_service

router = APIRouter(prefix="/ai", tags=["ai-chat"])


class AIChatRequest(BaseModel):
    finding_id: Optional[str] = None
    process_id: Optional[str] = None
    chat_type: str = "explain"  # explain, remediate, poc, general
    question: Optional[str] = None
    # Allow passing finding data directly (for in-memory findings)
    finding_data: Optional[dict] = None


@router.post("/chat")
async def ai_chat(req: AIChatRequest, current_user: dict = Depends(get_current_user)):
    """
    Ask AI about a vulnerability finding.
    
    chat_type:
    - explain: What is this vulnerability and why does it matter?
    - remediate: How do I fix this?
    - poc: Generate a safe proof-of-concept
    - general: Ask any question (provide 'question' field)
    """
    finding = req.finding_data or {}

    # If finding_id provided, fetch from DB
    if req.finding_id and not finding:
        try:
            findings = await user_service.get_findings(req.process_id or "", current_user["sub"])
            for f in findings:
                if f.get("finding_id") == req.finding_id:
                    finding = f
                    break
        except:
            pass

    if not finding and not req.question:
        raise HTTPException(400, "Provide finding_id, finding_data, or a question")

    # Get target from scan if available
    target = finding.get("target", "")
    if not target and req.process_id:
        try:
            scan = await user_service.get_scan(req.process_id, current_user["sub"])
            if scan:
                target = scan.get("target", "")
        except:
            pass

    result = await ai_chat_service.ask(
        chat_type=req.chat_type,
        finding=finding,
        user_id=current_user["sub"],
        question=req.question,
        target=target,
    )
    return result


@router.get("/chat/history")
async def chat_history(finding_id: str = None, limit: int = 20, current_user: dict = Depends(get_current_user)):
    """Get AI chat history for a finding or user."""
    history = await ai_chat_service.get_chat_history(
        finding_id=finding_id, user_id=current_user["sub"], limit=limit
    )
    return {"history": history}
