# src/api/routes/v1/collab.py

"""Collaboration — teams, members, shared scans, comments."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from src.api.dependencies import get_current_user
from src.services.collaboration import collaboration_service

router = APIRouter(prefix="/collab", tags=["collaboration"])


class CreateTeamRequest(BaseModel):
    name: str
    description: Optional[str] = None

class InviteRequest(BaseModel):
    email: str
    role: str = "member"

class CommentRequest(BaseModel):
    finding_id: str
    process_id: str
    content: str


# ═══ TEAMS ═══

@router.post("/teams")
async def create_team(req: CreateTeamRequest, current_user: dict = Depends(get_current_user)):
    return await collaboration_service.create_team(current_user["sub"], req.name, req.description)

@router.get("/teams")
async def list_teams(current_user: dict = Depends(get_current_user)):
    teams = await collaboration_service.list_teams(current_user["sub"])
    return {"teams": teams}

@router.get("/teams/{team_id}/members")
async def get_members(team_id: str, current_user: dict = Depends(get_current_user)):
    try:
        members = await collaboration_service.get_team_members(team_id, current_user["sub"])
        return {"members": members}
    except Exception as e:
        raise HTTPException(403, str(e))

@router.post("/teams/{team_id}/invite")
async def invite_member(team_id: str, req: InviteRequest, current_user: dict = Depends(get_current_user)):
    try:
        return await collaboration_service.invite_member(team_id, current_user["sub"], req.email, req.role)
    except Exception as e:
        raise HTTPException(400, str(e))

@router.delete("/teams/{team_id}/members/{user_id}")
async def remove_member(team_id: str, user_id: str, current_user: dict = Depends(get_current_user)):
    try:
        ok = await collaboration_service.remove_member(team_id, current_user["sub"], user_id)
        if not ok:
            raise HTTPException(404, "Member not found")
        return {"message": "Member removed"}
    except Exception as e:
        raise HTTPException(400, str(e))

@router.get("/teams/{team_id}/scans")
async def team_scans(team_id: str, current_user: dict = Depends(get_current_user)):
    try:
        scans = await collaboration_service.get_team_scans(team_id, current_user["sub"])
        return {"scans": scans}
    except Exception as e:
        raise HTTPException(403, str(e))


# ═══ COMMENTS ═══

@router.post("/comments")
async def add_comment(req: CommentRequest, current_user: dict = Depends(get_current_user)):
    return await collaboration_service.add_comment(
        finding_id=req.finding_id, process_id=req.process_id,
        user_id=current_user["sub"], username=current_user.get("username", "unknown"),
        content=req.content
    )

@router.get("/comments/{process_id}")
async def get_comments(process_id: str, finding_id: str = None, current_user: dict = Depends(get_current_user)):
    comments = await collaboration_service.get_comments(process_id, finding_id)
    return {"comments": comments}
