from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.agent.controller import handle_agent

router = APIRouter(prefix="/api/v1")


# -----------------------------
# Request / Response Schemas
# -----------------------------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: datetime
    
class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class IncomingMessage(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

class AgentResponse(BaseModel):
    agentActivated: bool
    decision: str
    confidence: float
    agentStage: Optional[str] = None
    signals: Optional[list] = None
    agentReply: Optional[str] = None


# -----------------------------
# Main Ingress Endpoint
# -----------------------------

@router.post("/ingest", response_model=AgentResponse)
def ingest_message(payload: IncomingMessage):
    """
    Unified entry point for:
    - SMS
    - WhatsApp
    - Email
    - Chat
    Channel is intentionally NOT used for decisioning
    """

    if not payload.message.text.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    result = handle_agent(
        session_id=payload.sessionId,
        message_text=payload.message.text,
        conversation_history=payload.conversationHistory,
        metadata=payload.metadata
    )

    return result

