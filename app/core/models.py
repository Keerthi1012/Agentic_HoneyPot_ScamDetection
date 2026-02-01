from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class Message(BaseModel):
    sender: str          # "scammer" or "user" (directional only)
    text: str
    timestamp: datetime


class Metadata(BaseModel):
    channel: str         # SMS, WHATSAPP, EMAIL
    language: Optional[str] = "en"
    locale: Optional[str] = "IN"


class AnalyzeRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message]
    metadata: Metadata


class AnalyzeResponse(BaseModel):
    sessionId: str
    state: str           # UNKNOWN | SUSPECTED | CONFIRMED_SCAM | AGENT_ACTIVE
    confidence: str      # LOW | MEDIUM | HIGH
    riskScore: int
    agentMode: Optional[str] = None   # PROBE | HONEYPOT
    agentReply: Optional[str] = None
    extractedIntel: dict
