from typing import List, Optional

from app.core.state import init_session, get_session, update_session
from app.detection.intent import detect_intent


# -------------------------------------------------
# Agent response generators (mock for now)
# -------------------------------------------------

def probing_agent():
    """
    Used when scam confidence is uncertain.
    Goal: ask neutral clarifying questions.
    """
    return (
        "Could you please clarify which organization you are contacting me from "
        "and why this action is required?"
    )


def extraction_agent():
    """
    Used when scam confidence is high.
    Goal: extract scammer intelligence without alerting them.
    """
    return (
        "I’m not sure I understand. Can you explain what exactly is wrong with my account? "
        "Is this related to a recent transaction?"
    )


# -------------------------------------------------
# Main Agent Controller
# -------------------------------------------------

def handle_agent(
    session_id: str,
    message_text: str,
    conversation_history: Optional[List] = None,
    metadata: Optional[dict] = None
):
    """
    Central decision point:
    - maintains session
    - detects intent
    - chooses probing vs extraction agent
    """

    # -----------------------------
    # Session initialization
    # -----------------------------
    init_session(session_id)
    session = get_session(session_id)

    # -----------------------------
    # Seed conversation history (if provided)
    # -----------------------------
    if conversation_history:
        for msg in conversation_history:
            session["messages"].append({
                "from": msg.sender,
                "text": msg.text,
                "timestamp": msg.timestamp.isoformat()
            })

    # -----------------------------
    # Add current incoming message
    # -----------------------------
    session["messages"].append({
        "from": "scammer",
        "text": message_text
    })

    # -----------------------------
    # Intent detection (latest message only)
    # -----------------------------
    intent_result = detect_intent(message_text)

    confidence = intent_result["confidence"]
    decision = intent_result["decision"]
    signals = intent_result["signals"]

    # -----------------------------
    # Agent selection logic
    # -----------------------------
    agent_activated = False
    agent_stage = None
    agent_reply = None

    if decision == "scam":
        agent_stage = "extraction"
        agent_reply = extraction_agent()
        agent_activated = True

    elif decision == "uncertain":
        agent_stage = "probing"
        agent_reply = probing_agent()
        agent_activated = True

    else:
        agent_stage = "benign"

    # -----------------------------
    # Save agent reply to session
    # -----------------------------
    if agent_reply:
        session["messages"].append({
            "from": "agent",
            "text": agent_reply
        })

    # -----------------------------
    # Persist session updates
    # -----------------------------
    update_session(session_id, {
        "confidence": confidence,
        "stage": agent_stage
    })

    # -----------------------------
    # API response
    # -----------------------------
    return {
        "agentActivated": agent_activated,
        "decision": decision,
        "confidence": confidence,
        "agentStage": agent_stage,
        "signals": signals,
        "agentReply": agent_reply
    }
