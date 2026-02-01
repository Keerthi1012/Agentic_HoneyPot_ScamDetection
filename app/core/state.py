"""
Session state management for Agentic Honeypot

Currently:
- In-memory store (per process)
- Session scoped by session_id

Later:
- Replace with Redis / DB without changing controller logic
"""

from typing import Dict, Any

# -----------------------------
# In-memory session store
# -----------------------------

_sessions: Dict[str, Dict[str, Any]] = {}


# -----------------------------
# Session APIs
# -----------------------------

def init_session(session_id: str):
    """
    Initialize a session if it does not exist
    """
    if session_id not in _sessions:
        _sessions[session_id] = {
            "session_id": session_id,
            "messages": [],          # conversation timeline
            "confidence": 0.0,       # last computed confidence
            "stage": "unknown",      # probing / extraction / benign
            "intelligence": {}       # extracted scam intel (future)
        }


def get_session(session_id: str) -> Dict[str, Any]:
    """
    Fetch session state
    """
    return _sessions.get(session_id)


def update_session(session_id: str, updates: Dict[str, Any]):
    """
    Update session state safely
    """
    if session_id not in _sessions:
        init_session(session_id)

    for key, value in updates.items():
        _sessions[session_id][key] = value
