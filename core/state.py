"""
Session state management for Agentic Honeypot

Currently:
- In-memory store (per process)
- Session scoped by session_id

Later:
- Replace with Redis / DB without changing controller logic
"""

from typing import Dict, Any
import datetime



# -----------------------------
# In-memory session store
# -----------------------------

_sessions: Dict[str, Dict[str, Any]] = {}


# -----------------------------
# Session APIs
# -----------------------------

def init_session(session_id):
    if session_id not in _sessions:
        _sessions[session_id] = {
            # Full conversation messages (scammer + agent)
            "messages": [],

            # Cumulative intelligence collected so far
            "intels": {
                "bankAccounts": set(),
                "upiIds": set(),
                "phishingLinks": set(),
                "phoneNumbers": set(),
                "suspiciousKeywords": set()
            },

            # Agent reasoning & lifecycle
            "current_goal": None,
            "goals_completed": set(),

            # Meta tracking (important for callback)
            "total_messages": 0,
            "callback_sent": False,

            # Audit / debugging
            "created_at": datetime.datetime.utcnow().isoformat()
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
        if key not in _sessions[session_id]:
            _sessions[session_id][key] = []

        if isinstance(_sessions[session_id][key], list):
            _sessions[session_id][key].append(value)
        else:
            _sessions[session_id][key] = value


def increment_message_count(session_id):
    """
    Helper to increment message count
    
    """
    session = get_session(session_id)
    if session:
        session["total_messages"] += 1


def merge_intelligence(session_id, extracted: dict):
    """
    Merge newly extracted intelligence into session memory.
    Expected keys follow GUVI naming.
    """
    session = get_session(session_id)
    if not session or not extracted:
        return

    for key in session["intels"]:
        values = extracted.get(key)
        if not values:
            continue

        if isinstance(values, list):
            session["intels"][key].update(values)
        else:
            session["intels"][key].add(values)


def get_serializable_intelligence(session_id):
    """
    JSON-safe getter for callback
    """
    session = get_session(session_id)
    if not session:
        return {}

    return {
        key: list(values)
        for key, values in session["intels"].items()
    }

# Callback gaurd helpers to prevent duplicate callback calls

def mark_callback_sent(session_id):
    session = get_session(session_id)
    if session:
        session["callback_sent"] = True


def is_callback_sent(session_id):
    session = get_session(session_id)
    return bool(session and session.get("callback_sent"))
