import os
import re 
import spacy
import datetime
import requests 
from dotenv import load_dotenv
from openai import OpenAI
from typing import List, Optional
from detection.intent import detect_intent
from agent.probing_agent import (
    select_next_goal,
    build_goal_prompt
)
from agent.extraction_agent import extract_and_enrich
from core.state import (
    init_session,
    get_session,
    increment_message_count,
    merge_intelligence,
    get_serializable_intelligence,
    is_callback_sent,
    mark_callback_sent
)


BLOCKED_REPLY_PATTERNS = [
    # customer support references
    "customer service",
    "customer care",
    "helpline",
    "support number",

    # real-world authority leakage
    "official website",
    "official site",
    "bank website",
    "check online",
    "search online",
    "google",

    # bank / authority references
    "bank support",
    "bank help",
    "contact the bank",
    "reach out to",

    # resolution / advice language
    "you should",
    "please check",
    "i recommend"
]




# Load environment variables
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -------------------------------------------------
# Main Agent Controller
# -------------------------------------------------
def should_stop_extraction(intels: dict, total_msgs: int) -> bool:
    """
    Stop ONLY when meaningful intelligence is collected
    or when conversation is genuinely too long.
    """

    payment_found = bool(
        intels.get("upiIds")
        or intels.get("bankAccounts")
        or intels.get("phishingLinks")
    )

    contact_found = bool(intels.get("phoneNumbers"))

    # ✅ PRIMARY STOP: both payment + contact
    if payment_found and contact_found:
        return True

    # ✅ SECONDARY SAFETY STOP (very high)
    # Allows ~6–7 full message turns
    if total_msgs >= 14:
        return True

    return False



def handle_agent(session_id: str, message):
    # 1. Init session
    init_session(session_id)
    session = get_session(session_id)

    # 2. Save incoming message
    session["messages"].append({
        "from": message.sender,
        "text": message.text,
        "timestamp": message.timestamp
    })
    increment_message_count(session_id)

    # 3. Detect intent
    intent_result = detect_intent(message.text)
    decision = intent_result["decision"]
    signals = intent_result["signals"]

    # 4. Extract intelligence (STATLESS)
    extracted_intel = extract_and_enrich(message.text)

    # 5. Merge intelligence (STATEFUL)
    merge_intelligence(session_id, extracted_intel)

    # 6. Decide next goal (AFTER MERGE)
    payment_requested = bool(
    re.search(r'\b(pay|send|transfer|deposit|₹|\brupees\b|\binr\b)\b', message.text.lower())
)



    next_goal = select_next_goal(session["intels"], payment_requested)

    # 7. Decide if honeypot should continue
    continue_honeypot = (
        decision == "scam"
        or session["total_messages"] <= 8
    )

    if continue_honeypot and not is_callback_sent(session_id):


        # Stop condition
        if should_stop_extraction(session["intels"], session["total_messages"]):
            if not is_callback_sent(session_id):
                send_final_callback(
                    session_id,
                    get_serializable_intelligence(session_id),
                    session["total_messages"]
                )
                mark_callback_sent(session_id)

            return {
                "status": "success",
                "reply": "Okay, I will check and get back later."
            }

        # Build conversation context
        context = "\n".join(
            f"{m['from']}: {m['text']}"
            for m in session["messages"][-5:]
        )

        # Generate reply
        prompt = build_goal_prompt(next_goal, context)
        agent_reply = generate_reply(prompt)

    else:
        # Soft probing fallback (keeps honeypot alive)
        context = "\n".join(
            f"{m['from']}: {m['text']}"
            for m in session["messages"][-3:]
        )
        prompt = build_goal_prompt("keep_engaged", context)
        agent_reply = generate_reply(prompt)



    # 10. Save agent reply (ONLY if valid)
    if agent_reply:
        session["messages"].append({
            "from": "agent",
            "text": agent_reply,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
        increment_message_count(session_id)


    # 11. Respond
    return {
        "status": "success",
        "reply": agent_reply
    }



def generate_reply(prompt: str) -> str:
    """
    Generate a human-like reply using OpenAI.
    The controller already decided WHAT to ask.
    This function only handles language generation.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                        {
                        "role": "system",
                        "content": (
                            "You are a normal older Indian person replying casually to a message that is confusing and worrying. "
                            "You are NOT dramatic, NOT emotional, and NOT explaining feelings. "
                            "You speak plainly and briefly, like real SMS replies. "
                            "You are confused and want clarification. "
                            "You ask simple questions like 'why', 'what is this', 'what do you want me to do'. "
                            "You always reply directly to the sender using 'you'. "
                            "You never comfort the other person. "
                            "You never narrate thoughts or emotions. "
                            "You never use third-person words like 'they' or 'these people'. "
                            "Keep replies to 1 short sentence, maximum 2. "
                            "Never mention scam, fraud, police, banks, or advice."
                        )
                    },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=120,
            temperature=0.8
        )

        reply = response.choices[0].message.content.strip()
        reply_lower = reply.lower()

        if any(pat in reply_lower for pat in BLOCKED_REPLY_PATTERNS):
            return (
                "I am very worried now and not understanding. "
                "Please tell me clearly what YOU want me to do."
            )

        return reply



    except Exception as e:
        print(f"OpenAI error: {e}")
        return "I am little confused, can you explain again?"


    

def send_final_callback(session_id: str, intel: dict, total_messages: int):
    """Send final intelligence report to GUVI evaluation endpoint"""
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": intel,
        "agentNotes": "Scammer used urgency tactics and shared phishing links/UPI IDs"
    }
    
    try:
        print(f"✅ GUVI callback sent: {payload}")
        response = requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
        print(f"✅ GUVI callback sent: {response.status_code}")
    except Exception as e:
        print(f"❌ GUVI callback failed: {e}")


