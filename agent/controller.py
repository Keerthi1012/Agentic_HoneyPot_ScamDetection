import os
import re 
import spacy
import datetime
import requests 
from dotenv import load_dotenv
from openai import OpenAI
from typing import List, Optional
from core.state import init_session, get_session, update_session
from detection.intent import detect_intent

# Load environment variables
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Load SpaCy model
nlp = spacy.load("en_core_web_sm")

# -------------------------------------------------
# Main Agent Controller
# -------------------------------------------------

def handle_agent(
    session_id: str,
    message: str,
):

    # -----------------------------
    # Session initialization
    # -----------------------------
    init_session(session_id)
    session = get_session(session_id)

    # -----------------------------
    # Seed conversation history (if provided)
    # -----------------------------
    if message:
        session["messages"].append({
            "from": message.sender,
            "text": message.text,
            "timestamp": message.timestamp.isoformat()
        })

    # -----------------------------
    # Intent detection (latest message only)
    # -----------------------------
    intent_result = detect_intent(message.text)

    confidence = intent_result["confidence"]
    decision = intent_result["decision"]
    signals = intent_result["signals"]
    intels = extract_intel(message.text)

    # -----------------------------
    # Agent selection logic
    # -----------------------------
    agent_stage = None
    agent_reply = None

    if decision == "scam":
        agent_stage = "extraction"
        agent_reply = generate_reply(session["messages"], agent_stage)

    else:
        agent_stage = "probing"
        agent_reply = generate_reply(session["messages"], agent_stage)

    # -----------------------------
    # Save agent reply to session
    # -----------------------------
    if agent_reply:
        session["messages"].append({
            "from": "agent",
            "text": agent_reply,
            "timestamp": datetime.datetime.now().replace(microsecond=0).isoformat()
        })

    # -----------------------------
    # Persist session updates
    # -----------------------------
    update_session(session_id, {
        "confidence": confidence,
        "stage": agent_stage,
        "signals": signals,
        "intels": intels
    })

    total_messages = len(session["messages"])
    if decision == "scam": 
        send_final_callback(session_id, intels, total_messages)

    print(f"Session before sending response back to user: {session}")
    # -----------------------------
    # API response
    # -----------------------------
    return {"sender": "user", "status": "success", "text": agent_reply}

def generate_reply(history: list, agent_stage: str) -> str:
    """Generate human-like reply using OpenAI GPT"""
    # Last 3 messages for context
    context = "\n".join([f"{m['from']}: {m['text']}" for m in history[-3:]])
    prompt = ""
    if agent_stage == "extraction":
        prompt = f"""You are a confused 65-year-old Indian uncle receiving scam messages. 
        You are talking with a fraudster who is trying to loot money through scamming. 
        Your task now is to extract as much of information about the fraudster without informing that you already figured out the fraud.
        
    Conversation history:
    {context}

    Rules:
    - Act confused but cooperative
    - Ask innocent questions to extract more info (UPI, bank details, links, PII information)
    - Use simple Indian English with minor typos
    - NEVER mention "scam", "fraud", or detection or similar words.
    - Keep replies short (1-2 sentences) with little bit of panic in the response message.

    Your reply:"""
    
    else:
        prompt = f"""You are a confused 65-year-old Indian uncle receiving scam messages.
        
    Conversation history:
    {context}

    Rules:
    - Act confused but cooperative
    - Ask innocent questions to extract more info (UPI, bank details, links)
    - Use simple Indian English with minor typos
    - NEVER mention "scam", "fraud", or detection
    - Keep replies short (1-2 sentences)

    Your reply:"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Cheap & fast
            messages=[
                {"role": "system", "content": "You are a confused elderly Indian user engaging with scammers to extract information."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=60,
            temperature=0.8  # Creative but controlled
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        # Fallback if OpenAI fails
        print(f"OpenAI error: {e}")
        return "Why do you need my UPI ID sir ?"
    
def extract_intel(text: str) -> dict:
    text = text.lower()
    
    """Extract URLs using SpaCy's built-in URL detection + custom patterns"""
    doc = nlp(text)

    # FIXED: Better phishing URL patterns (handles [url], (url), bare urls)
    phishing_links = []
    
    # 1. SpaCy's native URL detection (token.like_url)
    for token in doc:
        if token.like_url:
            phishing_links.append(token.text)
    
    # 2. Enhanced extraction for bracketed/parenthesized URLs
    bracketed_urls = re.findall(r'\[([^\]]*(?:http|www)[^\]]*)\]|https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    phishing_links.extend(bracketed_urls)
    
    # 3. Remove duplicates and filter valid links
    unique_links = list(set([link.strip('[]()<>') for link in phishing_links if len(link) > 5]))
    
    # FIXED: Better UPI patterns (handles @okhdfcbank, @paytm, etc.)
    upi_patterns = [
        r'\b([a-z][a-z0-9]*@[a-z0-9]{4,15})\b',      # ✅ ramu@okhdfcbank (word boundary)
        r'\b([a-z0-9]{3,}@paytm)\b',                 # ✅ rahul@paytm
        r'\b([a-z0-9]{3,}@phonepe)\b',               # ✅ user@phonepe
        r'\b([a-z0-9]{3,}@[a-z]+bank)\b',     
    ]
    upi_ids = []
    for pattern in upi_patterns:
        upi_ids.extend(re.findall(pattern, text))
    
    intel = {
        "bankAccounts": re.findall(r'\b\d{4}-\d{4}-\d{4}\b', text),  # XXXX-XXXX-XXXX
        "upiIds": list(set(upi_ids)),                                # Remove duplicates
        "phishingLinks": list(set([link for link in unique_links if 'http' in link or 'www' in link])),
        "phoneNumbers": re.findall(r'\+91\d{10}|\d{10}', text),
        "suspiciousKeywords": ['urgent', 'verify', 'blocked', 'immediately', 'suspension']
    }
    
    # Filter non-empty
    return {k: v for k, v in intel.items() if v}

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