# Agentic Honeypot for Scam Detection and Intelligence Extraction

## 1. Project Overview

This project implements an **agentic honeypot system** designed to **detect scam conversations, safely engage scammers, and extract actionable intelligence** through controlled, multi-turn interactions.

Unlike traditional scam detection systems that terminate conversations early, this system **continues engagement deliberately** to gather valuable forensic intelligence such as payment identifiers, phishing infrastructure, impersonation patterns, and contact details.

The system is **stateful, deterministic, and auditable**, using a language model only for **response phrasing**, never for decision-making.

---

## 2. Objectives

The system is built to:

* Detect scam-like intent in incoming messages
* Safely engage suspected scammers without alerting them
* Extract structured intelligence across multiple messages
* Prevent hallucinations or unsafe advice
* Terminate conversations automatically once sufficient intelligence is collected

---

## 3. High-Level Architecture

```
Incoming Message
      |
      v
Intent Detection
      |
      v
Intelligence Extraction
      |
      v
Session State Update
      |
      v
Goal Selection Engine
      |
      v
LLM Response Generator
      |
      v
Stop Condition Check
      |
      v
Final Intelligence Callback
```

---

## 4. System Components

### 4.1 API Layer

**Endpoint**

```
POST /api/v1/ingest
```

**Purpose**

* Accepts individual messages from an ongoing conversation
* Maintains continuity using a session identifier

**Input**

```json
{
  "sessionId": "example-session-1",
  "message": {
    "sender": "scammer",
    "text": "Your account is blocked. Pay immediately.",
    "timestamp": "2026-01-21T10:00:00Z"
  }
}
```

**Output**

```json
{
  "status": "success",
  "reply": "What do you want me to do now?"
}
```

Each API call represents **one message turn** in the conversation.

---

### 4.2 Session State Management

**Location:** `core/state.py`

Each session maintains:

* Conversation history
* Extracted intelligence (cumulative)
* Total message count
* Callback completion status

This enables **multi-turn reasoning and extraction** without relying on prompt memory.

The current implementation uses an in-memory store and is designed to be replaced with Redis or a database without changes to business logic.

---

### 4.3 Intent Detection

**Location:** `detection/intent.py`

**Purpose**
Classify incoming messages as scam or non-scam using deterministic logic.

**Techniques Used**

* Urgency and threat keyword detection
* Sensitive information request detection
* Suspicious URL analysis
* Grammar and stylistic anomaly detection
* Lightweight ML model (TF-IDF + Logistic Regression)

**Output**

```json
{
  "decision": "scam",
  "confidence": 0.71,
  "signals": ["urgency", "action_request"]
}
```

The intent result controls whether the honeypot continues engagement.

---

### 4.4 Intelligence Extraction

**Location:** `agent/extraction_agent.py`

**Purpose**
Extract structured indicators from scam messages.

**Raw Extraction Capabilities**

* UPI IDs
* Phone numbers
* Bank account numbers
* Phishing links
* Suspicious keywords

**Enrichment Capabilities**

* Domain parsing and normalization
* Bank impersonation detection in domains
* UPI provider extraction
* UPI handle impersonation detection

**Example Extracted Intelligence**

```json
{
  "upiIds": ["securepay@okhdfcbank"],
  "phishingLinks": ["secure-hdfc-verify.xyz"],
  "domains": ["secure-hdfc-verify.xyz"],
  "upiProviders": ["okhdfcbank"],
  "domainImpersonation": [
    "Domain 'secure-hdfc-verify.xyz' may impersonate HDFC"
  ]
}
```

All extraction is **regex and logic based**, not LLM dependent.

---

### 4.5 Goal Selection Engine

**Location:** `agent/probing_agent.py`

**Purpose**
Determine **what information to extract next**, based on what is already collected.

**Example Goals**

* Ask for payment method
* Ask for phone number
* Confirm payment details
* Keep the conversation active

**Key Property**
Goal selection is **deterministic and state-driven**, never random.

---

### 4.6 Response Generation

**Location:** `agent/controller.py`

**Purpose**
Generate human-like replies while strictly enforcing safety rules.

**LLM Usage**

* Used only for phrasing
* Never allowed to invent data
* Never allowed to give advice
* Never allowed to mention banks, authorities, or fraud

**Behavioral Constraints**

* Short, plain SMS-like responses
* Directly addresses the sender
* Asks clarification-oriented questions only
* Avoids emotional or dramatic language

---

### 4.7 Stop Conditions and Callback

**Stop Conditions**
Conversation ends when:

* Payment identifiers are collected, and
* Either contact details are collected or a safety threshold is reached

**Final Callback**
A single callback is sent once extraction completes.

**Example Callback Payload**

```json
{
  "sessionId": "example-session-1",
  "scamDetected": true,
  "totalMessagesExchanged": 7,
  "extractedIntelligence": {
    "upiIds": ["securepay@okhdfcbank"],
    "phishingLinks": ["secure-hdfc-verify.xyz"],
    "phoneNumbers": []
  }
}
```

Duplicate callbacks are prevented by design.

---

## 5. Information Collected by the System

The system is capable of collecting:

* Payment identifiers (UPI, bank accounts)
* Phishing URLs and domains
* Domain impersonation indicators
* UPI provider and handle impersonation
* Contact numbers
* Behavioral scam patterns
* Conversation flow metadata

All collected information is **structured, auditable, and machine-readable**.

---

## 6. Safety and Control Guarantees

* No hallucinated phone numbers or links
* No advice or recommendations
* No authority impersonation by the system
* No escalation or user guidance
* Hard caps on conversation length

---

## 7. Technology Stack

* FastAPI (API layer)
* spaCy (NLP parsing)
* scikit-learn (lightweight ML)
* OpenAI (language generation only)
* Python standard libraries
* In-memory session store (Redis-ready)

---

## 8. Extensibility

The system is designed to support:

* Persistent storage (Redis / SQL)
* WHOIS and ASN enrichment
* Cross-session scammer clustering
* Voice or IVR honeypots
* Risk scoring pipelines

---

## 9. Summary

This project demonstrates a **production-grade agentic honeypot** that balances:

* Safety
* Determinism
* Intelligence extraction
* Human realism

It is suitable for **real-world scam intelligence gathering**, not just classification.


