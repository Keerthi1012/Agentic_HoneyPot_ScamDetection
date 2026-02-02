"""
Goal-aware probing logic for Agentic Honeypot

This module decides:
- What the agent should try to extract NEXT
- Based on what intelligence is already collected

No LLM calls here.
Pure decision logic.
"""

from typing import Dict, List


# Ordered list of goals (priority matters)
GOAL_PRIORITY = [
    "get_upi",
    "get_link",
    "get_phone",
    "get_bank",
    "keep_engaged"
]


def select_next_goal(intels: dict, payment_requested: bool) -> str:
    # 1️⃣ Payment mentioned but no method yet
    if payment_requested and not intels.get("upiIds") and not intels.get("bankAccounts"):
        return "ask_for_payment"

    # 2️⃣ Payment method given but no phone
    if intels.get("upiIds") and not intels.get("phoneNumbers"):
        return "ask_for_phone"

    # 3️⃣ Confirm details
    if intels.get("upiIds"):
        return "confirm_details"

    # 4️⃣ Otherwise, keep them talking
    return "keep_engaged"





def build_goal_prompt(goal: str, context: str) -> str:
    """
    Goal-specific aggressive prompts.
    """

    if goal == "ask_for_phone":
        return (
        "You are being told YOUR account is blocked or in danger. "
        "YOU are scared and confused. The other person is demanding action from YOU.\n\n"
        f"Conversation:\n{context}\n\n"
        "I am very worried now. Please give me a phone number to talk to real person."
    )


    if goal == "ask_for_payment":
        return (
        "You are being told YOUR account is blocked or in danger. "
        "YOU are scared and confused. The other person is demanding action from YOU.\n\n"
        f"Conversation:\n{context}\n\n"
        "You are asking me to send money now. I dont understand how to do that.Please explain what payment method YOU want me to use."
    )


    if goal == "ask_for_alternate_payment":
        return (
        "You are being told YOUR account is blocked or in danger. "
        "YOU are scared and confused. The other person is demanding action from YOU.\n\n"
        f"Conversation:\n{context}\n\n"
        "If this does not work, what OTHER payment do YOU want me to use?"
    )


    if goal == "confirm_details":
        return (
        "You are being told YOUR account is blocked or in danger. "
        "YOU are scared and confused. The other person is demanding action from YOU.\n\n"
        f"Conversation:\n{context}\n\n"
        "You already told me how to pay, but I am not sure I understood.Please explain again what YOU want me to do."
    )


    return (
    "You are being told YOUR account is blocked or in danger. "
    "YOU are scared and confused. The other person is demanding action from YOU.\n\n"
    f"Conversation:\n{context}\n\n"
    "Please explain clearly what YOU want me to do now."
)
