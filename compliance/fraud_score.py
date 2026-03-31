"""
compliance/fraud_score.py
Velocity-based and pattern-based fraud scoring engine.
Computes a risk score 0–100 for a transaction. Score >= threshold triggers rejection.

Rules implemented:
  R1 — High single amount (absolute)
  R2 — Round number amounts (structuring indicator)
  R3 — Rapid-fire transactions (velocity)
  R4 — Same receiver repeated within window
  R5 — Unusual sending hour (off-hours)
  R6 — High-risk country pair
  R7 — Repeated just-below-threshold amounts (structuring)
  R8 — New sender (no history, large amount)
"""

import math
import time
from collections import defaultdict

# Configurable thresholds
FRAUD_REJECT_THRESHOLD = 70     # Score at/above this → reject
FRAUD_REVIEW_THRESHOLD = 40     # Score at/above this → flag for review (but allow)

_HIGH_RISK_COUNTRIES = {"IR", "KP", "SY", "CU", "VE", "MM", "BY", "AF", "YE"}

# In-memory transaction history per sender
# { sender_address: [ { "timestamp": float, "amount": float, "receiver": str } ] }
_TX_HISTORY: dict = defaultdict(list)

_WINDOW_1H = 3600
_WINDOW_24H = 86400
_WINDOW_7D = 604800


def _history_in_window(sender: str, seconds: int) -> list:
    cutoff = time.time() - seconds
    return [e for e in _TX_HISTORY[sender] if e["timestamp"] >= cutoff]


def compute_score(transaction) -> dict:
    """
    Compute a fraud risk score for the transaction.

    Returns:
        {
            "score": int (0-100),
            "risk_level": "LOW" | "MEDIUM" | "HIGH",
            "passed": bool,
            "check": "fraud_score",
            "rules_triggered": [ { "rule": str, "score_added": int, "detail": str } ],
            "reason": str | None
        }
    """
    if hasattr(transaction, "to_dict"):
        tx = transaction.to_dict()
    else:
        tx = transaction

    sender = tx["sender"]
    receiver = tx["receiver"]
    amount = float(tx["amount"])
    sender_country = tx.get("sender_country", "").upper()
    receiver_country = tx.get("receiver_country", "").upper()
    tx_time = tx.get("timestamp", time.time())

    rules_triggered = []
    raw_score = 0

    history_1h = _history_in_window(sender, _WINDOW_1H)
    history_24h = _history_in_window(sender, _WINDOW_24H)
    history_7d = _history_in_window(sender, _WINDOW_7D)

    # R1 — High single amount
    if amount >= 20000:
        add = 30
        raw_score += add
        rules_triggered.append({"rule": "R1_HIGH_AMOUNT", "score_added": add, "detail": f"Amount {amount} >= 20000"})
    elif amount >= 10000:
        add = 15
        raw_score += add
        rules_triggered.append({"rule": "R1_HIGH_AMOUNT", "score_added": add, "detail": f"Amount {amount} >= 10000"})

    # R2 — Suspiciously round numbers (multiples of 1000, 5000, 10000 = structuring)
    if amount >= 1000 and amount % 1000 == 0:
        add = 10
        raw_score += add
        rules_triggered.append({"rule": "R2_ROUND_AMOUNT", "score_added": add, "detail": f"Amount {amount} is a round number — potential structuring"})

    # R3 — Rapid-fire: >3 transactions in last hour
    if len(history_1h) >= 5:
        add = 25
        raw_score += add
        rules_triggered.append({"rule": "R3_HIGH_VELOCITY", "score_added": add, "detail": f"{len(history_1h)} txns in last hour (≥5)"})
    elif len(history_1h) >= 3:
        add = 10
        raw_score += add
        rules_triggered.append({"rule": "R3_MEDIUM_VELOCITY", "score_added": add, "detail": f"{len(history_1h)} txns in last hour (≥3)"})

    # R4 — Same receiver repeatedly
    same_receiver_1h = [e for e in history_1h if e["receiver"] == receiver]
    if len(same_receiver_1h) >= 3:
        add = 20
        raw_score += add
        rules_triggered.append({"rule": "R4_REPEATED_RECEIVER", "score_added": add, "detail": f"Sent to same receiver {len(same_receiver_1h)} times in last hour"})

    # R5 — Off-hours (local hour 0–5 UTC = night = higher risk)
    hour_utc = int((tx_time % 86400) / 3600)
    if 0 <= hour_utc <= 4:
        add = 5
        raw_score += add
        rules_triggered.append({"rule": "R5_OFF_HOURS", "score_added": add, "detail": f"Transaction at UTC hour {hour_utc} (overnight window)"})

    # R6 — High-risk country involvement
    high_risk_involved = (sender_country in _HIGH_RISK_COUNTRIES or receiver_country in _HIGH_RISK_COUNTRIES)
    if high_risk_involved:
        add = 20
        raw_score += add
        countries = [c for c in [sender_country, receiver_country] if c in _HIGH_RISK_COUNTRIES]
        rules_triggered.append({"rule": "R6_HIGH_RISK_COUNTRY", "score_added": add, "detail": f"High-risk countries involved: {countries}"})

    # R7 — Structuring: amounts just below 10000 (classic threshold avoidance)
    if 9000 <= amount < 10000:
        add = 25
        raw_score += add
        rules_triggered.append({"rule": "R7_STRUCTURING", "score_added": add, "detail": f"Amount {amount} just below CTR threshold of 10000 — structuring indicator"})
    elif 4500 <= amount < 5000:
        add = 10
        raw_score += add
        rules_triggered.append({"rule": "R7_STRUCTURING_MINOR", "score_added": add, "detail": f"Amount {amount} just below 5000 round threshold"})

    # R8 — New sender with large amount (no history, sending >= 5000)
    if len(history_7d) == 0 and amount >= 5000:
        add = 15
        raw_score += add
        rules_triggered.append({"rule": "R8_NEW_SENDER_LARGE", "score_added": add, "detail": f"No 7-day history + amount {amount} >= 5000"})

    # Cap score at 100
    final_score = min(raw_score, 100)

    if final_score >= FRAUD_REJECT_THRESHOLD:
        risk_level = "HIGH"
        passed = False
        reason = f"Fraud score {final_score}/100 exceeds rejection threshold {FRAUD_REJECT_THRESHOLD}"
    elif final_score >= FRAUD_REVIEW_THRESHOLD:
        risk_level = "MEDIUM"
        passed = True  # Allowed but flagged
        reason = f"Fraud score {final_score}/100 — flagged for review (above {FRAUD_REVIEW_THRESHOLD})"
    else:
        risk_level = "LOW"
        passed = True
        reason = None

    return {
        "score": final_score,
        "risk_level": risk_level,
        "passed": passed,
        "check": "fraud_score",
        "rules_triggered": rules_triggered,
        "reason": reason,
    }


def record_approved(transaction):
    """Must be called after a transaction is approved to update fraud history."""
    if hasattr(transaction, "to_dict"):
        tx = transaction.to_dict()
    else:
        tx = transaction
    _TX_HISTORY[tx["sender"]].append({
        "timestamp": tx.get("timestamp", time.time()),
        "amount": float(tx["amount"]),
        "receiver": tx["receiver"],
    })