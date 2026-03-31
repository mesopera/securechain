"""
compliance/limits.py
Checks whether a transaction exceeds the permitted transfer limits
for the sender/receiver country corridor, and tracks daily volumes
using an in-memory ledger (resets on process restart).
"""

import json
import os
import time
from collections import defaultdict

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def _load_json(filename: str) -> dict:
    path = os.path.join(_DATA_DIR, filename)
    with open(path) as f:
        return json.load(f)


_LIMITS = _load_json("country_limits.json")
_CORRIDORS: dict = _LIMITS["corridors"]
_DEFAULTS: dict = _LIMITS["global_defaults"]
_HIGH_RISK: set = set(_LIMITS.get("high_risk_countries", []))


# In-memory daily volume tracker: { sender_address: [ (timestamp, amount) ] }
_DAILY_VOLUME: dict = defaultdict(list)
# In-memory hourly tx count: { sender_address: [ timestamp ] }
_HOURLY_TX: dict = defaultdict(list)


def _get_corridor_limits(sender_country: str, receiver_country: str) -> dict:
    key = f"{sender_country.upper()}-{receiver_country.upper()}"
    return _CORRIDORS.get(key, _CORRIDORS["DEFAULT"])


def _clean_window(events: list, window_seconds: int) -> list:
    cutoff = time.time() - window_seconds
    return [e for e in events if e >= cutoff]


def _get_daily_total(sender: str) -> float:
    cutoff = time.time() - 86400  # 24 hours
    return sum(
        amount
        for ts, amount in _DAILY_VOLUME[sender]
        if ts >= cutoff
    )


def _record_transaction(sender: str, amount: float):
    """Record a transaction for rate tracking (call only on approval)."""
    now = time.time()
    _DAILY_VOLUME[sender].append((now, amount))
    _HOURLY_TX[sender].append(now)


def check(transaction) -> dict:
    """
    Check transfer limits for the transaction.

    Returns:
        {
            "passed": bool,
            "check": "limits",
            "flags": [ str ],
            "reason": str | None,
            "corridor": str,
            "corridor_limits": dict
        }
    """
    if hasattr(transaction, "to_dict"):
        tx = transaction.to_dict()
    else:
        tx = transaction

    sender = tx["sender"]
    amount = float(tx["amount"])
    sender_country = tx.get("sender_country", "").upper()
    receiver_country = tx.get("receiver_country", "").upper()

    corridor_key = f"{sender_country}-{receiver_country}"
    corridor = _get_corridor_limits(sender_country, receiver_country)

    flags = []

    # Hard block corridors (limit = 0)
    if corridor["single_tx_limit"] == 0:
        return {
            "passed": False,
            "check": "limits",
            "flags": ["corridor_blocked"],
            "reason": f"Corridor {corridor_key} is blocked — {corridor.get('notes', 'No transfers permitted')}",
            "corridor": corridor_key,
            "corridor_limits": corridor,
        }

    # Single transaction limit
    if amount > corridor["single_tx_limit"]:
        flags.append(
            f"single_tx_limit_exceeded: {amount} > {corridor['single_tx_limit']} USD"
        )

    # Daily cumulative limit
    daily_total = _get_daily_total(sender)
    if daily_total + amount > corridor["daily_limit_per_sender"]:
        flags.append(
            f"daily_limit_exceeded: cumulative {daily_total + amount:.2f} > "
            f"{corridor['daily_limit_per_sender']} USD"
        )

    # Hourly transaction count (from global defaults)
    hourly_count_limit = _DEFAULTS.get("hourly_tx_count_limit", 10)
    recent_hourly = _clean_window(list(_HOURLY_TX[sender]), 3600)
    if len(recent_hourly) >= hourly_count_limit:
        flags.append(
            f"hourly_tx_count_exceeded: {len(recent_hourly)} txns in last hour "
            f"(limit {hourly_count_limit})"
        )

    # High-risk country surcharge
    edd_required = corridor.get("requires_enhanced_due_diligence", False)
    is_high_risk = (sender_country in _HIGH_RISK or receiver_country in _HIGH_RISK)

    if flags:
        return {
            "passed": False,
            "check": "limits",
            "flags": flags,
            "reason": "Transfer limit violation: " + "; ".join(flags),
            "corridor": corridor_key,
            "corridor_limits": corridor,
            "enhanced_due_diligence_required": edd_required or is_high_risk,
        }

    return {
        "passed": True,
        "check": "limits",
        "flags": [],
        "reason": None,
        "corridor": corridor_key,
        "corridor_limits": corridor,
        "enhanced_due_diligence_required": edd_required or is_high_risk,
    }


def record_approved(transaction):
    """Must be called after a transaction is approved to update rate tracking."""
    if hasattr(transaction, "to_dict"):
        tx = transaction.to_dict()
    else:
        tx = transaction
    _record_transaction(tx["sender"], float(tx["amount"]))