"""
compliance/sanctions.py
Screens transaction sender and receiver addresses against OFAC and UN
sanctions lists. Uses a local JSON database (simulated).
"""

import json
import os

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def _load_json(filename: str) -> dict:
    path = os.path.join(_DATA_DIR, filename)
    with open(path) as f:
        return json.load(f)


# Load lists once at module import — fast lookups
_OFAC = _load_json("ofac_list.json")
_UN = _load_json("un_list.json")

_OFAC_BLOCKED: set = set(_OFAC["blocked_addresses"])
_UN_BLOCKED: set = set(_UN["blocked_addresses"])
_UN_BLOCKED_COUNTRIES: set = {c["country_code"] for c in _UN.get("blocked_countries", [])}

# Build address → entity lookup for descriptive rejection messages
_OFAC_ENTITY_MAP: dict = {
    e["address"]: e for e in _OFAC.get("blocked_entities", [])
}
_UN_ENTITY_MAP: dict = {
    e["address"]: e for e in _UN.get("blocked_entities", [])
}


def screen_address(address: str) -> dict:
    """
    Check a single wallet address against all sanctions lists.

    Returns:
        {
            "blocked": bool,
            "list": "OFAC" | "UN" | None,
            "reason": str | None,
            "entity": dict | None
        }
    """
    address = address.lower()

    if address in _OFAC_BLOCKED:
        entity = _OFAC_ENTITY_MAP.get(address, {})
        return {
            "blocked": True,
            "list": "OFAC",
            "reason": entity.get("reason", "Address on OFAC SDN list"),
            "entity": entity,
        }

    if address in _UN_BLOCKED:
        entity = _UN_ENTITY_MAP.get(address, {})
        return {
            "blocked": True,
            "list": "UN",
            "reason": entity.get("reason", "Address on UN Consolidated Sanctions List"),
            "entity": entity,
        }

    return {"blocked": False, "list": None, "reason": None, "entity": None}


def screen_country(country_code: str) -> dict:
    """
    Check if a country is subject to comprehensive UN sanctions.

    Returns:
        { "blocked": bool, "reason": str | None }
    """
    code = country_code.upper()
    if code in _UN_BLOCKED_COUNTRIES:
        country_entries = [
            c for c in _UN.get("blocked_countries", [])
            if c["country_code"] == code
        ]
        reason = country_entries[0]["reason"] if country_entries else "Country under comprehensive UN sanctions"
        return {"blocked": True, "reason": reason}
    return {"blocked": False, "reason": None}


def check(transaction) -> dict:
    """
    Full sanctions check for a transaction.
    Screens sender address, receiver address, sender country, receiver country.

    Args:
        transaction: Transaction object or dict with keys:
                     sender, receiver, sender_country, receiver_country

    Returns:
        {
            "passed": bool,
            "check": "sanctions",
            "flags": [ { "field": str, "detail": dict } ],
            "reason": str | None
        }
    """
    if hasattr(transaction, "to_dict"):
        tx = transaction.to_dict()
    else:
        tx = transaction

    flags = []

    # Screen sender address
    sender_result = screen_address(tx["sender"])
    if sender_result["blocked"]:
        flags.append({"field": "sender", "detail": sender_result})

    # Screen receiver address
    receiver_result = screen_address(tx["receiver"])
    if receiver_result["blocked"]:
        flags.append({"field": "receiver", "detail": receiver_result})

    # Screen sender country
    sender_country_result = screen_country(tx.get("sender_country", ""))
    if sender_country_result["blocked"]:
        flags.append({"field": "sender_country", "detail": sender_country_result})

    # Screen receiver country
    receiver_country_result = screen_country(tx.get("receiver_country", ""))
    if receiver_country_result["blocked"]:
        flags.append({"field": "receiver_country", "detail": receiver_country_result})

    if flags:
        reasons = "; ".join(
            f'{f["field"]}: {f["detail"].get("reason", "sanctioned")}'
            for f in flags
        )
        return {
            "passed": False,
            "check": "sanctions",
            "flags": flags,
            "reason": f"Sanctions hit — {reasons}",
        }

    return {
        "passed": True,
        "check": "sanctions",
        "flags": [],
        "reason": None,
    }