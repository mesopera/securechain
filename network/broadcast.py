"""
network/broadcast.py
Node-to-node HTTP messaging. Sends requests to peer nodes.
"""
import requests

TIMEOUT = 3  # seconds


def post(url: str, data: dict) -> dict | None:
    try:
        r = requests.post(url, json=data, timeout=TIMEOUT)
        return r.json() if r.ok else None
    except Exception:
        return None


def get(url: str) -> dict | None:
    try:
        r = requests.get(url, timeout=TIMEOUT)
        return r.json() if r.ok else None
    except Exception:
        return None


def broadcast_to_peers(peers: list[str], endpoint: str, data: dict) -> list[dict]:
    """Send POST to endpoint on every peer. Returns list of successful responses."""
    results = []
    for peer in peers:
        resp = post(f"{peer}{endpoint}", data)
        if resp:
            results.append(resp)
    return results


def fetch_chain(peer: str) -> list | None:
    resp = get(f"{peer}/chain")
    return resp.get("chain") if resp else None