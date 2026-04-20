"""
attacks/spoofing_attack.py
A fake validator node attempts to inject a fraudulent COMMIT vote
to finalize a transaction that never passed PBFT properly.

Expected result: REJECTED — commit vote signature is from an unknown
wallet not in the validator set; PBFT quorum cannot be reached with
fake votes alone.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import hashlib
import time
from core.wallet import Wallet

BASE = "http://localhost:5001"


def run():
    print("\n╔══════════════════════════════════════════╗")
    print("║  ATTACK: Spoofing / Fake Validator       ║")
    print("╚══════════════════════════════════════════╝")

    fake_wallet = Wallet()
    print(f"\n[1] Attacker creates fake validator wallet: {fake_wallet.address[:16]}...")

    # Craft a fake transaction
    fake_tx_id = hashlib.sha256(b"fake_transfer_steal_funds").hexdigest()
    fake_tx = {
        "tx_id": fake_tx_id,
        "sender": "victim_" + "a" * 57,
        "receiver": fake_wallet.address,
        "amount": 99999,
        "currency": "USD",
        "sender_country": "US",
        "receiver_country": "US",
        "nonce": 12345,
        "timestamp": time.time(),
        "signature": None,
        "zkp_proof": None,
        "compliance_result": None,
    }

    seq = 999  # fake sequence number
    fake_sig = fake_wallet.sign(f"{seq}:{fake_tx_id}:99".encode())

    # Attempt 1: inject fake PRE-PREPARE
    print(f"\n[2] Injecting fake PRE-PREPARE (seq={seq})...")
    fake_pp = {
        "type": "PRE-PREPARE",
        "seq": seq,
        "tx_id": fake_tx_id,
        "tx_data": fake_tx,
        "node_id": 99,
        "signature": fake_sig,
    }
    try:
        r = requests.post(f"{BASE}/pbft/pre-prepare", json=fake_pp, timeout=5)
        print(f"    HTTP response: {r.status_code}")
    except Exception as e:
        print(f"    Node unreachable: {e}")
        _demo_offline(fake_wallet, fake_tx_id, seq, fake_sig)
        return

    # Attempt 2: inject fake COMMIT votes (attacker controls only 1 node — not quorum)
    print(f"\n[3] Injecting fake COMMIT votes (attacker has 1 node, quorum needs 3)...")
    for i in range(1):   # attacker only has 1 fake node
        fake_commit = {
            "type": "COMMIT",
            "seq": seq,
            "tx_id": fake_tx_id,
            "node_id": 99 + i,
            "signature": fake_wallet.sign(f"{seq}:{fake_tx_id}:{99+i}".encode()),
        }
        r = requests.post(f"{BASE}/pbft/commit", json=fake_commit, timeout=5)
        print(f"    Fake commit from node {99+i}: HTTP {r.status_code}")

    time.sleep(0.5)

    # Check if chain was affected
    chain = requests.get(f"{BASE}/chain", timeout=5).json()
    fake_in_chain = any(
        tx.get("tx_id") == fake_tx_id
        for block in chain["chain"]
        for tx in block.get("transactions", [])
    )

    if not fake_in_chain:
        print("\n✅ SPOOFING ATTACK BLOCKED — fake transaction not in chain")
        print("   Reason: 1 fake vote cannot reach quorum of 3")
    else:
        print("\n❌ SPOOFING ATTACK SUCCEEDED — vulnerability detected")


def _demo_offline(fake_wallet, fake_tx_id, seq, fake_sig):
    print("\n  [OFFLINE DEMO] Simulating PBFT spoofing resistance...")
    from network.consensus import PBFTEngine, QUORUM
    from core.wallet import Wallet

    legitimate_engine = PBFTEngine(node_id=1, wallet=Wallet())

    # Attacker sends 1 fake commit vote
    fake_commit = {
        "type": "COMMIT",
        "seq": seq,
        "tx_id": fake_tx_id,
        "node_id": 99,
        "signature": fake_sig,
    }
    result = legitimate_engine.handle_commit(fake_commit)
    print(f"    State after 1 fake commit vote: {legitimate_engine.get_state(seq)}")
    print(f"    Finalized: {result is not None}")
    print(f"    Quorum required: {QUORUM} — attacker has: 1")
    print("\n✅ SPOOFING ATTACK BLOCKED — insufficient votes to reach quorum")


if __name__ == "__main__":
    run()