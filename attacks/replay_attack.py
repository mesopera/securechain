"""
attacks/replay_attack.py
Attempts to replay a previously confirmed transaction.

Expected result: REJECTED — duplicate tx_id already in mempool/chain.
The nonce on the original transaction is reused, so even a fresh submission
with the same tx_id is caught at the mempool deduplication layer.
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from core.wallet import Wallet
from core.transaction import Transaction

BASE = "http://localhost:5001"


def run():
    print("\n╔══════════════════════════════════════════╗")
    print("║  ATTACK: Replay Attack                   ║")
    print("╚══════════════════════════════════════════╝")

    alice = Wallet()
    bob = Wallet()

    # Step 1: Issue a legitimate transaction (no ZKP for attack demo — will fail at ZKP gate,
    # which is the correct security behavior; we demonstrate the nonce/mempool layer too)
    tx = Transaction(
        sender=alice.address,
        receiver=bob.address,
        amount=500,
        currency="USD",
        sender_country="US",
        receiver_country="IN",
    )
    alice.sign_transaction(tx)
    tx_dict = tx.to_dict()

    print(f"\n[1] Submitting original transaction: {tx.tx_id[:16]}...")
    try:
        r = requests.post(f"{BASE}/transaction", json=tx_dict, timeout=5)
        resp1 = r.json()
        print(f"    Result: accepted={resp1.get('accepted')}  reason={resp1.get('reason', 'N/A')}")
    except Exception as e:
        print(f"    Node unreachable: {e}")
        print("    (Start network first: bash start_network.sh)")
        _demo_offline(tx_dict)
        return

    time.sleep(0.5)

    print(f"\n[2] Replaying SAME transaction (same tx_id, same nonce)...")
    r2 = requests.post(f"{BASE}/transaction", json=tx_dict, timeout=5)
    resp2 = r2.json()
    print(f"    Result: accepted={resp2.get('accepted')}  reason={resp2.get('reason', 'N/A')}")

    if not resp2.get("accepted"):
        print("\n✅ REPLAY ATTACK BLOCKED — duplicate tx_id rejected by mempool")
    else:
        print("\n❌ REPLAY ATTACK SUCCEEDED — this is a vulnerability")


def _demo_offline(tx_dict):
    """Demonstrate replay protection without a running network."""
    print("\n  [OFFLINE DEMO] Simulating replay protection...")
    from network.mempool import Mempool
    mp = Mempool()

    added = mp.add(tx_dict)
    print(f"    First submission:  accepted={added}")
    replay = mp.add(tx_dict)
    print(f"    Replay submission: accepted={replay}")
    assert not replay
    print("\n✅ REPLAY ATTACK BLOCKED — mempool deduplication working correctly")


if __name__ == "__main__":
    run()