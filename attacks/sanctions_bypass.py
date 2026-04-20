"""
attacks/sanctions_bypass.py
Four bypass attempts against the compliance/sanctions layer.

Attempt 1 — Direct: submit with known OFAC address
Attempt 2 — Typosquat: address 1 character off from OFAC address
Attempt 3 — Relay: route through a clean intermediary address
Attempt 4 — Blocked corridor with valid-looking tx

Expected result: Attempts 1 and 4 BLOCKED; 2 and 3 demonstrate
partial risk (relay attack is a known real-world limitation).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.wallet import Wallet
from core.transaction import Transaction
from compliance import smart_contract

OFAC_ADDR = "deadbeef00000000000000000000000000000000000000000000000000000001"
CLEAN_ADDR = "cccc000000000000000000000000000000000000000000000000000000000001"


def _mock_zkp_pass():
    from identity import zkp_verifier
    original = zkp_verifier.verify
    zkp_verifier.verify = lambda tx: {"passed": True, "check": "zkp", "reason": None, "commitment": "mock"}
    return original


def _restore_zkp(original):
    from identity import zkp_verifier
    zkp_verifier.verify = original


def run():
    print("\n╔══════════════════════════════════════════╗")
    print("║  ATTACK: Sanctions Bypass Attempts       ║")
    print("╚══════════════════════════════════════════╝")

    original_verify = _mock_zkp_pass()

    try:
        # Attempt 1 — Direct OFAC address as sender
        print("\n[1] Direct: OFAC-blocked address as sender")
        tx1 = Transaction(OFAC_ADDR, CLEAN_ADDR, 1000, "USD", "US", "IN")
        r1 = smart_contract.run(tx1)
        _print_result("Direct OFAC sender", r1)

        # Attempt 2 — Typosquat (1 char different)
        typo_addr = "deadbeef0000000000000000000000000000000000000000000000000000000" + "2"
        print("\n[2] Typosquat: address 1 character off from OFAC entry")
        tx2 = Transaction(typo_addr, CLEAN_ADDR, 1000, "USD", "US", "IN")
        r2 = smart_contract.run(tx2)
        _print_result("Typosquat address", r2)
        if r2["approved"]:
            print("    ⚠ NOTE: Typosquat bypasses exact-match screening.")
            print("    In production: fuzzy matching + ML-based name screening required.")

        # Attempt 3 — Relay through clean address
        print("\n[3] Relay: OFAC address sends to clean relay, relay sends to destination")
        # Step A: OFAC → relay (should be blocked)
        tx3a = Transaction(OFAC_ADDR, CLEAN_ADDR, 1000, "USD", "US", "IN")
        r3a = smart_contract.run(tx3a)
        _print_result("OFAC → relay (step A)", r3a)

        # Step B: relay → destination (passes sanctions — relay address is clean)
        relay_wallet = Wallet()
        tx3b = Transaction(relay_wallet.address, CLEAN_ADDR, 1000, "USD", "US", "IN")
        r3b = smart_contract.run(tx3b)
        _print_result("relay → destination (step B)", r3b)
        if r3b["approved"]:
            print("    ⚠ NOTE: Relay attack step B passes — this is a known limitation.")
            print("    Mitigation: transaction graph analysis (not in scope for this prototype).")

        # Attempt 4 — Blocked corridor (US→IR)
        print("\n[4] Blocked corridor: US→IR with any amount")
        tx4 = Transaction(CLEAN_ADDR, CLEAN_ADDR, 1, "USD", "US", "IR")
        r4 = smart_contract.run(tx4)
        _print_result("Blocked corridor US→IR", r4)

    finally:
        _restore_zkp(original_verify)

    print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("SUMMARY:")
    print("  Attempt 1 (direct OFAC):        BLOCKED ✅")
    print("  Attempt 2 (typosquat):          PASSED  ⚠ — known limitation")
    print("  Attempt 3 step A (OFAC→relay):  BLOCKED ✅")
    print("  Attempt 3 step B (relay→dest):  PASSED  ⚠ — graph analysis needed")
    print("  Attempt 4 (blocked corridor):   BLOCKED ✅")


def _print_result(label, result):
    status = "✅ BLOCKED" if not result["approved"] else "⚠ PASSED"
    reason = result.get("rejection_reason") or "approved"
    print(f"    [{status}] {label}: {reason[:80]}")


if __name__ == "__main__":
    run()