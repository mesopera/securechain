"""
demo_phase3.py
End-to-end demonstration of SecureChain through Phase 3.

Demonstrates:
  1. Wallet creation and transaction signing
  2. All compliance check scenarios:
       a) Clean transaction — approved
       b) OFAC sanctioned sender — rejected
       c) UN sanctioned receiver — rejected
       d) Blocked corridor (US→IR) — rejected
       e) Exceeds transfer limit — rejected
       f) High fraud score (structuring) — rejected
       g) Transaction added to blockchain after approval
"""

from core.wallet import Wallet
from core.transaction import Transaction
from core.chain import Blockchain
from compliance import smart_contract


def separator(title):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def run_scenario(label, tx, chain=None):
    print(f"\n[SCENARIO] {label}")
    print(f"  sender  : {tx.sender[:16]}...")
    print(f"  receiver: {tx.receiver[:16]}...")
    print(f"  amount  : {tx.amount} {tx.currency}")
    print(f"  corridor: {tx.sender_country} → {tx.receiver_country}")

    result = smart_contract.run(tx)
    print(smart_contract.explain(result))

    if result["approved"] and chain:
        block = chain.add_block([tx.to_dict()])
        print(f"  ✓ Block #{block.index} sealed  hash={block.hash[:20]}...")

    return result


def main():
    separator("\t\t\tSecureChain")

    # Setup
    separator("1. Create wallets")
    alice = Wallet()
    bob = Wallet()
    carol = Wallet()
    print(f"  Alice  : {alice.address[:20]}...")
    print(f"  Bob    : {bob.address[:20]}...")
    print(f"  Carol  : {carol.address[:20]}...")

    chain = Blockchain()
    print(f"\n  Blockchain initialized: {chain}")

    # ── Scenario A: Clean transaction ──────────────────────────
    separator("2. Run compliance scenarios")

    tx_a = Transaction(alice.address, bob.address, 500, "USD", "US", "IN")
    alice.sign_transaction(tx_a)
    run_scenario("A — Clean $500 US→IN (should PASS)", tx_a, chain)

    # ── Scenario B: OFAC blocked sender ─────────────────────────
    ofac_addr = "deadbeef00000000000000000000000000000000000000000000000000000001"
    tx_b = Transaction(ofac_addr, bob.address, 1000, "USD", "US", "IN")
    run_scenario("B — OFAC sanctioned sender (should REJECT)", tx_b, chain)

    # ── Scenario C: UN blocked receiver ─────────────────────────
    un_addr = "1111111100000000000000000000000000000000000000000000000000000001"
    tx_c = Transaction(alice.address, un_addr, 200, "USD", "US", "GB")
    alice.sign_transaction(tx_c)
    run_scenario("C — UN sanctioned receiver (should REJECT)", tx_c, chain)

    # ── Scenario D: Blocked corridor ────────────────────────────
    tx_d = Transaction(alice.address, carol.address, 50, "USD", "US", "IR")
    alice.sign_transaction(tx_d)
    run_scenario("D — Blocked corridor US→IR (should REJECT)", tx_d, chain)

    # ── Scenario E: Exceeds limit ────────────────────────────────
    tx_e = Transaction(alice.address, carol.address, 30000, "USD", "US", "IN")
    alice.sign_transaction(tx_e)
    run_scenario("E — Exceeds $25,000 single-tx limit (should REJECT)", tx_e, chain)

    # ── Scenario F: Structuring (fraud) ─────────────────────────
    tx_f = Transaction(alice.address, bob.address, 9500, "USD", "US", "IR")
    alice.sign_transaction(tx_f)
    run_scenario("F — $9,500 structuring + high-risk country (should REJECT)", tx_f, chain)

    # ── Scenario G: Another clean transaction on chain ───────────
    tx_g = Transaction(carol.address, alice.address, 1200, "USD", "IN", "US")
    carol.sign_transaction(tx_g)
    run_scenario("G — Clean $1,200 IN→US (should PASS + add to chain)", tx_g, chain)

    # ── Chain state ──────────────────────────────────────────────
    separator("3. Final blockchain state")
    valid, msg = chain.is_valid()
    print(f"  Blocks  : {len(chain)}")
    print(f"  Valid   : {valid} — {msg}")
    for block in chain.chain:
        txn_count = len(block.transactions)
        print(f"    Block #{block.index}  txns={txn_count}  hash={block.hash[:20]}...")

    print("\n✅ Phase 3 demo complete.\n")


if __name__ == "__main__":
    main()