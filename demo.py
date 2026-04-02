"""
demo_phase3.py
End-to-end demonstration of SecureChain — Phase 2 + Phase 3.
"""

from core.wallet import Wallet
from core.transaction import Transaction
from core.chain import Blockchain
from compliance import smart_contract
from identity import zkp_issuer
from identity.merkle_tree import MerkleTree


def separator(title):
    print(f"\n{'─' * 64}")
    print(f"  {title}")
    print(f"{'─' * 64}")


def run_scenario(label, tx, chain=None):
    print(f"\n[SCENARIO] {label}")
    has_proof = bool(tx.zkp_proof)
    print(f"  sender  : {tx.sender[:16]}...")
    print(f"  amount  : {tx.amount} {tx.currency}  ({tx.sender_country}→{tx.receiver_country})")
    print(f"  zkp     : {'attached' if has_proof else 'MISSING'}")
    result = smart_contract.run(tx)
    print(smart_contract.explain(result))
    if result["approved"] and chain:
        block = chain.add_block([tx.to_dict()])
        print(f"  ✓ Block #{block.index} sealed  hash={block.hash[:20]}...")
    return result


def main():
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║     SecureChain — Phase 2 + 3 Demo                      ║")
    print("║     ZKP Identity + Compliance Engine                    ║")
    print("╚══════════════════════════════════════════════════════════╝")

    separator("1. Create wallets")
    alice = Wallet()
    bob = Wallet()
    carol = Wallet()
    print(f"  Alice : {alice.address[:24]}...")
    print(f"  Bob   : {bob.address[:24]}...")
    print(f"  Carol : {carol.address[:24]}...")

    chain = Blockchain()
    tree = MerkleTree()

    separator("2. KYC onboarding — issue ZKP proofs via snarkjs")
    print("  Generating proofs (takes ~10-30 seconds each)...")

    alice_issued = zkp_issuer.issue_proof(alice.address, f"PASSPORT:GB12345678:1990-04-15:{alice.address}")
    bob_issued   = zkp_issuer.issue_proof(bob.address,   f"PASSPORT:US98765432:1985-08-22:{bob.address}")
    carol_issued = zkp_issuer.issue_proof(carol.address, f"PASSPORT:IN11223344:1995-12-01:{carol.address}")

    tree.insert(alice_issued["kyc_commitment"])
    tree.insert(bob_issued["kyc_commitment"])
    tree.insert(carol_issued["kyc_commitment"])

    print(f"\n  KYC registry Merkle root: {tree.root[:20]}...")
    print(f"  Registered wallets: {tree.size}")

    separator("3. Compliance scenarios")

    # A — Clean, valid proof
    tx_a = Transaction(alice.address, bob.address, 500, "USD", "US", "IN")
    tx_a.zkp_proof = {"proof": alice_issued["proof"], "public_signals": alice_issued["public_signals"]}
    alice.sign_transaction(tx_a)
    run_scenario("A — Clean $500 US→IN with valid proof (PASS)", tx_a, chain)

    # B — No proof attached
    tx_b = Transaction(alice.address, bob.address, 200, "USD", "US", "IN")
    run_scenario("B — No ZKP proof attached (REJECT at ZKP gate)", tx_b, chain)

    # C — Proof belongs to different wallet (commitment mismatch)
    tx_c = Transaction(carol.address, bob.address, 300, "USD", "US", "IN")
    tx_c.zkp_proof = {"proof": alice_issued["proof"], "public_signals": alice_issued["public_signals"]}
    run_scenario("C — Mismatched proof (alice's proof for carol's tx) (REJECT at ZKP)", tx_c, chain)

    # D — Blocked corridor
    tx_d = Transaction(alice.address, carol.address, 50, "USD", "US", "IR")
    tx_d.zkp_proof = {"proof": alice_issued["proof"], "public_signals": alice_issued["public_signals"]}
    alice.sign_transaction(tx_d)
    run_scenario("D — Blocked corridor US→IR (REJECT at limits)", tx_d, chain)

    # E — Exceeds limit
    tx_e = Transaction(alice.address, carol.address, 30000, "USD", "US", "IN")
    tx_e.zkp_proof = {"proof": alice_issued["proof"], "public_signals": alice_issued["public_signals"]}
    alice.sign_transaction(tx_e)
    run_scenario("E — Exceeds $25,000 limit (REJECT at limits)", tx_e, chain)

    # F — Structuring
    tx_f = Transaction(alice.address, bob.address, 9500, "USD", "US", "VE")
    tx_f.zkp_proof = {"proof": alice_issued["proof"], "public_signals": alice_issued["public_signals"]}
    alice.sign_transaction(tx_f)
    run_scenario("F — $9,500 structuring + high-risk country (REJECT at fraud)", tx_f, chain)

    # G — Carol's clean transaction
    tx_g = Transaction(carol.address, alice.address, 1200, "USD", "IN", "US")
    tx_g.zkp_proof = {"proof": carol_issued["proof"], "public_signals": carol_issued["public_signals"]}
    carol.sign_transaction(tx_g)
    run_scenario("G — Clean $1,200 IN→US (PASS + sealed)", tx_g, chain)

    separator("4. Merkle proof verification")
    proof = tree.get_proof(alice_issued["kyc_commitment"])
    valid = MerkleTree.verify_proof(alice_issued["kyc_commitment"], proof, tree.root)
    print(f"  Alice registered in tree: {valid}  (path length: {len(proof['path'])} steps)")
    bogus = MerkleTree.verify_proof("bogus_commitment_xyz", proof, tree.root)
    print(f"  Bogus commitment verifies: {bogus}")

    separator("5. Final blockchain state")
    chain_valid, msg = chain.is_valid()
    print(f"  Blocks: {len(chain)}  |  Valid: {chain_valid} — {msg}")
    for block in chain.chain:
        print(f"    Block #{block.index}  txns={len(block.transactions)}  hash={block.hash[:20]}...")

    print("\n✅ Phase 2 + 3 demo complete.\n")


if __name__ == "__main__":
    main()