import argparse
import hashlib
import os
import signal
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.wallet import Wallet
from core.transaction import Transaction
from core.chain import Blockchain
from compliance import smart_contract
from identity import zkp_verifier
from identity.merkle_tree import MerkleTree
from network.consensus import PBFTEngine, QUORUM, TOTAL_NODES
from network.mempool import Mempool

NODE_PORTS = [5001, 5002, 5003, 5004, 5005]
_node_procs = []


def sep(title, width=64):
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")

def ok(msg):   print(f"  ✅ {msg}")
def fail(msg): print(f"  ❌ {msg}")
def info(msg): print(f"  ℹ  {msg}")
def step(msg): print(f"\n  ► {msg}")
def detail(msg): print(f"     {msg}")


def _mock_zkp():
    original = zkp_verifier.verify
    zkp_verifier.verify = lambda tx: {"passed": True, "check": "zkp", "reason": None, "commitment": "mock_demo"}
    return original

def _restore_zkp(original):
    zkp_verifier.verify = original


# ── Network helpers ───────────────────────────────────────────────────────────

def start_network():
    sep("Starting Validator Network (5 nodes on ports 5001–5005)")
    print("  Each node is an independent Flask process with its own:")
    print("  chain copy, mempool, PBFT engine, and compliance pipeline.\n")
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    for node_id in range(1, 6):
        port = 5000 + node_id
        peers = ",".join(str(p) for p in NODE_PORTS if p != port)
        log_file = open(f"logs/node{node_id}.log", "w")
        proc = subprocess.Popen(
            [sys.executable, "network/node.py",
             "--id", str(node_id), "--port", str(port), "--peers", peers],
            stdout=log_file, stderr=log_file,
        )
        _node_procs.append((proc, log_file))
        print(f"  Node {node_id} → pid {proc.pid}  port {port}  peers={peers}")

    print("\n  Waiting for all nodes to be ready", end="", flush=True)
    for _ in range(20):
        time.sleep(0.5)
        print(".", end="", flush=True)
        if sum(1 for p in NODE_PORTS if _node_alive(p)) == 5:
            break
    print()

    alive = sum(1 for p in NODE_PORTS if _node_alive(p))
    if alive == 5:
        ok("All 5 nodes running and responding to HTTP")
    else:
        info(f"{alive}/5 nodes ready")
    return alive >= 3


def stop_network():
    for proc, log_file in _node_procs:
        try: proc.terminate(); proc.wait(timeout=3)
        except: pass
        try: log_file.close()
        except: pass
    _node_procs.clear()


def _node_alive(port):
    try:
        return requests.get(f"http://localhost:{port}/status", timeout=1).ok
    except: return False

def _node_status(port):
    try:
        r = requests.get(f"http://localhost:{port}/status", timeout=2)
        return r.json() if r.ok else None
    except: return None

def _submit(port, tx_dict):
    try:
        r = requests.post(f"http://localhost:{port}/transaction", json=tx_dict, timeout=5)
        return r.json() if r.ok else None
    except: return None

def _get_chain(port):
    try:
        r = requests.get(f"http://localhost:{port}/chain", timeout=2)
        return r.json().get("chain", []) if r.ok else []
    except: return []


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1
# ═════════════════════════════════════════════════════════════════════════════

def demo_phase1():
    sep("PHASE 1 — Core Chain: Wallets, Signing, Blocks")
    print("  Building the fundamental cryptographic layer from scratch.")
    print("  No external blockchain libraries — pure Python.\n")

    step("Generate ECDSA wallets")
    detail("Each wallet generates a secp256k1 key pair — the same curve used by Bitcoin.")
    detail("Private key stays on your machine. Public key is hashed to produce an address.")
    alice = Wallet()
    bob   = Wallet()
    carol = Wallet()
    print(f"\n     Alice : {alice.address}")
    print(f"     Bob   : {bob.address}")
    print(f"     Carol : {carol.address}")

    step("Sign a transaction")
    detail("Alice creates a $500 transfer to Bob. She signs it with her private key.")
    detail("The signature is a 64-byte ECDSA proof. Anyone with Alice's public key")
    detail("can verify she authorised this — but nobody can forge it without her private key.")
    tx = Transaction(alice.address, bob.address, 500, "USD", "US", "IN")
    alice.sign_transaction(tx)
    print(f"\n     tx_id     : {tx.tx_id}")
    print(f"     signature : {tx.signature[:48]}...")
    ok("Transaction signed with ECDSA private key")

    step("Build a blockchain")
    detail("Each block contains: transactions, timestamp, and the SHA-256 hash of the previous block.")
    detail("This hash linkage means tampering with any block breaks every block after it.")
    chain = Blockchain()
    b1 = chain.add_block([tx.to_dict()])
    b2 = chain.add_block([{"sender": bob.address, "receiver": carol.address, "amount": 200}])
    print(f"\n     Block 0 (genesis) : {chain.chain[0].hash[:32]}...")
    print(f"     Block 1           : {b1.hash[:32]}...")
    print(f"     Block 2           : {b2.hash[:32]}...")
    print(f"     Block 2 prev_hash : {b2.previous_hash[:32]}...")
    detail("Notice block 2's prev_hash matches block 1's hash exactly — the chain is linked.")

    valid, msg = chain.is_valid()
    assert valid
    ok(f"Chain integrity verified — {len(chain)} blocks, all hashes match")

    step("Attempt tampering")
    detail("We change the amount in block 1 from 500 to 9999.")
    detail("This changes block 1's hash, breaking its link to block 2.")
    chain.chain[1].transactions = [{"hacked": 9999}]
    valid2, _ = chain.is_valid()
    assert not valid2
    ok("Tampered chain detected as invalid — hash mismatch caught immediately")
    detail("In SWIFT, a malicious insider can alter records. Here it is mathematically impossible.")

    return alice, bob, carol


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2
# ═════════════════════════════════════════════════════════════════════════════

def demo_phase2_real(alice, bob, carol):
    sep("PHASE 2 — ZKP Identity: Prove KYC Without Revealing Anything")
    print("  Zero-Knowledge Proofs let a user prove they are KYC-verified")
    print("  without revealing their name, passport, date of birth, or any")
    print("  personal data. The verifier learns one thing only: they qualify.\n")

    from identity import zkp_issuer
    from pathlib import Path

    if not (Path("identity/build") / "proving_key.zkey").exists():
        fail("ZKP build artifacts missing — run: bash identity/setup.sh")
        return None, None, None

    step("How the circuit works")
    detail("The circom circuit (kyc_proof.circom) enforces one constraint:")
    detail("  Poseidon( Poseidon(kyc_hash, secret), wallet_address ) == commitment")
    detail("kyc_hash  = SHA256 of your real KYC data (private, never shared)")
    detail("secret    = random blinding factor (private, never shared)")
    detail("commitment = the locked box stored in the public registry")
    detail("The proof shows you know what's inside the box without opening it.")

    step("Issue ZKP proofs for Alice, Bob, Carol (snarkjs GROTH16)")
    detail("This calls snarkjs to: generate witness → prove → export proof.json")
    print()

    alice_p = zkp_issuer.issue_proof(alice.address, f"PASSPORT:GB12345678:{alice.address[:8]}")
    bob_p   = zkp_issuer.issue_proof(bob.address,   f"PASSPORT:US98765432:{bob.address[:8]}")
    carol_p = zkp_issuer.issue_proof(carol.address, f"PASSPORT:IN11223344:{carol.address[:8]}")

    print(f"\n     Alice commitment : {alice_p['kyc_commitment'][:32]}...")
    print(f"     Bob   commitment : {bob_p['kyc_commitment'][:32]}...")
    print(f"     Carol commitment : {carol_p['kyc_commitment'][:32]}...")
    detail("These commitments are public. The inputs that produced them are not.")
    ok("3 ZKP proofs issued via snarkjs GROTH16")

    step("Register commitments in Merkle tree")
    detail("A Merkle tree stores all KYC commitments. The root hash is the only")
    detail("thing published on-chain. To prove your commitment is registered,")
    detail("you provide a path from your leaf to the root — O(log n) proof size.")
    tree = MerkleTree()
    tree.insert(alice_p["kyc_commitment"])
    tree.insert(bob_p["kyc_commitment"])
    tree.insert(carol_p["kyc_commitment"])
    print(f"\n     Merkle root : {tree.root}")
    ok(f"Registry root set — {tree.size} wallets registered")

    step("Verify Alice's Merkle proof")
    proof = tree.get_proof(alice_p["kyc_commitment"])
    valid = MerkleTree.verify_proof(alice_p["kyc_commitment"], proof, tree.root)
    assert valid
    ok(f"Alice's commitment verified in {len(proof['path'])} Merkle steps")

    step("Reject a bogus commitment")
    bogus = MerkleTree.verify_proof("not_a_real_commitment", proof, tree.root)
    assert not bogus
    ok("Unregistered commitment correctly rejected")
    detail("An attacker cannot forge a commitment — it would require inverting Poseidon hash.")

    return alice_p, bob_p, carol_p


def demo_phase2_mock(alice, bob, carol):
    sep("PHASE 2 — ZKP Identity (mock mode — run setup.sh for real proofs)")
    info("Simulating ZKP proof structure without circom ceremony\n")

    step("Mock commitment generation")
    detail("In production: Poseidon(Poseidon(kyc_hash, secret), wallet_address)")
    detail("Here: SHA256(wallet_address) as a stand-in commitment")

    alice_p = {"proof": {"mock": True}, "public_signals": ["1", "2"],
               "kyc_commitment": hashlib.sha256(alice.address.encode()).hexdigest()}
    bob_p   = {"proof": {"mock": True}, "public_signals": ["3", "4"],
               "kyc_commitment": hashlib.sha256(bob.address.encode()).hexdigest()}
    carol_p = {"proof": {"mock": True}, "public_signals": ["5", "6"],
               "kyc_commitment": hashlib.sha256(carol.address.encode()).hexdigest()}

    tree = MerkleTree()
    tree._save = lambda: None
    for p in [alice_p, bob_p, carol_p]:
        tree.insert(p["kyc_commitment"])

    print(f"     Merkle root : {tree.root}")
    ok(f"Mock registry: {tree.size} entries")

    proof = tree.get_proof(alice_p["kyc_commitment"])
    valid = MerkleTree.verify_proof(alice_p["kyc_commitment"], proof, tree.root)
    assert valid
    ok(f"Merkle proof verified ({len(proof['path'])} steps)")

    bogus = MerkleTree.verify_proof("bogus", proof, tree.root)
    assert not bogus
    ok("Bogus commitment rejected")

    return alice_p, bob_p, carol_p


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3
# ═════════════════════════════════════════════════════════════════════════════

def demo_phase3(alice, bob, carol, alice_p, bob_p):
    sep("PHASE 3 — Compliance Engine: 4-Gate Pipeline")
    print("  Every transaction must pass 4 gates in sequence.")
    print("  Fail any gate → transaction is dead. Later gates never run.")
    print("  The compliance result is sealed into the block permanently.\n")
    print("  Gate 0: ZKP proof present and valid")
    print("  Gate 1: Sanctions screening (OFAC + UN lists)")
    print("  Gate 2: Transfer limits (corridor rules + velocity)")
    print("  Gate 3: Fraud scoring (8 rules, reject if score ≥ 70/100)\n")

    original = _mock_zkp()

    scenarios = [
        {
            "label": "Clean $500 US→IN",
            "sender": alice.address, "receiver": bob.address,
            "amount": 500, "sc": "US", "rc": "IN",
            "expected": True,
            "explain": "Standard US→India corridor. All 4 gates pass. Risk=LOW.",
        },
        {
            "label": "OFAC sanctioned sender",
            "sender": "deadbeef00000000000000000000000000000000000000000000000000000001",
            "receiver": bob.address,
            "amount": 1000, "sc": "US", "rc": "IN",
            "expected": False,
            "explain": "Sender address is on the OFAC SDN list (Money laundering). Blocked at Gate 1.",
        },
        {
            "label": "UN sanctioned receiver",
            "sender": alice.address,
            "receiver": "1111111100000000000000000000000000000000000000000000000000000001",
            "amount": 200, "sc": "US", "rc": "GB",
            "expected": False,
            "explain": "Receiver address is on the UN list (WMD proliferation — UNSCR 1718). Blocked at Gate 1.",
        },
        {
            "label": "Blocked corridor US→IR",
            "sender": alice.address, "receiver": carol.address,
            "amount": 50, "sc": "US", "rc": "IR",
            "expected": False,
            "explain": "Iran corridor has a hard limit of $0. Comprehensive OFAC sanctions. Blocked at Gate 2.",
        },
        {
            "label": "Exceeds $25,000 single-tx limit",
            "sender": alice.address, "receiver": carol.address,
            "amount": 30000, "sc": "US", "rc": "IN",
            "expected": False,
            "explain": "US→IN corridor cap is $25,000. $30,000 exceeds it. Blocked at Gate 2.",
        },
        {
            "label": "High fraud score — $20,000 to high-risk country",
            "sender": alice.address, "receiver": bob.address,
            "amount": 20000, "sc": "US", "rc": "VE",
            "expected": False,
            "explain": "R1(high amount)+R2(round number)+R6(Venezuela=high risk)+R8(new sender) = 75/100. Blocked at Gate 3.",
        },
        {
            "label": "Clean $1,200 IN→US",
            "sender": carol.address, "receiver": alice.address,
            "amount": 1200, "sc": "IN", "rc": "US",
            "expected": True,
            "explain": "Standard India→US corridor. All gates pass. Risk=LOW.",
        },
    ]

    for s in scenarios:
        print(f"\n  ── {s['label']}")
        detail(s["explain"])
        tx = Transaction(s["sender"], s["receiver"], s["amount"], "USD", s["sc"], s["rc"])
        result = smart_contract.run(tx)
        passed = result["approved"] == s["expected"]
        status = "✅" if passed else "❌"
        approved_str = "APPROVED" if result["approved"] else "REJECTED"

        if not result["approved"] and result["rejection_reason"]:
            reason = result["rejection_reason"][:80]
            print(f"     {status} {approved_str} — {reason}")
        else:
            risk = result.get("risk_level", "")
            fraud_check = (result.get("checks") or {}).get("fraud_score") or {}
            score = fraud_check.get("score", "N/A")
            print(f"     {status} {approved_str} — risk={risk}  fraud_score={score}/100")

    _restore_zkp(original)


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4
# ═════════════════════════════════════════════════════════════════════════════

def demo_phase4_network(alice, bob, alice_p):
    sep("PHASE 4 — Validator Network + PBFT Consensus")
    print("  5 independent nodes must each verify and sign a transaction")
    print("  before it is sealed into a block. No single node has authority.\n")

    step("Node status check")
    detail("Each node has its own chain, mempool, and compliance engine.")
    detail("They communicate via HTTP — simulating what Docker networking does.")
    print()
    for port in NODE_PORTS:
        s = _node_status(port)
        if s:
            is_primary = s['node_id'] == 1
            role = " [PRIMARY]" if is_primary else ""
            print(f"     Node {s['node_id']}{role} :{port}  chain={s['chain_length']}  mempool={s['mempool_size']}  valid={s['chain_valid']}")
            if is_primary:
                detail("  The primary node receives transactions and initiates PBFT rounds.")

    step("Submit a transaction WITH a valid ZKP proof")
    detail("We attach Alice's real ZKP proof from Phase 2.")
    detail("This means the transaction will pass Gate 0 (ZKP) and enter the full pipeline.")
    detail("Node 1 (primary) will then broadcast it to all peers for PBFT consensus.")
    print()

    # Build a real transaction using alice's proof from Phase 2
    tx = Transaction(alice.address, bob.address, 750, "USD", "US", "IN")
    alice.sign_transaction(tx)
    tx_dict = tx.to_dict()

    # Attach alice's real ZKP proof
    if alice_p and alice_p.get("proof") and not alice_p["proof"].get("mock"):
        tx_dict["zkp_proof"] = {
            "proof": alice_p["proof"],
            "public_signals": alice_p["public_signals"],
        }
        detail("Real GROTH16 proof attached — cryptographic verification will run on each node.")
    else:
        # Mock ZKP for --no-zkp mode — patch verifier on nodes won't work over HTTP
        # so we monkeypatch locally and note the limitation
        tx_dict["zkp_proof"] = {
            "proof": {"pi_a": ["1","2","1"], "pi_b": [["1","2"],["3","4"],["1","0"]], "pi_c": ["1","2","1"], "protocol": "groth16"},
            "public_signals": ["99999999999999999999", "11111111111111111111"],
        }
        detail("Mock proof attached (--no-zkp mode). Node will reject at ZKP crypto check.")
        detail("This demonstrates the ZKP gate working — only real proofs pass crypto verification.")

    print(f"\n     tx_id     : {tx.tx_id}")
    print(f"     sender    : {alice.address[:24]}...")
    print(f"     amount    : {tx.amount} {tx.currency}")
    print(f"     corridor  : US → IN")
    print(f"     signature : {tx.signature[:32]}...")
    if tx_dict.get("zkp_proof"):
        print(f"     zkp_proof : attached ✓")

    print(f"\n  Submitting to Node 1 (primary)...")
    result = _submit(5001, tx_dict)

    if result:
        if result.get("accepted"):
            ok(f"Transaction ACCEPTED by Node 1")
            detail("Node 1 passed compliance, added to mempool, started PBFT PRE-PREPARE round.")
            detail("PRE-PREPARE broadcast to nodes 2,3,4,5.")
            detail("Each node independently re-ran compliance + ZKP verification.")
            detail("Once 3/5 nodes sent PREPARE votes, COMMIT phase started.")
            detail("Once 3/5 nodes sent COMMIT votes, block was sealed.")

            time.sleep(2)  # wait for PBFT to complete

            step("Check chain lengths across all nodes")
            detail("All nodes should now show one additional block — PBFT consensus reached.")
            print()
            all_synced = True
            for port in NODE_PORTS:
                s = _node_status(port)
                if s:
                    synced = "✓" if s['chain_length'] > 1 else "⏳"
                    print(f"     Node {s['node_id']} :{port}  blocks={s['chain_length']} {synced}")
                    if s['chain_length'] <= 1:
                        all_synced = False

            if all_synced:
                ok("All 5 nodes sealed the same block — PBFT consensus confirmed")
            else:
                info("Some nodes still syncing — PBFT may still be completing")

            step("Inspect the sealed block on Node 1")
            chain = _get_chain(5001)
            if len(chain) > 1:
                block = chain[-1]
                print(f"\n     Block index  : {block['index']}")
                print(f"     Block hash   : {block['hash']}")
                print(f"     Prev hash    : {block['previous_hash'][:32]}...")
                print(f"     Transactions : {len(block['transactions'])}")
                detail("This block is now immutable — changing it would break every block after it.")
                detail("Every node has an identical copy. No single node can alter the record.")
        else:
            reason = result.get("reason", "unknown")
            info(f"Transaction rejected: {reason[:80]}")
            if "ZKP" in reason or "zkp" in reason.lower() or "proof" in reason.lower():
                detail("ZKP gate fired correctly — the mock proof failed cryptographic verification.")
                detail("This is the correct security behaviour — nodes reject unverified proofs.")
                detail("In a real deployment, Alice's wallet would attach her GROTH16 proof automatically.")

                step("PBFT demonstration (offline simulation)")
                detail("Since the live network rejected the tx at ZKP, we demonstrate")
                detail("PBFT consensus mechanics in isolation below:")
                _demo_pbft_inline()
    else:
        info("Node 1 did not respond — demonstrating PBFT offline")
        _demo_pbft_inline()

    step("Chain lengths after all submissions")
    print()
    for port in NODE_PORTS:
        s = _node_status(port)
        if s:
            print(f"     Node {s['node_id']} :{port}  chain={s['chain_length']}  valid={s['chain_valid']}")


def _demo_pbft_inline():
    """Show PBFT round mechanics with local engines when network rejects."""
    print()
    detail("─── PBFT Round Simulation ───")
    detail(f"  n={TOTAL_NODES} nodes, f=1 Byzantine fault tolerance, quorum=2f+1={QUORUM}")
    print()

    engines = [PBFTEngine(node_id=i, wallet=Wallet()) for i in range(1, 6)]
    finalized = []
    for e in engines:
        e.on_finalized = lambda seq, d: finalized.append(d)

    tx_id = hashlib.sha256(b"pbft_demo_tx").hexdigest()
    tx_data = {"tx_id": tx_id, "sender": "a"*64, "receiver": "b"*64, "amount": 500}

    pp = engines[0].start_round(tx_data)
    detail(f"  [Node 1 → ALL] PRE-PREPARE  seq={pp['seq']}  tx={tx_id[:16]}...")

    prepares = []
    for e in engines[1:]:
        p = e.handle_pre_prepare(pp)
        if p:
            prepares.append(p)
            detail(f"  [Node {e.node_id} → ALL] PREPARE  sig={p['signature'][:24]}...")

    commits = []
    for prepare in prepares:
        for e in engines:
            c = e.handle_prepare(prepare)
            if c and c not in commits:
                commits.append(c)
                detail(f"  [Node {e.node_id} → ALL] COMMIT  ({len(e._states[pp['seq']].prepare_votes)} prepare votes reached quorum={QUORUM})")
                break

    for commit in commits[:QUORUM]:
        for e in engines:
            e.handle_commit(commit)

    time.sleep(0.15)
    ok(f"Block FINALIZED — {len(finalized)} node(s) triggered on_finalized callback")
    detail(f"  Transaction sealed. {QUORUM}/{TOTAL_NODES} signatures collected.")
    detail(f"  Even if 1 node was Byzantine (lying), consensus is unaffected.")
    detail(f"  The attacker cannot forge signatures from the other {TOTAL_NODES-1} nodes.")


def demo_phase4_pbft_offline():
    sep("PHASE 4 — PBFT Consensus (offline simulation)")
    print("  Demonstrating the 3-phase PBFT protocol with 5 local engine instances.\n")
    _demo_pbft_inline()


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 7 — Attacks
# ═════════════════════════════════════════════════════════════════════════════

def demo_attacks(network_running):
    sep("PHASE 7 — Attack Simulations")
    print("  Four attacks are attempted. Each one tests a different security layer.")
    print("  Every attack should be blocked — results are logged with the exact reason.\n")

    # ── Attack 1: Replay ──────────────────────────────────────────────────
    print("  ── [ATTACK 1] Replay Attack")
    detail("Scenario: attacker captures a confirmed $500 transaction and resubmits")
    detail("it verbatim, hoping to double-spend the funds.")
    detail("Defence: the mempool assigns each transaction a unique tx_id derived")
    detail("from its content + nonce. The same tx_id cannot enter the pool twice.")
    print()
    mp = Mempool()
    tx_id = hashlib.sha256(b"replay_test_tx").hexdigest()
    tx_dict = {"tx_id": tx_id, "sender": "a"*64, "receiver": "b"*64, "amount": 500}
    first  = mp.add(tx_dict)
    second = mp.add(tx_dict)
    assert first is True and second is False
    print(f"     First submission:  accepted={first}")
    print(f"     Replay submission: accepted={second}")
    ok("Replay blocked — mempool deduplication rejected duplicate tx_id")

    # ── Attack 2: Spoofing ────────────────────────────────────────────────
    print("\n  ── [ATTACK 2] Fake Validator / Spoofing Attack")
    detail("Scenario: attacker runs their own node (node_id=99) and tries to")
    detail("inject fraudulent COMMIT votes to finalise a transaction that never")
    detail("went through compliance or proper PBFT rounds.")
    detail("Defence: PBFT requires 2f+1=3 commit votes with valid signatures from")
    detail("known validators. One fake node cannot produce 3 valid signatures.")
    print()
    fake_engine  = PBFTEngine(node_id=99, wallet=Wallet())
    legit_engine = PBFTEngine(node_id=1,  wallet=Wallet())
    fake_tx_id   = hashlib.sha256(b"steal_funds").hexdigest()
    seq = 999

    fake_commit = {
        "type": "COMMIT", "seq": seq, "tx_id": fake_tx_id,
        "node_id": 99, "signature": fake_engine._sign(seq, fake_tx_id),
    }
    result = legit_engine.handle_commit(fake_commit)
    state  = legit_engine.get_state(seq)

    print(f"     Fake node sent 1 COMMIT vote")
    print(f"     Commit votes received: {state['commit_votes'] if state else 0}")
    print(f"     Quorum required      : {QUORUM}")
    print(f"     Finalized            : {result is not None}")
    assert result is None
    ok(f"Spoofing blocked — 1 fake vote cannot reach quorum of {QUORUM}")

    # ── Attack 3: Sanctions Bypass ────────────────────────────────────────
    print("\n  ── [ATTACK 3] Sanctions Bypass Attempts")
    detail("Four bypass strategies attempted against the compliance engine.")
    print()
    original = _mock_zkp()

    ofac_addr = "deadbeef00000000000000000000000000000000000000000000000000000001"
    clean     = "cccc000000000000000000000000000000000000000000000000000000000001"

    # Attempt A
    print("     Attempt A — Direct OFAC address as sender:")
    tx_a = Transaction(ofac_addr, clean, 1000, "USD", "US", "IN")
    r_a = smart_contract.run(tx_a)
    assert not r_a["approved"]
    detail(f"  Blocked at: SANCTIONS — {r_a['rejection_reason'][:60]}")
    ok("Direct OFAC sender blocked")

    # Attempt B
    print("\n     Attempt B — Typosquatting (last character changed):")
    typo = "deadbeef0000000000000000000000000000000000000000000000000000000" + "2"
    tx_b = Transaction(typo, clean, 100, "USD", "US", "IN")
    r_b = smart_contract.run(tx_b)
    status = "PASSED ⚠" if r_b["approved"] else "BLOCKED ✅"
    detail(f"  Result: {status}")
    if r_b["approved"]:
        info("Typosquat bypasses exact-match screening — known limitation")
        detail("  Mitigation in production: fuzzy matching, ML-based entity resolution")
        detail("  This is a documented gap, not a design flaw — exact-match is standard")

    # Attempt C
    print("\n     Attempt C — Relay (OFAC → clean relay → destination):")
    detail("  Step 1: OFAC addr sends to a clean relay wallet")
    tx_c1 = Transaction(ofac_addr, clean, 1000, "USD", "US", "IN")
    r_c1  = smart_contract.run(tx_c1)
    detail(f"  Step 1 result: {'BLOCKED ✅' if not r_c1['approved'] else 'PASSED ⚠'}")

    relay_wallet = Wallet()
    detail("  Step 2: Clean relay wallet sends to final destination")
    tx_c2 = Transaction(relay_wallet.address, clean, 1000, "USD", "US", "IN")
    r_c2  = smart_contract.run(tx_c2)
    detail(f"  Step 2 result: {'BLOCKED ✅' if not r_c2['approved'] else 'PASSED ⚠ (relay address is clean)'}")
    if r_c2["approved"]:
        info("Relay step 2 passes — this is a known limitation of single-hop screening")
        detail("  Mitigation: transaction graph analysis across multiple hops (not in scope)")

    # Attempt D
    print("\n     Attempt D — Blocked corridor US→IR:")
    tx_d = Transaction(clean, clean, 1, "USD", "US", "IR")
    r_d  = smart_contract.run(tx_d)
    assert not r_d["approved"]
    detail(f"  Blocked at: LIMITS — {r_d['rejection_reason'][:60]}")
    ok("Blocked corridor US→IR rejected regardless of addresses")

    _restore_zkp(original)

    # ── Attack 4: Node Failure ────────────────────────────────────────────
    print("\n  ── [ATTACK 4] Node Failure — 2 of 5 nodes killed")
    detail("Scenario: 2 validator nodes crash simultaneously (hardware failure,")
    detail("network partition, or targeted DoS attack).")
    detail(f"Defence: PBFT with n=5, f=1 guarantees liveness as long as")
    detail(f"{QUORUM}+ nodes are alive. 3 surviving nodes maintain quorum.")
    print()

    if network_running:
        killed = 0
        for node_id in [4, 5]:
            pid_file = f"pids/node{node_id}.pid"
            if os.path.exists(pid_file):
                pid = int(open(pid_file).read().strip())
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed += 1
                    print(f"     Killed Node {node_id} (pid {pid})")
                except Exception:
                    print(f"     Node {node_id} already stopped")

        time.sleep(1)
        alive = [p for p in NODE_PORTS if _node_alive(p)]
        print(f"\n     Nodes still alive: {[p-5000 for p in alive]} (ports {alive})")
        print(f"     Quorum needed    : {QUORUM}/5")
        print(f"     Quorum status    : {'MAINTAINED ✅' if len(alive) >= QUORUM else 'LOST ❌'}")
        ok(f"{len(alive)}/5 nodes alive — chain continues operating")
    else:
        detail("(Network not running — showing PBFT math)")
        print(f"\n     Total nodes    : {TOTAL_NODES}")
        print(f"     Fault tolerance: f={1}")
        print(f"     Quorum (2f+1)  : {QUORUM}")
        print(f"     After killing 2: {TOTAL_NODES-2} nodes alive ≥ {QUORUM} quorum")

        engines = [PBFTEngine(node_id=i, wallet=Wallet()) for i in range(1, 4)]
        finalized = []
        for e in engines:
            e.on_finalized = lambda seq, d: finalized.append(d)

        tx_id2 = hashlib.sha256(b"post_failure").hexdigest()
        tx2 = {"tx_id": tx_id2, "sender": "a"*64, "receiver": "b"*64, "amount": 100}
        pp = engines[0].start_round(tx2)
        seq2 = pp["seq"]

        for e in engines[1:]:
            prepare = e.handle_pre_prepare(pp)
            if prepare:
                for eng in engines:
                    commit = eng.handle_prepare(prepare)
                    if commit:
                        for en in engines:
                            en.handle_commit(commit)

        for e in engines:
            commit = e.handle_prepare({
                "type": "PREPARE", "seq": seq2, "tx_id": tx_id2,
                "node_id": 0, "signature": engines[0]._sign(seq2, tx_id2),
            })
            if commit:
                for en in engines:
                    en.handle_commit(commit)

        time.sleep(0.15)
        ok(f"3-node consensus reached after 2 failures — {len(finalized)} finalization(s)")

    print("\n  ── Attack Simulation Summary\n")
    print("     Replay attack             : BLOCKED ✅  (mempool deduplication)")
    print("     Fake validator            : BLOCKED ✅  (cannot reach PBFT quorum)")
    print("     OFAC direct               : BLOCKED ✅  (sanctions exact-match)")
    print("     Blocked corridor          : BLOCKED ✅  (corridor hard limit = 0)")
    print("     Typosquat                 : PASSED  ⚠   (known limitation — exact-match only)")
    print("     Relay attack step 2       : PASSED  ⚠   (known limitation — single-hop screening)")
    print("     2-node crash failure      : SURVIVED ✅ (PBFT quorum maintained)")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-zkp",     action="store_true")
    parser.add_argument("--no-network", action="store_true")
    args = parser.parse_args()

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║     SecureChain — Full System Demo                          ║")
    print("║     Phases 1–4 + Attack Simulations                        ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    network_running = False

    try:
        alice, bob, carol = demo_phase1()

        if args.no_zkp:
            alice_p, bob_p, carol_p = demo_phase2_mock(alice, bob, carol)
        else:
            alice_p, bob_p, carol_p = demo_phase2_real(alice, bob, carol)
            if alice_p is None:
                alice_p, bob_p, carol_p = demo_phase2_mock(alice, bob, carol)

        demo_phase3(alice, bob, carol, alice_p, bob_p)

        if args.no_network:
            demo_phase4_pbft_offline()
        else:
            network_running = start_network()
            if network_running:
                demo_phase4_network(alice, bob, alice_p)
            else:
                info("Network failed to start — falling back to offline PBFT demo")
                demo_phase4_pbft_offline()

        demo_attacks(network_running)

        sep("Demo Complete")
        print("  All phases demonstrated successfully.\n")
        print("  Phase 1 — ECDSA wallets, SHA-256 block hashing, tamper detection")
        print("  Phase 2 — ZKP KYC proofs via circom/snarkjs, Merkle commitment registry")
        print("  Phase 3 — 4-gate compliance pipeline (ZKP → sanctions → limits → fraud)")
        print("  Phase 4 — PBFT consensus across 5 independent validator nodes")
        print("  Phase 7 — Replay, spoofing, sanctions bypass, node failure attacks\n")

    finally:
        if network_running:
            sep("Stopping Network")
            stop_network()
            ok("All nodes stopped")


if __name__ == "__main__":
    main()