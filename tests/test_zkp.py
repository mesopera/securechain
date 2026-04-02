"""
tests/test_zkp.py
Tests for ZKP issuer, verifier, and Merkle tree.

NOTE: Tests that require the actual snarkjs ceremony (test_real_proof_*)
are skipped automatically if the ZKP build artifacts don't exist yet.
Run `bash identity/setup.sh` first to enable those tests.
"""

import pytest
import os
from pathlib import Path

from identity.merkle_tree import MerkleTree, _leaf_hash, _hash_pair
from identity import zkp_issuer, zkp_verifier
from core.transaction import Transaction
from core.wallet import Wallet

_BUILD_DIR = Path(__file__).parent.parent / "identity" / "build"
_ZKP_READY = (
    (_BUILD_DIR / "proving_key.zkey").exists() and
    (_BUILD_DIR / "verification_key.json").exists() and
    (_BUILD_DIR / "kyc_proof_js" / "kyc_proof.wasm").exists()
)


# ─────────────────────────────────────────────────────────────
# Merkle Tree tests (no ZKP setup required)
# ─────────────────────────────────────────────────────────────

class TestMerkleTree:
    def setup_method(self):
        """Use a fresh in-memory tree for each test."""
        self.tree = MerkleTree.__new__(MerkleTree)
        self.tree.leaves = []
        self.tree.leaf_hashes = []
        self.tree._tree = []

    def test_empty_tree_has_no_root(self):
        assert self.tree.root is None

    def test_single_leaf_has_root(self):
        self.tree.leaves = ["commitment_abc"]
        self.tree.leaf_hashes = [_leaf_hash("commitment_abc")]
        self.tree._build_tree()
        assert self.tree.root is not None

    def test_insert_increases_size(self):
        # Patch _save to no-op for test
        self.tree._save = lambda: None
        self.tree.insert("commit1")
        assert self.tree.size == 1
        self.tree.insert("commit2")
        assert self.tree.size == 2

    def test_two_leaves_root_is_deterministic(self):
        self.tree.leaves = ["c1", "c2"]
        self.tree.leaf_hashes = [_leaf_hash("c1"), _leaf_hash("c2")]
        self.tree._build_tree()
        root1 = self.tree.root

        self.tree._build_tree()
        root2 = self.tree.root
        assert root1 == root2

    def test_different_commitments_different_roots(self):
        self.tree.leaves = ["c1"]
        self.tree.leaf_hashes = [_leaf_hash("c1")]
        self.tree._build_tree()
        root_a = self.tree.root

        self.tree.leaves = ["c2"]
        self.tree.leaf_hashes = [_leaf_hash("c2")]
        self.tree._build_tree()
        root_b = self.tree.root

        assert root_a != root_b

    def test_merkle_proof_valid(self):
        self.tree._save = lambda: None
        self.tree.insert("alpha")
        self.tree.insert("beta")
        self.tree.insert("gamma")

        proof = self.tree.get_proof("beta")
        assert proof is not None
        assert MerkleTree.verify_proof("beta", proof, self.tree.root) is True

    def test_merkle_proof_invalid_for_wrong_commitment(self):
        self.tree._save = lambda: None
        self.tree.insert("alpha")
        self.tree.insert("beta")

        proof = self.tree.get_proof("alpha")
        # Verify with wrong commitment
        assert MerkleTree.verify_proof("beta", proof, self.tree.root) is False

    def test_proof_for_unregistered_commitment_is_none(self):
        self.tree._save = lambda: None
        self.tree.insert("alpha")
        proof = self.tree.get_proof("nothere")
        assert proof is None

    def test_contains(self):
        self.tree._save = lambda: None
        self.tree.insert("abc123")
        assert self.tree.contains("abc123") is True
        assert self.tree.contains("xyz") is False

    def test_four_leaves_all_proofs_valid(self):
        self.tree._save = lambda: None
        commitments = ["c1", "c2", "c3", "c4"]
        for c in commitments:
            self.tree.insert(c)
        for c in commitments:
            proof = self.tree.get_proof(c)
            assert MerkleTree.verify_proof(c, proof, self.tree.root), f"Proof failed for {c}"


# ─────────────────────────────────────────────────────────────
# ZKP verifier — no-proof rejection (no ceremony required)
# ─────────────────────────────────────────────────────────────

class TestZKPVerifierGating:
    def _make_tx(self, wallet):
        return Transaction(
            sender=wallet.address,
            receiver="b" * 64,
            amount=500,
            currency="USD",
            sender_country="US",
            receiver_country="IN",
        )

    def test_transaction_without_proof_rejected(self):
        wallet = Wallet()
        tx = self._make_tx(wallet)
        # No zkp_proof attached
        result = zkp_verifier.verify(tx)
        assert result["passed"] is False
        assert "No ZKP proof" in result["reason"]

    def test_transaction_with_empty_proof_rejected(self):
        wallet = Wallet()
        tx = self._make_tx(wallet)
        tx.zkp_proof = {}
        result = zkp_verifier.verify(tx)
        assert result["passed"] is False

    def test_unregistered_wallet_rejected(self):
        wallet = Wallet()
        tx = self._make_tx(wallet)
        # Attach a fake-looking proof structure
        tx.zkp_proof = {
            "proof": {"pi_a": [], "pi_b": [], "pi_c": []},
            "public_signals": ["12345", "67890"],
        }
        result = zkp_verifier.verify(tx)
        assert result["passed"] is False
        assert "no registered KYC commitment" in result["reason"]

    def test_compliance_pipeline_blocks_without_proof(self):
        from compliance import smart_contract
        wallet = Wallet()
        tx = self._make_tx(wallet)
        # No proof — should fail at ZKP gate before reaching sanctions
        result = smart_contract.run(tx)
        assert result["approved"] is False
        assert result["checks"]["zkp"]["passed"] is False
        assert result["checks"]["sanctions"] is None  # never reached


# ─────────────────────────────────────────────────────────────
# Full ZKP tests — only run if setup.sh has been run
# ─────────────────────────────────────────────────────────────

@pytest.mark.skipif(not _ZKP_READY, reason="ZKP build artifacts not found — run: bash identity/setup.sh")
class TestZKPFull:
    def setup_method(self):
        self.wallet = Wallet()
        self.kyc_data = f"PASSPORT:TEST123456:1990-01-01:{self.wallet.address}"

    def test_issue_proof_returns_valid_structure(self):
        result = zkp_issuer.issue_proof(self.wallet.address, self.kyc_data)
        assert "proof" in result
        assert "public_signals" in result
        assert "kyc_commitment" in result
        assert result["wallet_address"] == self.wallet.address

    def test_wallet_is_registered_after_issuance(self):
        zkp_issuer.issue_proof(self.wallet.address, self.kyc_data)
        assert zkp_issuer.is_registered(self.wallet.address) is True

    def test_proof_verifies_successfully(self):
        issued = zkp_issuer.issue_proof(self.wallet.address, self.kyc_data)
        tx = Transaction(
            sender=self.wallet.address,
            receiver="b" * 64,
            amount=500,
            currency="USD",
            sender_country="US",
            receiver_country="IN",
        )
        tx.zkp_proof = {
            "proof": issued["proof"],
            "public_signals": issued["public_signals"],
        }
        result = zkp_verifier.verify(tx)
        assert result["passed"] is True

    def test_wrong_wallet_proof_rejected(self):
        """A proof issued for wallet A cannot be used by wallet B."""
        wallet_b = Wallet()
        issued = zkp_issuer.issue_proof(self.wallet.address, self.kyc_data)

        # Try to use wallet_a's proof for a transaction from wallet_b
        tx = Transaction(
            sender=wallet_b.address,  # different wallet
            receiver="b" * 64,
            amount=100,
            currency="USD",
            sender_country="US",
            receiver_country="IN",
        )
        tx.zkp_proof = {
            "proof": issued["proof"],
            "public_signals": issued["public_signals"],
        }
        result = zkp_verifier.verify(tx)
        assert result["passed"] is False

    def test_tampered_public_signal_rejected(self):
        """Changing a public signal invalidates the proof."""
        issued = zkp_issuer.issue_proof(self.wallet.address, self.kyc_data)
        tx = Transaction(
            sender=self.wallet.address,
            receiver="b" * 64,
            amount=100,
            currency="USD",
            sender_country="US",
            receiver_country="IN",
        )
        # Tamper with the first public signal
        tampered_signals = list(issued["public_signals"])
        tampered_signals[0] = "999999999999999999999"
        tx.zkp_proof = {
            "proof": issued["proof"],
            "public_signals": tampered_signals,
        }
        result = zkp_verifier.verify(tx)
        assert result["passed"] is False

    def test_full_pipeline_with_valid_proof(self):
        from compliance import smart_contract
        issued = zkp_issuer.issue_proof(self.wallet.address, self.kyc_data)
        tx = Transaction(
            sender=self.wallet.address,
            receiver="b" * 64,
            amount=200,
            currency="USD",
            sender_country="US",
            receiver_country="IN",
        )
        tx.zkp_proof = {
            "proof": issued["proof"],
            "public_signals": issued["public_signals"],
        }
        result = smart_contract.run(tx)
        assert result["approved"] is True
        assert result["checks"]["zkp"]["passed"] is True