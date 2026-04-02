"""
identity/zkp_verifier.py
─────────────────────────────────────────────────────────────────────────────
Verifies a zk-SNARK proof attached to a transaction.

Called inside the compliance pipeline BEFORE sanctions/limits/fraud checks.
A transaction without a valid proof is rejected immediately.

Verification checks:
  1. Transaction has a zkp_proof attached
  2. Proof public signals match:
       - public_signals[0] == registered kyc_commitment for sender wallet
       - public_signals[1] == wallet_address field element
  3. snarkjs groth16 verify confirms the proof is cryptographically valid
─────────────────────────────────────────────────────────────────────────────
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from identity.zkp_issuer import (
    _address_to_field,
    _check_setup,
    get_commitment,
    _IDENTITY_DIR,
)

_BUILD_DIR = _IDENTITY_DIR / "build"
_VKEY = _BUILD_DIR / "verification_key.json"


def verify(transaction) -> dict:
    """
    Verify the ZKP proof attached to a transaction.

    Args:
        transaction: Transaction object or dict

    Returns:
        {
            "passed": bool,
            "check": "zkp",
            "reason": str | None
        }
    """
    if hasattr(transaction, "to_dict"):
        tx = transaction.to_dict()
    else:
        tx = transaction

    sender = tx["sender"]

    # ── Gate 1: proof must be present ─────────────────────────────────────
    zkp = tx.get("zkp_proof")
    if not zkp:
        return _fail("No ZKP proof attached to transaction. KYC verification required.")

    proof = zkp.get("proof")
    public_signals = zkp.get("public_signals")

    if not proof or not public_signals:
        return _fail("ZKP proof is malformed — missing proof or public_signals.")

    # ── Gate 2: sender must be registered ─────────────────────────────────
    registered_commitment = get_commitment(sender)
    if not registered_commitment:
        return _fail(f"Sender {sender[:16]}... has no registered KYC commitment. Onboarding required.")

    # ── Gate 3: public signals must match registry ─────────────────────────
    # public_signals[0] = kyc_commitment
    # public_signals[1] = wallet_address (as field element)
    if len(public_signals) < 2:
        return _fail("ZKP public signals incomplete.")

    claimed_commitment = str(public_signals[0])
    if claimed_commitment != str(registered_commitment):
        return _fail(
            f"ZKP commitment mismatch — claimed {claimed_commitment[:12]}... "
            f"but registry has {str(registered_commitment)[:12]}..."
        )

    claimed_wallet_field = str(public_signals[1])
    expected_wallet_field = str(_address_to_field(sender))
    if claimed_wallet_field != expected_wallet_field:
        return _fail("ZKP wallet field element does not match sender address.")

    # ── Gate 4: cryptographic verification via snarkjs ────────────────────
    try:
        _check_setup()
    except RuntimeError as e:
        return _fail(str(e))

    crypto_valid = _snarkjs_verify(proof, public_signals)
    if not crypto_valid:
        return _fail("ZKP cryptographic verification failed — proof is invalid.")

    return {
        "passed": True,
        "check": "zkp",
        "reason": None,
        "commitment": claimed_commitment,
    }


def _snarkjs_verify(proof: dict, public_signals: list) -> bool:
    """Run snarkjs groth16 verify and return True if valid."""
    with tempfile.TemporaryDirectory() as tmpdir:
        proof_path = os.path.join(tmpdir, "proof.json")
        public_path = os.path.join(tmpdir, "public.json")

        with open(proof_path, "w") as f:
            json.dump(proof, f)
        with open(public_path, "w") as f:
            json.dump(public_signals, f)

        result = subprocess.run(
            ["snarkjs", "groth16", "verify",
             str(_VKEY), public_path, proof_path],
            capture_output=True,
            text=True,
        )

        # snarkjs prints "OK!" on success
        return result.returncode == 0 and "OK" in result.stdout


def _fail(reason: str) -> dict:
    return {"passed": False, "check": "zkp", "reason": reason}