"""
identity/zkp_issuer.py
─────────────────────────────────────────────────────────────────────────────
Generates a zk-SNARK proof for a KYC-verified user.

Called ONCE at onboarding. Produces a proof that binds the user's wallet
address to their KYC status, without revealing any identity data.

Flow:
  1. User provides their KYC data (passport hash, DOB, etc.)
  2. Issuer computes kyc_hash = SHA256(kyc_data)
  3. Issuer generates a random secret (blinding factor)
  4. Issuer computes kyc_commitment = Poseidon(Poseidon(kyc_hash, secret), wallet_address)
  5. snarkjs generates a GROTH16 proof with:
       - private inputs: kyc_hash, secret
       - public inputs: kyc_commitment, wallet_address
  6. Proof + commitment stored in identity registry
  7. Proof JSON attached to user's wallet for transaction signing

The commitment goes on-chain. The proof travels with each transaction.
The verifier can verify the proof against the commitment without learning
anything about kyc_hash or secret.
─────────────────────────────────────────────────────────────────────────────
"""

import hashlib
import json
import os
import subprocess
import tempfile
import secrets as py_secrets
from pathlib import Path

_IDENTITY_DIR = Path(__file__).parent
_BUILD_DIR = _IDENTITY_DIR / "build"
_WASM = _BUILD_DIR / "kyc_proof_js" / "kyc_proof.wasm"
_ZKEY = _BUILD_DIR / "proving_key.zkey"
_REGISTRY_PATH = _IDENTITY_DIR / "registry.json"

# Circom field prime (BN128)
_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _load_registry() -> dict:
    if _REGISTRY_PATH.exists():
        with open(_REGISTRY_PATH) as f:
            return json.load(f)
    return {}


def _save_registry(registry: dict):
    _REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)


def _address_to_field(address: str) -> int:
    """Convert a hex wallet address to a field element."""
    val = int(address[:62], 16)  # take 62 hex chars = 248 bits, safely < field prime
    return val % _FIELD_PRIME


def _poseidon_simulate(inputs: list[int]) -> int:
    """
    Python-side Poseidon simulation for computing commitments.
    This mirrors the circomlib Poseidon hash for 2 inputs.
    
    NOTE: We use a deterministic but simplified version here for computing
    the commitment value. The actual ZKP uses circomlib's Poseidon inside
    the circuit — they must match. We achieve this by having snarkjs compute
    the witness (which runs the circuit), so the circuit's Poseidon is
    authoritative. This Python function is used to PRE-COMPUTE the expected
    commitment for registry storage.

    For production: use a proper Python Poseidon library (e.g. poseidon-hash).
    For this academic project: we compute the commitment via snarkjs itself
    during proof generation, and store what snarkjs reports as public signals.
    """
    # We concatenate and SHA256 as a stand-in for commitment pre-computation.
    # The real commitment value is extracted from snarkjs public.json output.
    combined = "".join(str(x) for x in inputs)
    h = int(hashlib.sha256(combined.encode()).hexdigest(), 16)
    return h % _FIELD_PRIME


def _sha256_to_field(data: bytes) -> int:
    """Hash bytes and return as field element."""
    h = int(hashlib.sha256(data).hexdigest(), 16)
    return h % _FIELD_PRIME


def issue_proof(wallet_address: str, kyc_data: str) -> dict:
    """
    Generate a ZKP proof for a KYC-verified wallet.

    Args:
        wallet_address: the user's wallet address (hex string)
        kyc_data: any string representing KYC info (e.g. "PASSPORT:GB12345678:1990-01-01")
                  In production this would be a hash of verified identity documents.

    Returns:
        {
            "wallet_address": str,
            "kyc_commitment": str,   (public — stored in registry)
            "proof": dict,           (groth16 proof — travels with transactions)
            "public_signals": list,  (public inputs for verification)
        }

    Raises:
        RuntimeError if snarkjs is not available or setup hasn't been run.
    """
    _check_setup()

    # Derive private inputs
    kyc_hash = _sha256_to_field(kyc_data.encode())
    secret = py_secrets.randbelow(_FIELD_PRIME)
    wallet_field = _address_to_field(wallet_address)

    # Build input.json for snarkjs witness generation
    circuit_input = {
        "kyc_hash": str(kyc_hash),
        "secret": str(secret),
        "wallet_address": str(wallet_field),
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, "input.json")
        witness_path = os.path.join(tmpdir, "witness.wtns")
        proof_path = os.path.join(tmpdir, "proof.json")
        public_path = os.path.join(tmpdir, "public.json")

        # We need a placeholder kyc_commitment for the circuit input.
        # Strategy: generate proof with a dummy commitment first to get the
        # real commitment from public signals, then we store that.
        # Actually: the commitment IS a circuit output derived from private inputs,
        # but in our circuit design it's a PUBLIC INPUT that must match.
        # So we compute it via a JS helper first.
        kyc_commitment = _compute_commitment_via_js(kyc_hash, secret, wallet_field)

        circuit_input["kyc_commitment"] = str(kyc_commitment)

        with open(input_path, "w") as f:
            json.dump(circuit_input, f)

        # Generate witness
        _run_snarkjs_witness(input_path, witness_path)

        # Generate proof
        _run_snarkjs_prove(witness_path, proof_path, public_path)

        with open(proof_path) as f:
            proof = json.load(f)
        with open(public_path) as f:
            public_signals = json.load(f)

    # Register the commitment
    registry = _load_registry()
    registry[wallet_address] = {
        "kyc_commitment": str(kyc_commitment),
        "wallet_field": str(wallet_field),
        "registered": True,
    }
    _save_registry(registry)

    result = {
        "wallet_address": wallet_address,
        "kyc_commitment": str(kyc_commitment),
        "proof": proof,
        "public_signals": public_signals,
    }

    print(f"  ✓ ZKP proof issued for wallet {wallet_address[:16]}...")
    print(f"    commitment: {str(kyc_commitment)[:20]}...")
    return result


def _compute_commitment_via_js(kyc_hash: int, secret: int, wallet_field: int) -> int:
    """
    Compute Poseidon(Poseidon(kyc_hash, secret), wallet_field) using a small
    JS script via Node.js — ensures exact match with circomlib's Poseidon.
    """
    js_script = f"""
const {{ buildPoseidon }} = require('circomlibjs');

async function main() {{
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const step1 = poseidon([BigInt("{kyc_hash}"), BigInt("{secret}")]);
    const blinded = F.toObject(step1);

    const step2 = poseidon([blinded, BigInt("{wallet_field}")]);
    const commitment = F.toObject(step2);

    console.log(commitment.toString());
}}

main().catch(e => {{ console.error(e); process.exit(1); }});
"""
    # Write JS into circuits_dir so Node resolves circomlibjs from local node_modules
    circuits_dir = str(_IDENTITY_DIR / "circuits")
    js_path = os.path.join(circuits_dir, "_compute_commitment_tmp.js")

    with open(js_path, "w") as f:
        f.write(js_script)

    try:
        # Install deps if needed
        if not os.path.exists(os.path.join(circuits_dir, "node_modules", "circomlibjs")):
            subprocess.run(["npm", "install"], cwd=circuits_dir, capture_output=True, check=True)

        result = subprocess.run(
            ["node", js_path],
            capture_output=True,
            text=True,
            cwd=circuits_dir,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Commitment computation failed:\n{result.stderr}")

        return int(result.stdout.strip())
    finally:
        if os.path.exists(js_path):
            os.remove(js_path)


def _run_snarkjs_witness(input_path: str, witness_path: str):
    wasm = str(_WASM)
    result = subprocess.run(
        ["snarkjs", "wtns", "calculate", wasm, input_path, witness_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Witness generation failed:\n{result.stderr}\n{result.stdout}")


def _run_snarkjs_prove(witness_path: str, proof_path: str, public_path: str):
    zkey = str(_ZKEY)
    result = subprocess.run(
        ["snarkjs", "groth16", "prove", zkey, witness_path, proof_path, public_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Proof generation failed:\n{result.stderr}\n{result.stdout}")


def _check_setup():
    missing = []
    if not _WASM.exists():
        missing.append(str(_WASM))
    if not _ZKEY.exists():
        missing.append(str(_ZKEY))
    if missing:
        raise RuntimeError(
            "ZKP setup not complete. Run: bash identity/setup.sh\n"
            f"Missing: {missing}"
        )


def get_commitment(wallet_address: str) -> str | None:
    """Look up the registered KYC commitment for a wallet address."""
    registry = _load_registry()
    entry = registry.get(wallet_address)
    return entry["kyc_commitment"] if entry else None


def is_registered(wallet_address: str) -> bool:
    """Check whether a wallet has a registered KYC commitment."""
    return get_commitment(wallet_address) is not None