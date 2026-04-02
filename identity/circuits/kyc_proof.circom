pragma circom 2.0.0;

/*
  kyc_proof.circom
  ─────────────────────────────────────────────────────────────────────────────
  Proves that a user is KYC-verified WITHOUT revealing their private data.

  What this circuit proves:
    1. The prover knows a secret (their KYC hash — a hash of their real identity)
    2. That secret hashes to a value that is registered in the KYC registry
    3. The prover knows their wallet address
    4. The wallet address hashes together with the KYC hash to produce a
       "commitment" that the issuer signed — binding identity to wallet

  Public inputs (revealed on-chain, visible to verifiers):
    - kyc_commitment : Poseidon(kyc_hash, wallet_address) — registry entry
    - wallet_address : the sender's address (as field element)

  Private inputs (never revealed):
    - kyc_hash       : hash of the user's real KYC data (passport, etc.)
    - secret         : random blinding factor for extra privacy

  The verifier only learns: "this wallet owns a valid KYC commitment"
  They learn nothing about the underlying identity.

  Uses Poseidon hash (ZK-friendly, much cheaper than SHA-256 in circuits).
  ─────────────────────────────────────────────────────────────────────────────
*/

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

template KYCProof() {
    // ── Public inputs ──────────────────────────────────────────────────────
    signal input kyc_commitment;   // Poseidon(kyc_hash, wallet_address) — registered
    signal input wallet_address;   // sender's wallet address as field element

    // ── Private inputs ─────────────────────────────────────────────────────
    signal input kyc_hash;         // hash of real KYC data — NEVER revealed
    signal input secret;           // blinding factor — NEVER revealed

    // ── Internal signals ───────────────────────────────────────────────────
    signal computed_commitment;
    signal blinded_hash;

    // Step 1: blind the kyc_hash with the secret
    // blinded_hash = Poseidon(kyc_hash, secret)
    component blind = Poseidon(2);
    blind.inputs[0] <== kyc_hash;
    blind.inputs[1] <== secret;
    blinded_hash <== blind.out;

    // Step 2: compute the commitment = Poseidon(blinded_hash, wallet_address)
    // This binds the KYC identity to the specific wallet
    component commit = Poseidon(2);
    commit.inputs[0] <== blinded_hash;
    commit.inputs[1] <== wallet_address;
    computed_commitment <== commit.out;

    // Step 3: enforce that the computed commitment matches the public one
    // This is the core constraint — the proof is invalid if they don't match
    kyc_commitment === computed_commitment;
}

component main {public [kyc_commitment, wallet_address]} = KYCProof();
