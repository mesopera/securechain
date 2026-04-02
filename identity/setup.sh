#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# identity/setup.sh
# One-time ZKP trusted setup ceremony for kyc_proof circuit.
#
# Run this ONCE before using the ZKP system.
# Produces: kyc_proof.r1cs, kyc_proof.wasm, proving_key.zkey, verification_key.json
#
# Prerequisites (run install.sh first if not done):
#   - circom binary on PATH
#   - snarkjs installed (npm install -g snarkjs)
#   - node_modules/circomlib present in identity/circuits/
# ─────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$SCRIPT_DIR/circuits"
BUILD_DIR="$SCRIPT_DIR/build"
PTAU_DIR="$SCRIPT_DIR/ptau"

echo "════════════════════════════════════════════════════"
echo "  SecureChain — ZKP Trusted Setup"
echo "════════════════════════════════════════════════════"

# Create dirs
mkdir -p "$BUILD_DIR"
mkdir -p "$PTAU_DIR"

# ── Step 1: Install circomlib ─────────────────────────────────────────────────
echo ""
echo "[1/7] Installing circomlib..."
cd "$CIRCUITS_DIR"
if [ ! -d "node_modules/circomlib" ]; then
    npm install circomlib
else
    echo "  circomlib already installed, skipping."
fi
cd "$SCRIPT_DIR"

# ── Step 2: Compile the circuit ───────────────────────────────────────────────
echo ""
echo "[2/7] Compiling kyc_proof.circom..."
circom "$CIRCUITS_DIR/kyc_proof.circom" \
    --r1cs \
    --wasm \
    --sym \
    --output "$BUILD_DIR"
echo "  ✓ Compiled → $BUILD_DIR/kyc_proof.r1cs"
echo "  ✓ WASM     → $BUILD_DIR/kyc_proof_js/kyc_proof.wasm"

# ── Step 3: Powers of Tau ceremony (phase 1) ─────────────────────────────────
# Using power 12 → supports circuits up to 2^12 = 4096 constraints
# Our circuit is tiny (< 100 constraints) so this is plenty
echo ""
echo "[3/7] Powers of Tau — begin ceremony (power 12)..."
PTAU_FILE="$PTAU_DIR/pot12_0000.ptau"
if [ ! -f "$PTAU_FILE" ]; then
    snarkjs powersoftau new bn128 12 "$PTAU_FILE" -v
else
    echo "  ptau file already exists, skipping."
fi

# ── Step 4: Contribute randomness ────────────────────────────────────────────
echo ""
echo "[4/7] Contributing randomness to ceremony..."
PTAU_CONTRIB="$PTAU_DIR/pot12_0001.ptau"
if [ ! -f "$PTAU_CONTRIB" ]; then
    echo "securechain random beacon" | snarkjs powersoftau contribute \
        "$PTAU_FILE" "$PTAU_CONTRIB" --name="SecureChain Setup" -v
else
    echo "  Contribution already exists, skipping."
fi

# ── Step 5: Prepare phase 2 ───────────────────────────────────────────────────
echo ""
echo "[5/7] Preparing phase 2..."
PTAU_FINAL="$PTAU_DIR/pot12_final.ptau"
if [ ! -f "$PTAU_FINAL" ]; then
    snarkjs powersoftau prepare phase2 "$PTAU_CONTRIB" "$PTAU_FINAL" -v
else
    echo "  Phase 2 ptau already exists, skipping."
fi

# ── Step 6: Generate proving key (zkey) ───────────────────────────────────────
echo ""
echo "[6/7] Generating proving key..."
ZKEY_0="$BUILD_DIR/kyc_proof_0000.zkey"
ZKEY_FINAL="$BUILD_DIR/proving_key.zkey"
if [ ! -f "$ZKEY_FINAL" ]; then
    snarkjs groth16 setup "$BUILD_DIR/kyc_proof.r1cs" "$PTAU_FINAL" "$ZKEY_0"
    echo "securechain zkey contribution" | snarkjs zkey contribute \
        "$ZKEY_0" "$ZKEY_FINAL" --name="SecureChain" -v
    rm -f "$ZKEY_0"
else
    echo "  Proving key already exists, skipping."
fi

# ── Step 7: Export verification key ───────────────────────────────────────────
echo ""
echo "[7/7] Exporting verification key..."
VKEY="$BUILD_DIR/verification_key.json"
snarkjs zkey export verificationkey "$ZKEY_FINAL" "$VKEY"
echo "  ✓ Verification key → $VKEY"

echo ""
echo "════════════════════════════════════════════════════"
echo "  ✅ Setup complete!"
echo ""
echo "  Build artifacts:"
echo "    $BUILD_DIR/kyc_proof.r1cs"
echo "    $BUILD_DIR/kyc_proof_js/kyc_proof.wasm"
echo "    $BUILD_DIR/proving_key.zkey"
echo "    $BUILD_DIR/verification_key.json"
echo ""
echo "  You can now run: python demo_phase3.py"
echo "════════════════════════════════════════════════════"