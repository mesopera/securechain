# SecureChain

A compliance-native permissioned blockchain for international money transfers.

## Architecture

```
Transaction → ZKP Verify → Sanctions → Limits → Fraud Score → PBFT (3/5) → Block
```

**Stack:** Python 3.11 · Flask · ECDSA · circom · snarkjs · React · Vite · Tailwind

## Project Structure

```
securechain/
├── core/               # Block, chain, transaction, wallet
├── identity/           # ZKP circuit, issuer, verifier, Merkle registry
├── compliance/         # Sanctions, limits, fraud scoring, smart contract
├── network/            # Flask nodes, PBFT consensus, mempool, broadcast
├── attacks/            # 4 attack simulation scripts
├── dashboard/          # React frontend
└── tests/              # pytest suite
```

## Setup

### 1. Install Python deps
```bash
pip install -r requirements.txt
```

### 2. Install Node + snarkjs
```bash
# Install snarkjs globally
npm install -g snarkjs

# Install circom (Linux)
curl -L https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 -o circom
chmod +x circom && sudo mv circom /usr/local/bin/
```

### 3. ZKP trusted setup (one time, ~3 min)
```bash
bash identity/setup.sh
```

### 4. Run tests
```bash
pytest tests/ -v
```

## Running the Network

### Option A — Processes (Codespaces / development)
```bash
bash start_network.sh     # starts nodes on ports 5001-5005
bash stop_network.sh      # stop all
```

### Option B — Docker (local machine)
```bash
# Run ZKP setup first, then:
docker-compose up --build
```

### Dashboard
```bash
cd dashboard
npm install
npm run dev               # opens on http://localhost:3000
```

## Demo

```bash
python demo_phase3.py     # full compliance + ZKP demo
```

## Attack Simulations

Each script runs standalone and produces a clear pass/fail result:

```bash
python attacks/replay_attack.py       # duplicate tx rejected
python attacks/spoofing_attack.py     # fake validator blocked
python attacks/sanctions_bypass.py    # OFAC bypass attempts
python attacks/node_failure.py        # 2 nodes killed, chain survives
```

## Compliance Pipeline

| Step | Check | Failure |
|------|-------|---------|
| 0 | ZKP identity proof | No KYC = instant reject |
| 1 | Sanctions (OFAC + UN) | Blocked address/country |
| 2 | Transfer limits | Corridor/amount limits |
| 3 | Fraud scoring | Score ≥ 70/100 |

## PBFT Consensus

- n=5 nodes, f=1 fault tolerance
- Quorum: 3 of 5 signatures required
- Phases: PRE-PREPARE → PREPARE → COMMIT → FINALIZED
- Survives: 1 Byzantine node or 2 crash failures

## API Reference

Each node exposes:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/transaction` | Submit transaction |
| POST | `/pbft/pre-prepare` | PBFT phase 1 |
| POST | `/pbft/prepare` | PBFT phase 2 |
| POST | `/pbft/commit` | PBFT phase 3 |
| GET | `/chain` | Full chain |
| GET | `/mempool` | Pending transactions |
| GET | `/status` | Node health |
| GET | `/pbft/state/<seq>` | Round state |