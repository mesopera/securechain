"""
network/node.py
Validator node — Flask REST API + PBFT engine + chain storage.

Endpoints:
  POST /transaction          — submit a new transaction
  POST /pbft/pre-prepare     — receive PRE-PREPARE from primary
  POST /pbft/prepare         — receive PREPARE vote
  POST /pbft/commit          — receive COMMIT vote
  GET  /chain                — return full chain
  GET  /mempool              — return pending transactions
  GET  /status               — node health + chain length
  GET  /pbft/state/<seq>     — PBFT round state
"""
import os
import sys
import json
import time

from flask import Flask, request, jsonify
from flask_cors import CORS

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.wallet import Wallet
from core.chain import Blockchain
from core.transaction import Transaction
from network.mempool import Mempool
from network.consensus import PBFTEngine
from network import broadcast
from compliance import smart_contract
from identity import zkp_verifier


def create_node(node_id: int, port: int, peer_ports: list[int]):
    app = Flask(__name__)
    CORS(app)

    wallet = Wallet()
    chain = Blockchain(storage_path=f"data/chain_node{node_id}.json")
    mempool = Mempool()
    pbft = PBFTEngine(node_id=node_id, wallet=wallet)

    peers = [f"http://localhost:{p}" for p in peer_ports]

    # ── PBFT finalization callback ────────────────────────────────────────
    def on_finalized(seq: int, finalized: dict):
        tx_data = finalized["tx_data"]
        if not mempool.has(tx_data["tx_id"]):
            return
        block = chain.add_block([tx_data])
        mempool.remove(tx_data["tx_id"])
        print(f"[Node {node_id}] ✓ Block #{block.index} sealed  seq={seq}  tx={tx_data['tx_id'][:10]}...")

    pbft.on_finalized = on_finalized

    # ── Submit transaction ────────────────────────────────────────────────
    @app.route("/transaction", methods=["POST"])
    def submit_transaction():
        data = request.json
        if not data:
            return jsonify({"error": "No data"}), 400

        # Build Transaction object for compliance checking
        try:
            tx = Transaction.from_dict(data)
        except Exception as e:
            return jsonify({"error": f"Invalid transaction: {e}"}), 400

        # Run compliance pipeline (includes ZKP gate)
        result = smart_contract.run(tx)
        if not result["approved"]:
            return jsonify({
                "accepted": False,
                "reason": result["rejection_reason"],
                "compliance": result,
            }), 200

        tx_dict = tx.to_dict()
        if not mempool.add(tx_dict):
            return jsonify({"accepted": False, "reason": "Duplicate transaction"}), 200

        # Primary node (node 1) starts PBFT round
        if node_id == 1:
            pre_prepare = pbft.start_round(tx_dict)
            broadcast.broadcast_to_peers(peers, "/pbft/pre-prepare", pre_prepare)
            # Also handle our own pre-prepare
            prepare = pbft.handle_pre_prepare(pre_prepare)
            if prepare:
                broadcast.broadcast_to_peers(peers, "/pbft/prepare", prepare)
                _handle_prepare_locally(prepare)

        return jsonify({
            "accepted": True,
            "tx_id": tx.tx_id,
            "compliance": {"approved": True, "risk_level": result["risk_level"]},
        }), 200

    # ── PBFT: receive PRE-PREPARE ─────────────────────────────────────────
    @app.route("/pbft/pre-prepare", methods=["POST"])
    def pbft_pre_prepare():
        msg = request.json
        prepare = pbft.handle_pre_prepare(msg)
        if prepare:
            broadcast.broadcast_to_peers(peers, "/pbft/prepare", prepare)
            _handle_prepare_locally(prepare)
        return jsonify({"ok": True})

    # ── PBFT: receive PREPARE ─────────────────────────────────────────────
    @app.route("/pbft/prepare", methods=["POST"])
    def pbft_prepare():
        msg = request.json
        _handle_prepare_locally(msg)
        return jsonify({"ok": True})

    def _handle_prepare_locally(msg):
        commit = pbft.handle_prepare(msg)
        if commit:
            broadcast.broadcast_to_peers(peers, "/pbft/commit", commit)
            _handle_commit_locally(commit)

    # ── PBFT: receive COMMIT ──────────────────────────────────────────────
    @app.route("/pbft/commit", methods=["POST"])
    def pbft_commit():
        msg = request.json
        _handle_commit_locally(msg)
        return jsonify({"ok": True})

    def _handle_commit_locally(msg):
        pbft.handle_commit(msg)

    # ── Chain ─────────────────────────────────────────────────────────────
    @app.route("/chain", methods=["GET"])
    def get_chain():
        return jsonify({"chain": chain.to_dict(), "length": len(chain)})

    # ── Mempool ───────────────────────────────────────────────────────────
    @app.route("/mempool", methods=["GET"])
    def get_mempool():
        return jsonify({"pending": mempool.get_pending(), "count": mempool.size()})

    # ── Status ────────────────────────────────────────────────────────────
    @app.route("/status", methods=["GET"])
    def status():
        valid, msg = chain.is_valid()
        return jsonify({
            "node_id": node_id,
            "port": port,
            "address": wallet.address,
            "chain_length": len(chain),
            "chain_valid": valid,
            "mempool_size": mempool.size(),
            "peers": peers,
        })

    # ── PBFT round state ──────────────────────────────────────────────────
    @app.route("/pbft/state/<int:seq>", methods=["GET"])
    def pbft_state(seq):
        state = pbft.get_state(seq)
        return jsonify(state or {"error": "seq not found"})

    return app, port


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--peers", type=str, default="")
    args = parser.parse_args()

    peer_ports = [int(p) for p in args.peers.split(",") if p]
    os.makedirs("data", exist_ok=True)

    app, port = create_node(args.id, args.port, peer_ports)
    print(f"[Node {args.id}] Starting on port {port}  peers={peer_ports}")
    app.run(host="0.0.0.0", port=port, debug=False)