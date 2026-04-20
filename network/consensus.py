"""
network/consensus.py
Practical Byzantine Fault Tolerance (PBFT) consensus — 3-phase protocol.

Phases:
  PRE-PREPARE : Primary broadcasts transaction to all replicas
  PREPARE     : Each replica validates and broadcasts PREPARE vote
  COMMIT      : Once 2f+1 PREPARE votes seen, broadcast COMMIT vote
  FINALIZE    : Once 2f+1 COMMIT votes seen, block is sealed

With n=5 nodes, f=1 (tolerates 1 Byzantine node).
Quorum = 2f+1 = 3 signatures required.
"""
import hashlib
import json
import time
import threading
from dataclasses import dataclass, field


TOTAL_NODES = 5
FAULT_TOLERANCE = 1          # f
QUORUM = 2 * FAULT_TOLERANCE + 1   # 3


@dataclass
class PBFTState:
    """Per-sequence-number PBFT round state."""
    seq: int
    tx_id: str
    tx_data: dict
    phase: str = "PRE-PREPARE"   # PRE-PREPARE → PREPARE → COMMIT → FINALIZED
    prepare_votes: dict = field(default_factory=dict)   # node_id → signature
    commit_votes: dict  = field(default_factory=dict)
    finalized: bool = False
    started_at: float = field(default_factory=time.time)


class PBFTEngine:
    def __init__(self, node_id: int, wallet):
        self.node_id = node_id
        self.wallet = wallet
        self._states: dict[int, PBFTState] = {}
        self._seq = 0
        self._lock = threading.Lock()
        self.on_finalized = None   # callback(seq, tx_data) when block sealed

    # ── Primary: start a new round ────────────────────────────────────────
    def start_round(self, tx_data: dict) -> dict:
        with self._lock:
            self._seq += 1
            seq = self._seq
            tx_id = tx_data["tx_id"]
            state = PBFTState(seq=seq, tx_id=tx_id, tx_data=tx_data, phase="PREPARE") # Primary immediately enters PREPARE phase (skips its own PRE-PREPARE)
            self._states[seq] = state

        msg = {
            "type": "PRE-PREPARE",
            "seq": seq,
            "tx_id": tx_id,
            "tx_data": tx_data,
            "node_id": self.node_id,
            "signature": self._sign(seq, tx_id),
        }
        return msg

    # ── Any node: handle incoming PRE-PREPARE ─────────────────────────────
    def handle_pre_prepare(self, msg: dict) -> dict | None:
        seq = msg["seq"]
        tx_id = msg["tx_id"]
        tx_data = msg["tx_data"]

        with self._lock:
            existing = self._states.get(seq)
            if existing and existing.phase != "PRE-PREPARE":
                return None   # already progressed past this phase
            # Create or update state to PREPARE
            state = PBFTState(seq=seq, tx_id=tx_id, tx_data=tx_data, phase="PREPARE")
            self._states[seq] = state

        return {
            "type": "PREPARE",
            "seq": seq,
            "tx_id": tx_id,
            "node_id": self.node_id,
            "signature": self._sign(seq, tx_id),
        }

    # ── Any node: handle incoming PREPARE vote ────────────────────────────
    def handle_prepare(self, msg: dict) -> dict | None:
        seq = msg["seq"]
        tx_id = msg["tx_id"]
        voter = msg["node_id"]
        sig = msg["signature"]

        with self._lock:
            state = self._states.get(seq)
            if not state or state.finalized:
                return None
            state.prepare_votes[voter] = sig

            if len(state.prepare_votes) >= QUORUM and state.phase == "PREPARE":
                state.phase = "COMMIT"
                return {
                    "type": "COMMIT",
                    "seq": seq,
                    "tx_id": tx_id,
                    "node_id": self.node_id,
                    "signature": self._sign(seq, tx_id),
                    "prepare_votes": dict(state.prepare_votes),
                }
        return None

    # ── Any node: handle incoming COMMIT vote ─────────────────────────────
    def handle_commit(self, msg: dict) -> dict | None:
        seq = msg["seq"]
        tx_id = msg["tx_id"]
        voter = msg["node_id"]
        sig = msg["signature"]

        with self._lock:
            state = self._states.get(seq)
            if not state or state.finalized:
                return None
            state.commit_votes[voter] = sig

            if len(state.commit_votes) >= QUORUM and not state.finalized:
                state.finalized = True
                state.phase = "FINALIZED"
                finalized_data = {
                    "seq": seq,
                    "tx_data": state.tx_data,
                    "commit_votes": dict(state.commit_votes),
                    "finalized_at": time.time(),
                }
                if self.on_finalized:
                    threading.Thread(
                        target=self.on_finalized,
                        args=(seq, finalized_data),
                        daemon=True,
                    ).start()
                return finalized_data
        return None

    def get_state(self, seq: int) -> dict | None:
        with self._lock:
            s = self._states.get(seq)
            if not s:
                return None
            return {
                "seq": s.seq,
                "tx_id": s.tx_id,
                "phase": s.phase,
                "prepare_votes": len(s.prepare_votes),
                "commit_votes": len(s.commit_votes),
                "finalized": s.finalized,
            }

    def _sign(self, seq: int, tx_id: str) -> str:
        payload = f"{seq}:{tx_id}:{self.node_id}".encode()
        return self.wallet.sign(payload)