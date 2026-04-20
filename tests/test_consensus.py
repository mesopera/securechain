"""
tests/test_consensus.py
Unit tests for PBFT consensus engine and mempool.
"""
import pytest
import time
from core.wallet import Wallet
from network.consensus import PBFTEngine, QUORUM, TOTAL_NODES
from network.mempool import Mempool


def make_engine(node_id=1):
    return PBFTEngine(node_id=node_id, wallet=Wallet())


def make_tx(i=1):
    import hashlib, time
    tx_id = hashlib.sha256(f"tx{i}{time.time()}".encode()).hexdigest()
    return {"tx_id": tx_id, "sender": "a" * 64, "receiver": "b" * 64, "amount": 100}


# ── PBFT Engine ───────────────────────────────────────────────────────────────

class TestPBFT:
    def test_start_round_returns_pre_prepare(self):
        engine = make_engine(1)
        tx = make_tx()
        msg = engine.start_round(tx)
        assert msg["type"] == "PRE-PREPARE"
        assert msg["tx_id"] == tx["tx_id"]
        assert msg["seq"] == 1

    def test_seq_increments_each_round(self):
        engine = make_engine(1)
        m1 = engine.start_round(make_tx(1))
        m2 = engine.start_round(make_tx(2))
        assert m2["seq"] == m1["seq"] + 1

    def test_handle_pre_prepare_returns_prepare(self):
        primary = make_engine(1)
        replica = make_engine(2)
        tx = make_tx()
        pp = primary.start_round(tx)
        prepare = replica.handle_pre_prepare(pp)
        assert prepare is not None
        assert prepare["type"] == "PREPARE"
        assert prepare["node_id"] == 2

    def test_duplicate_pre_prepare_ignored(self):
        primary = make_engine(1)
        replica = make_engine(2)
        tx = make_tx()
        pp = primary.start_round(tx)
        replica.handle_pre_prepare(pp)
        result = replica.handle_pre_prepare(pp)   # duplicate
        assert result is None

    def test_quorum_prepare_votes_triggers_commit(self):
        engine = make_engine(1)
        tx = make_tx()
        pp = engine.start_round(tx)
        engine.handle_pre_prepare(pp)   # creates state at seq

        seq = pp["seq"]
        tx_id = pp["tx_id"]

        commit = None
        for voter_id in range(2, 2 + QUORUM):
            voter = make_engine(voter_id)
            msg = {"type": "PREPARE", "seq": seq, "tx_id": tx_id,
                   "node_id": voter_id, "signature": voter._sign(seq, tx_id)}
            commit = engine.handle_prepare(msg)
            if commit:
                break

        assert commit is not None
        assert commit["type"] == "COMMIT"

    def test_insufficient_prepare_votes_no_commit(self):
        engine = make_engine(1)
        tx = make_tx()
        pp = engine.start_round(tx)
        engine.handle_pre_prepare(pp)

        seq, tx_id = pp["seq"], pp["tx_id"]
        voter = make_engine(2)
        msg = {"type": "PREPARE", "seq": seq, "tx_id": tx_id,
               "node_id": 2, "signature": voter._sign(seq, tx_id)}
        commit = engine.handle_prepare(msg)  # only 1 vote, need QUORUM=3
        assert commit is None

    def test_quorum_commit_votes_triggers_finalization(self):
        finalized_results = []

        engine = make_engine(1)
        engine.on_finalized = lambda seq, data: finalized_results.append(data)

        tx = make_tx()
        pp = engine.start_round(tx)
        engine.handle_pre_prepare(pp)

        seq, tx_id = pp["seq"], pp["tx_id"]

        # Simulate quorum prepare votes to get to COMMIT phase
        for voter_id in range(2, 2 + QUORUM):
            voter = make_engine(voter_id)
            msg = {"type": "PREPARE", "seq": seq, "tx_id": tx_id,
                   "node_id": voter_id, "signature": voter._sign(seq, tx_id)}
            engine.handle_prepare(msg)

        # Now send quorum commit votes
        for voter_id in range(2, 2 + QUORUM):
            voter = make_engine(voter_id)
            msg = {"type": "COMMIT", "seq": seq, "tx_id": tx_id,
                   "node_id": voter_id, "signature": voter._sign(seq, tx_id)}
            engine.handle_commit(msg)

        time.sleep(0.1)  # callback is threaded
        assert len(finalized_results) == 1
        assert finalized_results[0]["seq"] == seq

    def test_finalized_round_ignores_further_votes(self):
        engine = make_engine(1)
        tx = make_tx()
        pp = engine.start_round(tx)
        engine.handle_pre_prepare(pp)
        seq, tx_id = pp["seq"], pp["tx_id"]

        for voter_id in range(2, 2 + QUORUM):
            voter = make_engine(voter_id)
            engine.handle_prepare({"type": "PREPARE", "seq": seq, "tx_id": tx_id,
                                   "node_id": voter_id, "signature": voter._sign(seq, tx_id)})
        for voter_id in range(2, 2 + QUORUM):
            voter = make_engine(voter_id)
            engine.handle_commit({"type": "COMMIT", "seq": seq, "tx_id": tx_id,
                                  "node_id": voter_id, "signature": voter._sign(seq, tx_id)})

        time.sleep(0.1)
        state = engine.get_state(seq)
        assert state["finalized"] is True

        # Extra commit should be ignored
        voter = make_engine(99)
        result = engine.handle_commit({"type": "COMMIT", "seq": seq, "tx_id": tx_id,
                                       "node_id": 99, "signature": voter._sign(seq, tx_id)})
        assert result is None

    def test_get_state_returns_correct_phase(self):
        engine = make_engine(1)
        tx = make_tx()
        pp = engine.start_round(tx)
        engine.handle_pre_prepare(pp)
        state = engine.get_state(pp["seq"])
        assert state["phase"] == "PREPARE"

    def test_quorum_constant(self):
        assert QUORUM == 3   # 2f+1 with f=1


# ── Mempool ───────────────────────────────────────────────────────────────────

class TestMempool:
    def test_add_and_retrieve(self):
        mp = Mempool()
        tx = make_tx()
        assert mp.add(tx) is True
        assert mp.size() == 1
        assert tx in mp.get_pending()

    def test_duplicate_rejected(self):
        mp = Mempool()
        tx = make_tx()
        mp.add(tx)
        assert mp.add(tx) is False
        assert mp.size() == 1

    def test_remove(self):
        mp = Mempool()
        tx = make_tx()
        mp.add(tx)
        mp.remove(tx["tx_id"])
        assert mp.size() == 0

    def test_has(self):
        mp = Mempool()
        tx = make_tx()
        mp.add(tx)
        assert mp.has(tx["tx_id"]) is True
        assert mp.has("nonexistent") is False

    def test_clear(self):
        mp = Mempool()
        for i in range(5):
            mp.add(make_tx(i))
        mp.clear()
        assert mp.size() == 0