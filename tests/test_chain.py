import pytest
from core.block import Block
from core.chain import Blockchain


def test_genesis_block_created():
    bc = Blockchain()
    assert len(bc) == 1
    assert bc.chain[0].index == 0
    assert bc.chain[0].previous_hash == "0" * 64


def test_add_block():
    bc = Blockchain()
    txns = [{"sender": "alice", "receiver": "bob", "amount": 100}]
    block = bc.add_block(txns)
    assert block.index == 1
    assert len(bc) == 2
    assert block.previous_hash == bc.chain[0].hash


def test_chain_is_valid():
    bc = Blockchain()
    bc.add_block([{"sender": "a", "receiver": "b", "amount": 50}])
    bc.add_block([{"sender": "b", "receiver": "c", "amount": 25}])
    valid, msg = bc.is_valid()
    assert valid is True


def test_tampered_chain_invalid():
    bc = Blockchain()
    bc.add_block([{"sender": "a", "receiver": "b", "amount": 100}])
    # Tamper with block data
    bc.chain[1].transactions = [{"sender": "hacker", "receiver": "hacker", "amount": 9999}]
    valid, msg = bc.is_valid()
    assert valid is False


def test_block_hash_changes_on_tamper():
    b = Block(index=1, transactions=[], previous_hash="0" * 64)
    original_hash = b.hash
    b.transactions = [{"x": "y"}]
    assert b.compute_hash() != original_hash


def test_multiple_blocks_linkage():
    bc = Blockchain()
    for i in range(5):
        bc.add_block([{"tx": i}])
    assert len(bc) == 6
    valid, msg = bc.is_valid()
    assert valid is True