import pytest
from core.transaction import Transaction
from core.wallet import Wallet, verify_signature


def make_tx(**kwargs):
    defaults = dict(
        sender="a" * 64,
        receiver="b" * 64,
        amount=500,
        currency="USD",
        sender_country="US",
        receiver_country="IN",
    )
    defaults.update(kwargs)
    return Transaction(**defaults)


def test_transaction_creates_id():
    tx = make_tx()
    assert tx.tx_id is not None
    assert len(tx.tx_id) == 64


def test_transaction_to_dict():
    tx = make_tx()
    d = tx.to_dict()
    assert d["amount"] == 500.0
    assert d["currency"] == "USD"


def test_transaction_from_dict_roundtrip():
    tx = make_tx()
    d = tx.to_dict()
    tx2 = Transaction.from_dict(d)
    assert tx2.tx_id == tx.tx_id
    assert tx2.amount == tx.amount


def test_wallet_creates_unique_addresses():
    w1 = Wallet()
    w2 = Wallet()
    assert w1.address != w2.address


def test_wallet_sign_and_verify():
    wallet = Wallet()
    tx = Transaction(
        sender=wallet.address,
        receiver="b" * 64,
        amount=100,
        currency="USD",
        sender_country="US",
        receiver_country="IN",
    )
    wallet.sign_transaction(tx)
    assert tx.signature is not None

    valid = verify_signature(
        wallet.public_key_hex(),
        tx.signable_payload(),
        tx.signature,
    )
    assert valid is True


def test_invalid_signature_rejected():
    wallet = Wallet()
    other_wallet = Wallet()
    tx = Transaction(
        sender=wallet.address,
        receiver="b" * 64,
        amount=100,
        currency="USD",
        sender_country="US",
        receiver_country="IN",
    )
    wallet.sign_transaction(tx)

    # Verify with wrong public key
    valid = verify_signature(
        other_wallet.public_key_hex(),
        tx.signable_payload(),
        tx.signature,
    )
    assert valid is False


def test_wallet_export_and_load():
    wallet = Wallet()
    exported = wallet.export()
    loaded = Wallet.load(exported["private_key_pem"])
    assert loaded.address == wallet.address
    assert loaded.public_key_hex() == wallet.public_key_hex()