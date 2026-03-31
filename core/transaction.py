import hashlib
import json
import time


class Transaction:
    def __init__(
        self,
        sender,
        receiver,
        amount,
        currency,
        sender_country,
        receiver_country,
        nonce=None,
        timestamp=None,
    ):
        self.sender = sender            # wallet address (public key hex)
        self.receiver = receiver        # wallet address
        self.amount = float(amount)
        self.currency = currency        # e.g. "USD"
        self.sender_country = sender_country    # e.g. "US"
        self.receiver_country = receiver_country  # e.g. "IN"
        self.nonce = nonce or int(time.time() * 1000)
        self.timestamp = timestamp or time.time()
        self.signature = None
        self.zkp_proof = None           # populated by ZKP layer (Phase 2)
        self.compliance_result = None   # populated by compliance engine
        self.tx_id = self._compute_id()

    def _compute_id(self):
        payload = {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "currency": self.currency,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()

    def to_dict(self):
        return {
            "tx_id": self.tx_id,
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "currency": self.currency,
            "sender_country": self.sender_country,
            "receiver_country": self.receiver_country,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "zkp_proof": self.zkp_proof,
            "compliance_result": self.compliance_result,
        }

    @classmethod
    def from_dict(cls, d):
        tx = cls(
            sender=d["sender"],
            receiver=d["receiver"],
            amount=d["amount"],
            currency=d["currency"],
            sender_country=d["sender_country"],
            receiver_country=d["receiver_country"],
            nonce=d["nonce"],
            timestamp=d["timestamp"],
        )
        tx.tx_id = d["tx_id"]
        tx.signature = d.get("signature")
        tx.zkp_proof = d.get("zkp_proof")
        tx.compliance_result = d.get("compliance_result")
        return tx

    def signable_payload(self):
        """Returns the canonical bytes that the wallet should sign."""
        payload = {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "currency": self.currency,
            "nonce": self.nonce,
        }
        return json.dumps(payload, sort_keys=True).encode()

    def __repr__(self):
        return (
            f"Transaction(id={self.tx_id[:10]}..., "
            f"{self.sender[:8]}→{self.receiver[:8]}, "
            f"{self.amount} {self.currency})"
        )