import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


class Wallet:
    def __init__(self):
        self._private_key = ec.generate_private_key(ec.SECP256K1())
        self._public_key = self._private_key.public_key()
        self.address = self._derive_address()

    def _derive_address(self):
        pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        return hashlib.sha256(pub_bytes).hexdigest()

    def sign(self, data: bytes) -> str:
        """Sign arbitrary bytes; returns hex-encoded DER signature."""
        sig_bytes = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return sig_bytes.hex()

    def sign_transaction(self, transaction) -> None:
        """Attach signature to a Transaction object in place."""
        payload = transaction.signable_payload()
        transaction.signature = self.sign(payload)

    def public_key_hex(self) -> str:
        pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        return pub_bytes.hex()

    def export(self) -> dict:
        priv_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return {
            "address": self.address,
            "public_key": self.public_key_hex(),
            "private_key_pem": priv_bytes.decode(),
        }

    @classmethod
    def load(cls, pem: str) -> "Wallet":
        wallet = cls.__new__(cls)
        wallet._private_key = serialization.load_pem_private_key(
            pem.encode(), password=None
        )
        wallet._public_key = wallet._private_key.public_key()
        wallet.address = wallet._derive_address()
        return wallet


def verify_signature(public_key_hex: str, data: bytes, signature_hex: str) -> bool:
    """
    Verify an ECDSA signature.
    public_key_hex: compressed point hex (from wallet.public_key_hex())
    data: the original bytes that were signed
    signature_hex: hex-encoded DER signature
    """
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pub_bytes
        )
        sig_bytes = bytes.fromhex(signature_hex)
        public_key.verify(sig_bytes, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False