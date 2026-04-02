"""
identity/merkle_tree.py
─────────────────────────────────────────────────────────────────────────────
Merkle tree for the on-chain KYC commitment registry.

Instead of storing the full KYC commitment list on-chain (expensive),
we store only the Merkle ROOT. Anyone can verify that a commitment is
registered by providing a Merkle proof (path from leaf to root).

This is how real ZKP identity systems work (e.g. Semaphore protocol).

Usage:
  tree = MerkleTree()
  tree.insert(commitment)
  root = tree.root
  proof = tree.get_proof(commitment)
  valid = MerkleTree.verify_proof(commitment, proof, root)
─────────────────────────────────────────────────────────────────────────────
"""

import hashlib
import json
import math
from pathlib import Path

_REGISTRY_PATH = Path(__file__).parent / "merkle_registry.json"


def _hash_pair(left: str, right: str) -> str:
    """Hash two nodes together (order-independent for proof direction)."""
    combined = (left + right).encode()
    return hashlib.sha256(combined).hexdigest()


def _leaf_hash(commitment: str) -> str:
    """Hash a commitment value to produce a leaf node."""
    return hashlib.sha256(f"leaf:{commitment}".encode()).hexdigest()


class MerkleTree:
    def __init__(self):
        self.leaves: list[str] = []       # raw commitments
        self.leaf_hashes: list[str] = []  # hashed leaves
        self._tree: list[list[str]] = []  # full tree levels
        self._load()

    def insert(self, commitment: str) -> str:
        """
        Add a KYC commitment to the tree.
        Returns the new root hash.
        """
        self.leaves.append(commitment)
        self.leaf_hashes.append(_leaf_hash(commitment))
        self._build_tree()
        self._save()
        return self.root

    def _build_tree(self):
        """Rebuild the full Merkle tree from current leaves."""
        if not self.leaf_hashes:
            self._tree = []
            return

        # Pad to next power of 2
        n = len(self.leaf_hashes)
        size = 2 ** math.ceil(math.log2(max(n, 1)))
        padded = self.leaf_hashes + ["0" * 64] * (size - n)

        levels = [padded]
        current = padded
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                next_level.append(_hash_pair(current[i], current[i + 1]))
            levels.append(next_level)
            current = next_level

        self._tree = levels

    @property
    def root(self) -> str | None:
        if not self._tree:
            return None
        return self._tree[-1][0]

    @property
    def size(self) -> int:
        return len(self.leaves)

    def get_proof(self, commitment: str) -> dict | None:
        """
        Generate a Merkle proof (sibling path) for a commitment.

        Returns:
            {
                "commitment": str,
                "leaf_hash": str,
                "path": [ {"sibling": str, "direction": "left"|"right"} ],
                "root": str
            }
        or None if commitment not in tree.
        """
        if commitment not in self.leaves:
            return None

        idx = self.leaves.index(commitment)
        leaf_h = self.leaf_hashes[idx]

        # Walk up the tree collecting siblings
        path = []
        current_idx = idx
        for level in self._tree[:-1]:  # all levels except root
            if current_idx % 2 == 0:
                # current is left child — sibling is right
                sibling_idx = current_idx + 1
                direction = "right"
            else:
                # current is right child — sibling is left
                sibling_idx = current_idx - 1
                direction = "left"

            sibling = level[sibling_idx] if sibling_idx < len(level) else "0" * 64
            path.append({"sibling": sibling, "direction": direction})
            current_idx //= 2

        return {
            "commitment": commitment,
            "leaf_hash": leaf_h,
            "path": path,
            "root": self.root,
        }

    @staticmethod
    def verify_proof(commitment: str, proof: dict, expected_root: str) -> bool:
        """
        Verify a Merkle proof without access to the full tree.

        Args:
            commitment: the commitment value being proven
            proof: the proof dict from get_proof()
            expected_root: the known/trusted root

        Returns:
            True if the proof is valid
        """
        current = _leaf_hash(commitment)

        for step in proof["path"]:
            sibling = step["sibling"]
            direction = step["direction"]

            if direction == "right":
                # current is left, sibling is right
                current = _hash_pair(current, sibling)
            else:
                # sibling is left, current is right
                current = _hash_pair(sibling, current)

        return current == expected_root

    def contains(self, commitment: str) -> bool:
        return commitment in self.leaves

    def _save(self):
        _REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "leaves": self.leaves,
            "leaf_hashes": self.leaf_hashes,
            "root": self.root,
            "size": self.size,
        }
        with open(_REGISTRY_PATH, "w") as f:
            json.dump(data, f, indent=2)

    def _load(self):
        if _REGISTRY_PATH.exists():
            with open(_REGISTRY_PATH) as f:
                data = json.load(f)
            self.leaves = data.get("leaves", [])
            self.leaf_hashes = data.get("leaf_hashes", [])
            if self.leaves:
                self._build_tree()

    def __repr__(self):
        return f"MerkleTree(leaves={self.size}, root={str(self.root)[:12] if self.root else 'empty'}...)"