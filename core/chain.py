import json
import os
from core.block import Block


class Blockchain:
    def __init__(self, storage_path=None):
        self.chain = []
        self.storage_path = storage_path

        if storage_path and os.path.exists(storage_path):
            self.load_from_disk()
        else:
            self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            transactions=[],
            previous_hash="0" * 64,
            timestamp=0,
        )
        self.chain.append(genesis)
        if self.storage_path:
            self.save_to_disk()

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, transactions):
        """Create and append a new block with the given transactions."""
        block = Block(
            index=len(self.chain),
            transactions=transactions,
            previous_hash=self.last_block.hash,
        )
        self.chain.append(block)
        if self.storage_path:
            self.save_to_disk()
        return block

    def is_valid(self):
        """Validate the entire chain integrity."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Recompute hash
            if current.hash != current.compute_hash():
                return False, f"Block {i} hash mismatch"

            # Check linkage
            if current.previous_hash != previous.hash:
                return False, f"Block {i} broken link to block {i-1}"

        return True, "Chain valid"

    def save_to_disk(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        data = [block.to_dict() for block in self.chain]
        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=2)

    def load_from_disk(self):
        with open(self.storage_path) as f:
            data = json.load(f)
        self.chain = []
        for d in data:
            b = Block(
                index=d["index"],
                transactions=d["transactions"],
                previous_hash=d["previous_hash"],
                timestamp=d["timestamp"],
            )
            b.nonce = d["nonce"]
            b.hash = d["hash"]
            self.chain.append(b)

    def to_dict(self):
        return [block.to_dict() for block in self.chain]

    def __len__(self):
        return len(self.chain)

    def __repr__(self):
        return f"Blockchain(blocks={len(self.chain)}, tip={self.last_block.hash[:12]}...)"