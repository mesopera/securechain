"""
network/mempool.py
Thread-safe pending transaction pool.
"""
import threading
from core.transaction import Transaction
 
 
class Mempool:
    def __init__(self):
        self._pool: dict[str, dict] = {}
        self._lock = threading.Lock()
 
    def add(self, tx: dict) -> bool:
        with self._lock:
            if tx["tx_id"] in self._pool:
                return False
            self._pool[tx["tx_id"]] = tx
            return True
 
    def remove(self, tx_id: str):
        with self._lock:
            self._pool.pop(tx_id, None)
 
    def get_pending(self) -> list[dict]:
        with self._lock:
            return list(self._pool.values())
 
    def has(self, tx_id: str) -> bool:
        with self._lock:
            return tx_id in self._pool
 
    def size(self) -> int:
        with self._lock:
            return len(self._pool)
 
    def clear(self):
        with self._lock:
            self._pool.clear()
 