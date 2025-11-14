"""
Block class for the blockchain.
"""

import json
import hashlib
from time import time
from typing import List, Dict, Any, Optional


class Block:
    """
    Represents a single block in the blockchain.

    Attributes:
        index: Position of the block in the chain
        transactions: List of transactions included in the block
        timestamp: Time when the block was created
        previous_hash: Hash of the previous block
        nonce: Number used once for proof of work
        hash: Hash of the current block
    """

    def __init__(
        self,
        index: int,
        transactions: List[Dict[str, Any]],
        timestamp: float,
        previous_hash: str,
        nonce: int = 0
    ):
        """
        Initialize a new Block.

        Args:
            index: Block position in the chain
            transactions: List of transaction dictionaries
            timestamp: Block creation timestamp
            previous_hash: Hash of the previous block
            nonce: Proof of work nonce (default: 0)
        """
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash of the block.

        Returns:
            Hexadecimal hash string
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert block to dictionary representation.

        Returns:
            Dictionary containing all block data
        """
        return {
            'index': self.index,
            'transactions': self.transactions,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }

    def __repr__(self) -> str:
        """
        String representation of the block.

        Returns:
            Formatted block information
        """
        return (
            f"Block(index={self.index}, "
            f"transactions={len(self.transactions)}, "
            f"timestamp={self.timestamp}, "
            f"hash={self.hash[:16]}...)"
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """
        Create a Block instance from a dictionary.

        Args:
            data: Dictionary containing block data

        Returns:
            New Block instance
        """
        block = cls(
            index=data['index'],
            transactions=data['transactions'],
            timestamp=data['timestamp'],
            previous_hash=data['previous_hash'],
            nonce=data.get('nonce', 0)
        )
        if 'hash' in data:
            block.hash = data['hash']
        return block

    def is_valid(self) -> bool:
        """
        Check if block hash is valid.

        Returns:
            True if hash matches computed hash, False otherwise
        """
        return self.hash == self.compute_hash()
