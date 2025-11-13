"""
Unit tests for the Block class.
"""

import pytest
from time import time
from blockchain_core.block import Block


class TestBlock:
    """Test cases for Block class."""

    def test_block_creation(self):
        """Test creating a new block."""
        timestamp = time()
        transactions = [
            {'sender': 'Alice', 'recipient': 'Bob', 'value': 10}
        ]
        block = Block(
            index=1,
            transactions=transactions,
            timestamp=timestamp,
            previous_hash="abc123"
        )

        assert block.index == 1
        assert block.transactions == transactions
        assert block.timestamp == timestamp
        assert block.previous_hash == "abc123"
        assert block.nonce == 0
        assert block.hash is not None

    def test_compute_hash(self):
        """Test hash computation."""
        block = Block(0, [], time(), "0")
        hash1 = block.compute_hash()
        hash2 = block.compute_hash()

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 produces 64 hex characters

    def test_hash_changes_with_data(self):
        """Test that different data produces different hashes."""
        timestamp = time()
        block1 = Block(0, [], timestamp, "0")
        block2 = Block(1, [], timestamp, "0")

        assert block1.hash != block2.hash

    def test_to_dict(self):
        """Test converting block to dictionary."""
        timestamp = time()
        transactions = [{'test': 'data'}]
        block = Block(1, transactions, timestamp, "abc")

        block_dict = block.to_dict()

        assert block_dict['index'] == 1
        assert block_dict['transactions'] == transactions
        assert block_dict['timestamp'] == timestamp
        assert block_dict['previous_hash'] == "abc"
        assert 'hash' in block_dict

    def test_from_dict(self):
        """Test creating block from dictionary."""
        data = {
            'index': 5,
            'transactions': [{'test': 'data'}],
            'timestamp': time(),
            'previous_hash': 'xyz789',
            'nonce': 42,
            'hash': 'test_hash'
        }

        block = Block.from_dict(data)

        assert block.index == 5
        assert block.transactions == data['transactions']
        assert block.timestamp == data['timestamp']
        assert block.previous_hash == 'xyz789'
        assert block.nonce == 42

    def test_is_valid(self):
        """Test block hash validation."""
        block = Block(0, [], time(), "0")
        assert block.is_valid()

        # Tamper with the block
        block.index = 999
        assert not block.is_valid()

    def test_repr(self):
        """Test string representation."""
        block = Block(1, [{'test': 'data'}], time(), "abc")
        repr_str = repr(block)

        assert 'Block' in repr_str
        assert 'index=1' in repr_str
        assert 'transactions=1' in repr_str
