"""
Test for Merkle tree implementation.
"""

import pytest
from blockchain_core.merkle_tree import MerkleTree, MerkleNode


class TestMerkleTree:
    """Test cases for Merkle tree."""

    def test_merkle_tree_creation(self):
        """Test creating a Merkle tree."""
        transactions = [
            {'sender': 'Alice', 'recipient': 'Bob', 'value': 10},
            {'sender': 'Bob', 'recipient': 'Charlie', 'value': 20}
        ]

        tree = MerkleTree(transactions)
        assert tree is not None
        assert tree.root is not None

    def test_merkle_root_hash(self):
        """Test Merkle root hash generation."""
        transactions = [
            {'sender': 'Alice', 'recipient': 'Bob', 'value': 10}
        ]

        tree = MerkleTree(transactions)
        root_hash = tree.get_root_hash()

        assert root_hash is not None
        assert len(root_hash) == 64  # SHA-256

    def test_merkle_proof(self):
        """Test Merkle proof generation and verification."""
        transactions = [
            {'sender': f'sender_{i}', 'recipient': f'recipient_{i}', 'value': i}
            for i in range(4)
        ]

        tree = MerkleTree(transactions)
        root_hash = tree.get_root_hash()

        # Generate proof for first transaction
        proof = tree.get_proof(transactions[0])
        assert proof is not None

        # Verify proof
        is_valid = tree.verify_proof(transactions[0], proof, root_hash)
        assert is_valid is True

    def test_empty_merkle_tree(self):
        """Test empty Merkle tree."""
        tree = MerkleTree([])
        assert tree.root is not None
        assert tree.get_root_hash() is not None

    def test_merkle_tree_height(self):
        """Test Merkle tree height calculation."""
        transactions = [{'tx': i} for i in range(8)]
        tree = MerkleTree(transactions)

        height = tree.get_tree_height()
        assert height > 0

    def test_merkle_tree_size(self):
        """Test Merkle tree size calculation."""
        transactions = [{'tx': i} for i in range(4)]
        tree = MerkleTree(transactions)

        size = tree.get_tree_size()
        assert size > 0
