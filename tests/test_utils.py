"""
Unit tests for utility functions.
"""

import pytest
from blockchain_core.utils import (
    compute_hash,
    validate_address,
    serialize_transaction,
    validate_transaction_structure
)


class TestUtils:
    """Test cases for utility functions."""

    def test_compute_hash_string(self):
        """Test hashing a string."""
        data = "test data"
        hash1 = compute_hash(data)
        hash2 = compute_hash(data)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256
        assert isinstance(hash1, str)

    def test_compute_hash_dict(self):
        """Test hashing a dictionary."""
        data = {'key': 'value', 'number': 42}
        hash1 = compute_hash(data)

        assert len(hash1) == 64
        assert isinstance(hash1, str)

    def test_compute_hash_consistency(self):
        """Test that same data produces same hash."""
        data = {'a': 1, 'b': 2}
        hash1 = compute_hash(data)
        hash2 = compute_hash(data)

        assert hash1 == hash2

    def test_compute_hash_different_data(self):
        """Test that different data produces different hashes."""
        hash1 = compute_hash({'a': 1})
        hash2 = compute_hash({'a': 2})

        assert hash1 != hash2

    def test_validate_address_valid(self):
        """Test validating a valid address."""
        valid_address = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHK"
        assert validate_address(valid_address) is True

    def test_validate_address_invalid(self):
        """Test validating invalid addresses."""
        assert validate_address("") is False
        assert validate_address(None) is False
        assert validate_address("not a valid address") is False
        assert validate_address(123) is False

    def test_serialize_transaction(self):
        """Test transaction serialization."""
        transaction = {
            'sender': 'Alice',
            'recipient': 'Bob',
            'value': 100
        }

        serialized = serialize_transaction(transaction)

        assert isinstance(serialized, str)
        assert 'Alice' in serialized
        assert 'Bob' in serialized
        assert '100' in serialized

    def test_serialize_transaction_consistency(self):
        """Test that serialization is consistent."""
        transaction = {'b': 2, 'a': 1}  # Unordered

        result1 = serialize_transaction(transaction)
        result2 = serialize_transaction(transaction)

        assert result1 == result2

    def test_validate_transaction_structure_valid(self):
        """Test validating a valid transaction structure."""
        transaction = {
            'sender_public_key': 'sender',
            'recipient_address': 'recipient',
            'value': 50
        }

        assert validate_transaction_structure(transaction) is True

    def test_validate_transaction_structure_missing_fields(self):
        """Test validating incomplete transactions."""
        # Missing value
        transaction1 = {
            'sender_public_key': 'sender',
            'recipient_address': 'recipient'
        }
        assert validate_transaction_structure(transaction1) is False

        # Missing sender
        transaction2 = {
            'recipient_address': 'recipient',
            'value': 50
        }
        assert validate_transaction_structure(transaction2) is False

        # Empty transaction
        transaction3 = {}
        assert validate_transaction_structure(transaction3) is False
