"""
Unit tests for the Wallet class.
"""

import pytest
from collections import OrderedDict
from blockchain_core.wallet import Wallet


class TestWallet:
    """Test cases for Wallet class."""

    def test_wallet_creation(self):
        """Test creating a new wallet."""
        wallet = Wallet()

        assert wallet.private_key is not None
        assert wallet.public_key is not None
        assert wallet.address is not None
        assert isinstance(wallet.address, str)

    def test_unique_wallets(self):
        """Test that different wallets have different keys."""
        wallet1 = Wallet()
        wallet2 = Wallet()

        assert wallet1.address != wallet2.address
        assert wallet1.private_key != wallet2.private_key

    def test_serialize_public_key(self):
        """Test public key serialization."""
        wallet = Wallet()
        serialized = wallet.serialize_public_key()

        assert serialized.startswith('-----BEGIN PUBLIC KEY-----')
        assert serialized.endswith('-----END PUBLIC KEY-----\n')

    def test_sign_transaction(self):
        """Test transaction signing."""
        wallet = Wallet()
        transaction = OrderedDict({
            'sender_public_key': wallet.address,
            'recipient_address': 'recipient_address',
            'value': 10
        })

        signature = wallet.sign_transaction(transaction)

        assert signature is not None
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_verify_signature(self):
        """Test signature verification."""
        wallet = Wallet()
        transaction = OrderedDict({
            'sender_public_key': wallet.address,
            'recipient_address': 'recipient_address',
            'value': 10
        })

        signature = wallet.sign_transaction(transaction)
        is_valid = Wallet.verify_signature(wallet.address, signature, transaction)

        assert is_valid is True

    def test_verify_invalid_signature(self):
        """Test invalid signature detection."""
        wallet1 = Wallet()
        wallet2 = Wallet()

        transaction = OrderedDict({
            'sender_public_key': wallet1.address,
            'recipient_address': 'recipient_address',
            'value': 10
        })

        signature = wallet1.sign_transaction(transaction)

        # Try to verify with wrong public key
        is_valid = Wallet.verify_signature(wallet2.address, signature, transaction)

        assert is_valid is False

    def test_verify_tampered_transaction(self):
        """Test detection of tampered transactions."""
        wallet = Wallet()
        transaction = OrderedDict({
            'sender_public_key': wallet.address,
            'recipient_address': 'recipient_address',
            'value': 10
        })

        signature = wallet.sign_transaction(transaction)

        # Tamper with transaction
        transaction['value'] = 1000

        is_valid = Wallet.verify_signature(wallet.address, signature, transaction)

        assert is_valid is False

    def test_export_private_key(self):
        """Test private key export."""
        wallet = Wallet()
        private_key_pem = wallet.export_private_key()

        assert private_key_pem.startswith('-----BEGIN PRIVATE KEY-----')
        assert private_key_pem.endswith('-----END PRIVATE KEY-----\n')

    def test_from_private_key(self):
        """Test wallet import from private key."""
        wallet1 = Wallet()
        private_key_pem = wallet1.export_private_key()

        wallet2 = Wallet.from_private_key(private_key_pem)

        assert wallet1.address == wallet2.address

    def test_repr(self):
        """Test string representation."""
        wallet = Wallet()
        repr_str = repr(wallet)

        assert 'Wallet' in repr_str
        assert 'address=' in repr_str
