"""
Unit tests for the Transaction class.
"""

import pytest
from collections import OrderedDict
from blockchain_core.transaction import Transaction
from blockchain_core.wallet import Wallet


class TestTransaction:
    """Test cases for Transaction class."""

    def test_transaction_creation(self):
        """Test creating a new transaction."""
        sender_key = "sender_public_key"
        recipient = "recipient_address"
        value = 50

        transaction = Transaction(sender_key, recipient, value)

        assert transaction.sender_public_key == sender_key
        assert transaction.recipient_address == recipient
        assert transaction.value == value
        assert transaction.signature is None

    def test_to_dict(self):
        """Test converting transaction to dictionary."""
        transaction = Transaction("sender", "recipient", 100)
        tx_dict = transaction.to_dict()

        assert isinstance(tx_dict, OrderedDict)
        assert tx_dict['sender_public_key'] == "sender"
        assert tx_dict['recipient_address'] == "recipient"
        assert tx_dict['value'] == 100

    def test_sign_transaction(self):
        """Test signing a transaction."""
        wallet = Wallet()
        transaction = Transaction(wallet.address, "recipient", 25)

        transaction.sign(wallet)

        assert transaction.signature is not None
        assert isinstance(transaction.signature, bytes)

    def test_sign_wrong_wallet(self):
        """Test signing with wrong wallet raises error."""
        wallet1 = Wallet()
        wallet2 = Wallet()

        transaction = Transaction(wallet1.address, "recipient", 25)

        with pytest.raises(ValueError):
            transaction.sign(wallet2)

    def test_is_valid(self):
        """Test transaction validation."""
        wallet = Wallet()
        transaction = Transaction(wallet.address, "recipient", 25)

        # Unsigned transaction is invalid
        assert transaction.is_valid() is False

        # Signed transaction is valid
        transaction.sign(wallet)
        assert transaction.is_valid() is True

    def test_tampered_transaction(self):
        """Test detection of tampered transactions."""
        wallet = Wallet()
        transaction = Transaction(wallet.address, "recipient", 25)
        transaction.sign(wallet)

        # Tamper with value
        transaction.value = 1000

        assert transaction.is_valid() is False

    def test_create_coinbase(self):
        """Test creating a coinbase transaction."""
        recipient = "miner_address"
        reward = 50

        coinbase = Transaction.create_coinbase(recipient, reward)

        assert coinbase['sender_public_key'] == 'network'
        assert coinbase['recipient_address'] == recipient
        assert coinbase['value'] == reward

    def test_from_dict(self):
        """Test creating transaction from dictionary."""
        data = {
            'sender_public_key': 'sender',
            'recipient_address': 'recipient',
            'value': 75,
            'signature': b'test_signature'
        }

        transaction = Transaction.from_dict(data)

        assert transaction.sender_public_key == 'sender'
        assert transaction.recipient_address == 'recipient'
        assert transaction.value == 75
        assert transaction.signature == b'test_signature'

    def test_repr(self):
        """Test string representation."""
        transaction = Transaction("sender_key", "recipient_addr", 100)
        repr_str = repr(transaction)

        assert 'Transaction' in repr_str
        assert 'value=100' in repr_str
