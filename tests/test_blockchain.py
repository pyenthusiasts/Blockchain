"""
Unit tests for the Blockchain class.
"""

import pytest
from time import time
from collections import OrderedDict
from blockchain_core.blockchain import Blockchain
from blockchain_core.wallet import Wallet
from blockchain_core.block import Block


class TestBlockchain:
    """Test cases for Blockchain class."""

    def test_blockchain_creation(self):
        """Test creating a new blockchain."""
        blockchain = Blockchain()

        assert len(blockchain.chain) == 1  # Genesis block
        assert blockchain.difficulty == 2
        assert blockchain.miner_rewards == 50
        assert len(blockchain.transactions) == 0

    def test_genesis_block(self):
        """Test genesis block properties."""
        blockchain = Blockchain()
        genesis = blockchain.chain[0]

        assert genesis.index == 0
        assert genesis.previous_hash == "0"
        assert len(genesis.transactions) == 0

    def test_register_node(self):
        """Test registering network nodes."""
        blockchain = Blockchain()

        result1 = blockchain.register_node("http://192.168.1.1:5000")
        assert result1 is True
        assert len(blockchain.nodes) == 1

        result2 = blockchain.register_node("http://192.168.1.1:5000")
        assert result2 is False  # Already registered
        assert len(blockchain.nodes) == 1

    def test_last_block(self):
        """Test getting the last block."""
        blockchain = Blockchain()
        last = blockchain.last_block()

        assert last.index == 0
        assert last == blockchain.chain[0]

    def test_add_valid_transaction(self):
        """Test adding a valid transaction."""
        blockchain = Blockchain()
        wallet = Wallet()

        transaction = OrderedDict({
            'sender_public_key': wallet.address,
            'recipient_address': 'recipient',
            'value': 10
        })
        signature = wallet.sign_transaction(transaction)

        result = blockchain.add_transaction(
            wallet.address,
            'recipient',
            10,
            signature
        )

        assert result is True
        assert len(blockchain.transactions) == 1

    def test_add_transaction_insufficient_balance(self):
        """Test adding transaction with insufficient balance."""
        blockchain = Blockchain()
        wallet = Wallet()

        transaction = OrderedDict({
            'sender_public_key': wallet.address,
            'recipient_address': 'recipient',
            'value': 10000  # More than available
        })
        signature = wallet.sign_transaction(transaction)

        result = blockchain.add_transaction(
            wallet.address,
            'recipient',
            10000,
            signature
        )

        assert result is False
        assert len(blockchain.transactions) == 0

    def test_add_transaction_invalid_signature(self):
        """Test adding transaction with invalid signature."""
        blockchain = Blockchain()
        wallet1 = Wallet()
        wallet2 = Wallet()

        transaction = OrderedDict({
            'sender_public_key': wallet1.address,
            'recipient_address': 'recipient',
            'value': 10
        })
        # Sign with different wallet
        signature = wallet2.sign_transaction(transaction)

        result = blockchain.add_transaction(
            wallet1.address,
            'recipient',
            10,
            signature
        )

        assert result is False

    def test_valid_proof(self):
        """Test proof of work validation."""
        transactions = []
        last_hash = "abc123"
        difficulty = 2

        # This should be invalid (doesn't start with 00)
        is_valid = Blockchain.valid_proof(transactions, last_hash, "999", difficulty)
        assert is_valid is False

    @pytest.mark.slow
    def test_proof_of_work(self):
        """Test proof of work calculation."""
        blockchain = Blockchain(difficulty=2)
        blockchain.transactions.append({
            'sender_public_key': 'test',
            'recipient_address': 'recipient',
            'value': 10
        })

        proof = blockchain.proof_of_work()

        assert isinstance(proof, int)
        assert proof >= 0

    @pytest.mark.slow
    def test_mine_block(self):
        """Test mining a new block."""
        blockchain = Blockchain(difficulty=2)
        miner_wallet = Wallet()

        initial_length = len(blockchain.chain)
        block_index = blockchain.mine(miner_wallet.address)

        assert block_index is not None
        assert len(blockchain.chain) == initial_length + 1
        assert blockchain.chain[-1].index == block_index

    def test_get_balance(self):
        """Test balance calculation."""
        blockchain = Blockchain()
        wallet = Wallet()

        # Initial balance
        balance = blockchain.get_balance(wallet.address)
        assert balance == 150  # Initial balance from config

    @pytest.mark.slow
    def test_get_balance_after_mining(self):
        """Test balance after mining."""
        blockchain = Blockchain(difficulty=2)
        miner_wallet = Wallet()

        initial_balance = blockchain.get_balance(miner_wallet.address)
        blockchain.mine(miner_wallet.address)
        new_balance = blockchain.get_balance(miner_wallet.address)

        assert new_balance > initial_balance

    def test_is_valid_chain(self):
        """Test blockchain validation."""
        blockchain = Blockchain()
        assert blockchain.is_valid_chain() is True

    def test_invalid_chain_detection(self):
        """Test detection of invalid chain."""
        blockchain = Blockchain()

        # Tamper with genesis block
        blockchain.chain[0].index = 999

        assert blockchain.is_valid_chain() is False

    def test_get_chain_length(self):
        """Test getting chain length."""
        blockchain = Blockchain()
        assert blockchain.get_chain_length() == 1

    def test_to_dict(self):
        """Test converting blockchain to dictionary."""
        blockchain = Blockchain()
        blockchain_dict = blockchain.to_dict()

        assert 'chain' in blockchain_dict
        assert 'pending_transactions' in blockchain_dict
        assert 'difficulty' in blockchain_dict
        assert 'miner_rewards' in blockchain_dict
        assert 'length' in blockchain_dict
        assert blockchain_dict['length'] == 1

    def test_repr(self):
        """Test string representation."""
        blockchain = Blockchain()
        repr_str = repr(blockchain)

        assert 'Blockchain' in repr_str
        assert 'length=1' in repr_str
        assert 'difficulty=2' in repr_str
