"""
Integration tests for the blockchain system.

These tests verify that multiple components work together correctly.
"""

import pytest
import tempfile
import os
from pathlib import Path

from blockchain_core import Blockchain, Wallet
from blockchain_core.persistence import BlockchainDB, save_blockchain_to_db, load_blockchain_from_db
from blockchain_core.merkle_tree import MerkleTree
from collections import OrderedDict


class TestEndToEnd:
    """End-to-end integration tests."""

    def test_full_transaction_flow(self):
        """Test complete transaction flow from wallet creation to mining."""
        # Create blockchain
        blockchain = Blockchain(difficulty=2)

        # Create wallets
        alice = Wallet()
        bob = Wallet()
        miner = Wallet()

        # Initial balances
        alice_initial = blockchain.get_balance(alice.address)
        bob_initial = blockchain.get_balance(bob.address)

        # Mine initial block for Alice
        blockchain.mine(alice.address)
        assert blockchain.get_chain_length() == 2  # Genesis + 1

        # Alice should have received mining reward
        alice_balance = blockchain.get_balance(alice.address)
        assert alice_balance > alice_initial

        # Create transaction from Alice to Bob
        transaction = OrderedDict({
            'sender_public_key': alice.address,
            'recipient_address': bob.address,
            'value': 25
        })

        signature = alice.sign_transaction(transaction)
        success = blockchain.add_transaction(
            alice.address,
            bob.address,
            25,
            signature
        )

        assert success is True
        assert len(blockchain.transactions) > 0

        # Mine to confirm transaction
        blockchain.mine(miner.address)

        # Verify balances
        alice_final = blockchain.get_balance(alice.address)
        bob_final = blockchain.get_balance(bob.address)

        assert alice_final < alice_balance  # Alice sent money
        assert bob_final > bob_initial  # Bob received money
        assert bob_final == bob_initial + 25

        # Verify chain validity
        assert blockchain.is_valid_chain()

    def test_multiple_transactions_and_mining(self):
        """Test multiple transactions across multiple blocks."""
        blockchain = Blockchain(difficulty=2)

        # Create wallets
        wallets = [Wallet() for _ in range(5)]

        # Mine initial block for first wallet
        blockchain.mine(wallets[0].address)

        # Create multiple transactions
        for i in range(4):
            sender = wallets[i]
            recipient = wallets[i + 1]

            transaction = OrderedDict({
                'sender_public_key': sender.address,
                'recipient_address': recipient.address,
                'value': 10
            })

            signature = sender.sign_transaction(transaction)
            blockchain.add_transaction(
                sender.address,
                recipient.address,
                10,
                signature
            )

            # Mine every 2 transactions
            if i % 2 == 1:
                blockchain.mine(wallets[0].address)

        # Mine remaining transactions
        if blockchain.transactions:
            blockchain.mine(wallets[0].address)

        # Verify chain is valid
        assert blockchain.is_valid_chain()

        # Verify chain length
        assert blockchain.get_chain_length() > 2

        # Verify last wallet received funds
        assert blockchain.get_balance(wallets[4].address) > 150  # Initial + received

    @pytest.mark.slow
    def test_chain_validation_after_tampering(self):
        """Test that tampering with blockchain is detected."""
        blockchain = Blockchain(difficulty=2)
        wallet = Wallet()

        # Create valid blockchain
        blockchain.mine(wallet.address)
        blockchain.mine(wallet.address)

        # Verify it's valid
        assert blockchain.is_valid_chain()

        # Tamper with a block
        blockchain.chain[1].transactions.append({
            'sender_public_key': 'hacker',
            'recipient_address': 'hacker_wallet',
            'value': 1000000
        })

        # Should be invalid now
        assert not blockchain.is_valid_chain()


class TestPersistence:
    """Integration tests for persistence layer."""

    def test_save_and_load_blockchain(self):
        """Test saving and loading blockchain from database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'test_blockchain.db')

            # Create and populate blockchain
            blockchain1 = Blockchain(difficulty=2)
            wallet = Wallet()

            blockchain1.mine(wallet.address)
            blockchain1.mine(wallet.address)

            # Save to database
            success = save_blockchain_to_db(blockchain1, db_path)
            assert success

            # Load from database
            blockchain2 = load_blockchain_from_db(db_path)
            assert blockchain2 is not None

            # Verify loaded blockchain
            assert blockchain2.get_chain_length() == blockchain1.get_chain_length()
            assert blockchain2.difficulty == blockchain1.difficulty
            assert blockchain2.miner_rewards == blockchain1.miner_rewards

            # Verify chain is valid
            assert blockchain2.is_valid_chain()

    def test_persistence_with_transactions(self):
        """Test saving and loading blockchain with pending transactions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'test_blockchain.db')

            # Create blockchain with transactions
            blockchain1 = Blockchain(difficulty=2)
            alice = Wallet()
            bob = Wallet()

            blockchain1.mine(alice.address)

            transaction = OrderedDict({
                'sender_public_key': alice.address,
                'recipient_address': bob.address,
                'value': 10
            })

            signature = alice.sign_transaction(transaction)
            blockchain1.add_transaction(
                alice.address,
                bob.address,
                10,
                signature
            )

            # Save with pending transactions
            save_blockchain_to_db(blockchain1, db_path)

            # Load and verify
            blockchain2 = load_blockchain_from_db(db_path)
            assert len(blockchain2.transactions) > 0


class TestMerkleTreeIntegration:
    """Integration tests for Merkle tree with blockchain."""

    def test_merkle_tree_with_block_transactions(self):
        """Test Merkle tree creation from block transactions."""
        blockchain = Blockchain(difficulty=2)
        wallet = Wallet()

        # Add some transactions and mine
        for i in range(5):
            blockchain.transactions.append({
                'sender': f'sender_{i}',
                'recipient': f'recipient_{i}',
                'value': i * 10
            })

        blockchain.mine(wallet.address)

        # Get the mined block
        block = blockchain.chain[-1]

        # Create Merkle tree from block transactions
        merkle_tree = MerkleTree(block.transactions)

        # Verify root hash
        root_hash = merkle_tree.get_root_hash()
        assert len(root_hash) == 64  # SHA-256

        # Verify proof for a transaction
        if block.transactions:
            tx = block.transactions[0]
            proof = merkle_tree.get_proof(tx)
            is_valid = merkle_tree.verify_proof(tx, proof, root_hash)
            assert is_valid

    def test_merkle_proof_verification_across_blocks(self):
        """Test Merkle proof verification for transactions across multiple blocks."""
        blockchain = Blockchain(difficulty=2)
        wallet = Wallet()

        # Mine several blocks with transactions
        for block_num in range(3):
            for tx_num in range(3):
                blockchain.transactions.append({
                    'sender': f'sender_{block_num}_{tx_num}',
                    'recipient': f'recipient_{block_num}_{tx_num}',
                    'value': (block_num + 1) * (tx_num + 1) * 10
                })

            blockchain.mine(wallet.address)

        # Verify Merkle proofs for all blocks
        for block in blockchain.chain[1:]:  # Skip genesis
            if block.transactions:
                tree = MerkleTree(block.transactions)
                root = tree.get_root_hash()

                # Verify each transaction
                for tx in block.transactions:
                    proof = tree.get_proof(tx)
                    assert tree.verify_proof(tx, proof, root)


class TestWalletAndTransactions:
    """Integration tests for wallet and transaction interactions."""

    def test_wallet_export_import_and_use(self):
        """Test exporting, importing, and using a wallet."""
        # Create original wallet
        wallet1 = Wallet()
        address1 = wallet1.address
        private_key = wallet1.export_private_key()

        # Import wallet from private key
        wallet2 = Wallet.from_private_key(private_key)
        address2 = wallet2.address

        # Verify addresses match
        assert address1 == address2

        # Create and sign transaction with both wallets
        transaction = OrderedDict({
            'sender_public_key': address1,
            'recipient_address': 'recipient',
            'value': 100
        })

        signature1 = wallet1.sign_transaction(transaction)
        signature2 = wallet2.sign_transaction(transaction)

        # Verify both signatures are valid
        assert Wallet.verify_signature(address1, signature1, transaction)
        assert Wallet.verify_signature(address2, signature2, transaction)

    def test_transaction_validation_in_blockchain(self):
        """Test transaction validation with various scenarios."""
        blockchain = Blockchain(difficulty=2)
        alice = Wallet()
        bob = Wallet()

        # Mine to give Alice funds
        blockchain.mine(alice.address)

        alice_balance = blockchain.get_balance(alice.address)

        # Valid transaction
        transaction = OrderedDict({
            'sender_public_key': alice.address,
            'recipient_address': bob.address,
            'value': 10
        })

        signature = alice.sign_transaction(transaction)
        assert blockchain.add_transaction(
            alice.address,
            bob.address,
            10,
            signature
        )

        # Invalid signature
        fake_signature = bob.sign_transaction(transaction)
        assert not blockchain.add_transaction(
            alice.address,
            bob.address,
            10,
            fake_signature
        )

        # Insufficient balance
        transaction2 = OrderedDict({
            'sender_public_key': alice.address,
            'recipient_address': bob.address,
            'value': alice_balance + 1000
        })

        signature2 = alice.sign_transaction(transaction2)
        assert not blockchain.add_transaction(
            alice.address,
            bob.address,
            alice_balance + 1000,
            signature2
        )


class TestDatabaseOperations:
    """Integration tests for database operations."""

    def test_database_queries(self):
        """Test database query operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'test.db')

            with BlockchainDB(db_path) as db:
                # Create test blockchain
                blockchain = Blockchain(difficulty=2)
                wallet = Wallet()

                # Mine blocks
                blockchain.mine(wallet.address)
                blockchain.mine(wallet.address)

                # Save blocks
                for block in blockchain.chain:
                    db.save_block(block)

                # Test get_block_by_index
                block = db.get_block_by_index(0)
                assert block is not None
                assert block.index == 0

                # Test get_transactions_by_address
                transactions = db.get_transactions_by_address(wallet.address)
                assert len(transactions) > 0

    def test_metadata_storage(self):
        """Test storing and retrieving metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'test.db')

            with BlockchainDB(db_path) as db:
                # Save metadata
                db.save_metadata('test_key', 'test_value')
                db.save_metadata('difficulty', '4')

                # Load metadata
                value1 = db.load_metadata('test_key')
                value2 = db.load_metadata('difficulty')

                assert value1 == 'test_value'
                assert value2 == '4'

                # Non-existent key
                value3 = db.load_metadata('nonexistent')
                assert value3 is None


@pytest.mark.integration
class TestCompleteSystem:
    """Tests for the complete blockchain system."""

    @pytest.mark.slow
    def test_complete_blockchain_lifecycle(self):
        """Test complete blockchain lifecycle."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'blockchain.db')

            # Phase 1: Create and populate blockchain
            blockchain = Blockchain(difficulty=2)
            wallets = [Wallet() for _ in range(3)]

            # Mine initial blocks
            for _ in range(2):
                blockchain.mine(wallets[0].address)

            # Create transactions
            transaction = OrderedDict({
                'sender_public_key': wallets[0].address,
                'recipient_address': wallets[1].address,
                'value': 20
            })

            signature = wallets[0].sign_transaction(transaction)
            blockchain.add_transaction(
                wallets[0].address,
                wallets[1].address,
                20,
                signature
            )

            # Mine transaction
            blockchain.mine(wallets[2].address)

            # Verify initial state
            assert blockchain.is_valid_chain()
            initial_length = blockchain.get_chain_length()
            initial_balance_0 = blockchain.get_balance(wallets[0].address)
            initial_balance_1 = blockchain.get_balance(wallets[1].address)

            # Phase 2: Save to database
            assert save_blockchain_to_db(blockchain, db_path)

            # Phase 3: Load from database
            loaded_blockchain = load_blockchain_from_db(db_path)
            assert loaded_blockchain is not None

            # Phase 4: Verify loaded blockchain
            assert loaded_blockchain.get_chain_length() == initial_length
            assert loaded_blockchain.is_valid_chain()

            # Verify balances are preserved
            loaded_balance_0 = loaded_blockchain.get_balance(wallets[0].address)
            loaded_balance_1 = loaded_blockchain.get_balance(wallets[1].address)

            assert loaded_balance_0 == initial_balance_0
            assert loaded_balance_1 == initial_balance_1

            # Phase 5: Continue using loaded blockchain
            loaded_blockchain.mine(wallets[2].address)
            assert loaded_blockchain.get_chain_length() == initial_length + 1
            assert loaded_blockchain.is_valid_chain()


if __name__ == "__main__":
    # Run integration tests
    pytest.main([__file__, '-v'])
