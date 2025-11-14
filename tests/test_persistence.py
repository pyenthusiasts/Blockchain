"""
Test for blockchain persistence.
"""

import pytest
import tempfile
import os
from blockchain_core.persistence import BlockchainDB


class TestBlockchainDB:
    """Test cases for blockchain database."""

    def test_database_initialization(self):
        """Test database initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'test.db')
            db = BlockchainDB(db_path)
            assert db is not None
            assert db.conn is not None
            db.close()

    def test_metadata_operations(self):
        """Test metadata save and load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'test.db')
            with BlockchainDB(db_path) as db:
                # Save metadata
                success = db.save_metadata('test_key', 'test_value')
                assert success is True

                # Load metadata
                value = db.load_metadata('test_key')
                assert value == 'test_value'

                # Non-existent key
                value = db.load_metadata('nonexistent')
                assert value is None

    def test_context_manager(self):
        """Test context manager usage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'test.db')
            with BlockchainDB(db_path) as db:
                db.save_metadata('key', 'value')

            # Database should be closed
            # Re-open to verify data persisted
            with BlockchainDB(db_path) as db:
                value = db.load_metadata('key')
                assert value == 'value'
