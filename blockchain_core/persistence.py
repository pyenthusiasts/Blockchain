"""
Persistence layer for blockchain data using SQLite.
"""

import sqlite3
import json
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path

from .block import Block
from .blockchain import Blockchain

logger = logging.getLogger(__name__)


class BlockchainDB:
    """
    Database handler for blockchain persistence.
    """

    def __init__(self, db_path: str = 'blockchain.db'):
        """
        Initialize the database connection.

        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._init_database()

    def _init_database(self):
        """Initialize the database schema."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

        cursor = self.conn.cursor()

        # Create blocks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                block_index INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                transactions TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER,
                sender_public_key TEXT NOT NULL,
                recipient_address TEXT NOT NULL,
                value REAL NOT NULL,
                signature TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (block_index) REFERENCES blocks(block_index)
            )
        ''')

        # Create pending transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_public_key TEXT NOT NULL,
                recipient_address TEXT NOT NULL,
                value REAL NOT NULL,
                signature TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create indexes
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_blocks_hash
            ON blocks(hash)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_transactions_sender
            ON transactions(sender_public_key)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_transactions_recipient
            ON transactions(recipient_address)
        ''')

        self.conn.commit()
        logger.info(f"Database initialized at {self.db_path}")

    def save_block(self, block: Block) -> bool:
        """
        Save a block to the database.

        Args:
            block: Block to save

        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()

            # Save block
            cursor.execute('''
                INSERT OR REPLACE INTO blocks
                (block_index, timestamp, previous_hash, hash, nonce, transactions)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                block.index,
                block.timestamp,
                block.previous_hash,
                block.hash,
                block.nonce,
                json.dumps(block.transactions)
            ))

            # Save transactions
            for tx in block.transactions:
                cursor.execute('''
                    INSERT INTO transactions
                    (block_index, sender_public_key, recipient_address, value, signature)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    block.index,
                    tx.get('sender_public_key', ''),
                    tx.get('recipient_address', ''),
                    tx.get('value', 0),
                    tx.get('signature', '')
                ))

            self.conn.commit()
            logger.info(f"Block {block.index} saved to database")
            return True

        except Exception as e:
            logger.error(f"Error saving block: {e}")
            self.conn.rollback()
            return False

    def load_blockchain(self) -> Optional[List[Block]]:
        """
        Load the entire blockchain from the database.

        Returns:
            List of blocks or None if error
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT block_index, timestamp, previous_hash, hash, nonce, transactions
                FROM blocks
                ORDER BY block_index ASC
            ''')

            blocks = []
            for row in cursor.fetchall():
                block = Block(
                    index=row['block_index'],
                    transactions=json.loads(row['transactions']),
                    timestamp=row['timestamp'],
                    previous_hash=row['previous_hash'],
                    nonce=row['nonce']
                )
                block.hash = row['hash']
                blocks.append(block)

            logger.info(f"Loaded {len(blocks)} blocks from database")
            return blocks

        except Exception as e:
            logger.error(f"Error loading blockchain: {e}")
            return None

    def save_pending_transactions(self, transactions: List[Dict]) -> bool:
        """
        Save pending transactions to the database.

        Args:
            transactions: List of pending transactions

        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()

            # Clear existing pending transactions
            cursor.execute('DELETE FROM pending_transactions')

            # Save new pending transactions
            for tx in transactions:
                cursor.execute('''
                    INSERT INTO pending_transactions
                    (sender_public_key, recipient_address, value, signature)
                    VALUES (?, ?, ?, ?)
                ''', (
                    tx.get('sender_public_key', ''),
                    tx.get('recipient_address', ''),
                    tx.get('value', 0),
                    tx.get('signature', '')
                ))

            self.conn.commit()
            logger.info(f"Saved {len(transactions)} pending transactions")
            return True

        except Exception as e:
            logger.error(f"Error saving pending transactions: {e}")
            self.conn.rollback()
            return False

    def load_pending_transactions(self) -> List[Dict]:
        """
        Load pending transactions from the database.

        Returns:
            List of pending transactions
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT sender_public_key, recipient_address, value, signature
                FROM pending_transactions
            ''')

            transactions = []
            for row in cursor.fetchall():
                transactions.append({
                    'sender_public_key': row['sender_public_key'],
                    'recipient_address': row['recipient_address'],
                    'value': row['value'],
                    'signature': row['signature']
                })

            logger.info(f"Loaded {len(transactions)} pending transactions")
            return transactions

        except Exception as e:
            logger.error(f"Error loading pending transactions: {e}")
            return []

    def save_metadata(self, key: str, value: str) -> bool:
        """
        Save metadata key-value pair.

        Args:
            key: Metadata key
            value: Metadata value

        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO metadata (key, value)
                VALUES (?, ?)
            ''', (key, value))
            self.conn.commit()
            return True

        except Exception as e:
            logger.error(f"Error saving metadata: {e}")
            return False

    def load_metadata(self, key: str) -> Optional[str]:
        """
        Load metadata value by key.

        Args:
            key: Metadata key

        Returns:
            Metadata value or None if not found
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT value FROM metadata WHERE key = ?', (key,))
            row = cursor.fetchone()
            return row['value'] if row else None

        except Exception as e:
            logger.error(f"Error loading metadata: {e}")
            return None

    def get_block_by_index(self, index: int) -> Optional[Block]:
        """
        Get a block by its index.

        Args:
            index: Block index

        Returns:
            Block or None if not found
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT block_index, timestamp, previous_hash, hash, nonce, transactions
                FROM blocks
                WHERE block_index = ?
            ''', (index,))

            row = cursor.fetchone()
            if row:
                block = Block(
                    index=row['block_index'],
                    transactions=json.loads(row['transactions']),
                    timestamp=row['timestamp'],
                    previous_hash=row['previous_hash'],
                    nonce=row['nonce']
                )
                block.hash = row['hash']
                return block

            return None

        except Exception as e:
            logger.error(f"Error getting block: {e}")
            return None

    def get_transactions_by_address(self, address: str) -> List[Dict]:
        """
        Get all transactions involving an address.

        Args:
            address: Wallet address

        Returns:
            List of transactions
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT block_index, sender_public_key, recipient_address, value
                FROM transactions
                WHERE sender_public_key = ? OR recipient_address = ?
                ORDER BY block_index DESC
            ''', (address, address))

            transactions = []
            for row in cursor.fetchall():
                transactions.append({
                    'block_index': row['block_index'],
                    'sender': row['sender_public_key'],
                    'recipient': row['recipient_address'],
                    'value': row['value']
                })

            return transactions

        except Exception as e:
            logger.error(f"Error getting transactions: {e}")
            return []

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def save_blockchain_to_db(blockchain: Blockchain, db_path: str = 'blockchain.db') -> bool:
    """
    Save a blockchain to the database.

    Args:
        blockchain: Blockchain instance to save
        db_path: Path to database file

    Returns:
        True if successful, False otherwise
    """
    try:
        with BlockchainDB(db_path) as db:
            # Save all blocks
            for block in blockchain.chain:
                if not db.save_block(block):
                    return False

            # Save pending transactions
            if not db.save_pending_transactions(blockchain.transactions):
                return False

            # Save metadata
            db.save_metadata('difficulty', str(blockchain.difficulty))
            db.save_metadata('miner_rewards', str(blockchain.miner_rewards))

        logger.info(f"Blockchain saved to {db_path}")
        return True

    except Exception as e:
        logger.error(f"Error saving blockchain: {e}")
        return False


def load_blockchain_from_db(db_path: str = 'blockchain.db', difficulty: int = 2, miner_rewards: float = 50) -> Optional[Blockchain]:
    """
    Load a blockchain from the database.

    Args:
        db_path: Path to database file
        difficulty: Default difficulty if not in metadata
        miner_rewards: Default miner rewards if not in metadata

    Returns:
        Blockchain instance or None if error
    """
    try:
        with BlockchainDB(db_path) as db:
            # Load metadata
            saved_difficulty = db.load_metadata('difficulty')
            saved_rewards = db.load_metadata('miner_rewards')

            if saved_difficulty:
                difficulty = int(saved_difficulty)
            if saved_rewards:
                miner_rewards = float(saved_rewards)

            # Create blockchain
            blockchain = Blockchain(difficulty=difficulty, miner_rewards=miner_rewards)

            # Load blocks
            blocks = db.load_blockchain()
            if blocks:
                blockchain.chain = blocks

            # Load pending transactions
            blockchain.transactions = db.load_pending_transactions()

        logger.info(f"Blockchain loaded from {db_path}")
        return blockchain

    except Exception as e:
        logger.error(f"Error loading blockchain: {e}")
        return None
