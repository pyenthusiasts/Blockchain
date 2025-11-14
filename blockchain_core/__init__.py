"""
Blockchain Core - A simple but comprehensive blockchain implementation.

This package provides all the core functionality for a blockchain system including:
- Block creation and validation
- Transaction management and signing
- Wallet management with cryptographic keys
- Proof of work consensus algorithm
- Network node management
- Merkle tree for efficient transaction verification
- Database persistence layer
"""

from .blockchain import Blockchain
from .block import Block
from .wallet import Wallet
from .transaction import Transaction
from .utils import setup_logging, compute_hash, validate_address
from .merkle_tree import MerkleTree, MerkleNode
from .persistence import BlockchainDB, save_blockchain_to_db, load_blockchain_from_db

__version__ = '2.0.0'
__author__ = 'Python Enthusiasts'

__all__ = [
    'Blockchain',
    'Block',
    'Wallet',
    'Transaction',
    'MerkleTree',
    'MerkleNode',
    'BlockchainDB',
    'save_blockchain_to_db',
    'load_blockchain_from_db',
    'setup_logging',
    'compute_hash',
    'validate_address',
]
