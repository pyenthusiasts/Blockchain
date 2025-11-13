"""
Blockchain Core - A simple but comprehensive blockchain implementation.

This package provides all the core functionality for a blockchain system including:
- Block creation and validation
- Transaction management and signing
- Wallet management with cryptographic keys
- Proof of work consensus algorithm
- Network node management
"""

from .blockchain import Blockchain
from .block import Block
from .wallet import Wallet
from .transaction import Transaction
from .utils import setup_logging, compute_hash, validate_address

__version__ = '1.0.0'
__author__ = 'Python Enthusiasts'

__all__ = [
    'Blockchain',
    'Block',
    'Wallet',
    'Transaction',
    'setup_logging',
    'compute_hash',
    'validate_address',
]
