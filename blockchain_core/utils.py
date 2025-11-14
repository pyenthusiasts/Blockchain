"""
Utility functions for the blockchain application.
"""

import hashlib
import json
import logging
from typing import Any, Dict, List


def setup_logging(level: str = 'INFO') -> logging.Logger:
    """
    Set up logging configuration.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured logger instance
    """
    logging.basicConfig(
        level=getattr(logging, level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)


def compute_hash(data: Any) -> str:
    """
    Compute SHA-256 hash of data.

    Args:
        data: Data to hash (will be JSON serialized if not string)

    Returns:
        Hexadecimal hash string
    """
    if not isinstance(data, (str, bytes)):
        data = json.dumps(data, sort_keys=True)
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def validate_address(address: str) -> bool:
    """
    Validate a blockchain address format.

    Args:
        address: Address string to validate

    Returns:
        True if valid, False otherwise
    """
    if not address or not isinstance(address, str):
        return False
    # For PEM format public keys
    return address.startswith('-----BEGIN PUBLIC KEY-----')


def serialize_transaction(transaction: Dict) -> str:
    """
    Serialize a transaction to a consistent format.

    Args:
        transaction: Transaction dictionary

    Returns:
        JSON string representation
    """
    return json.dumps(transaction, sort_keys=True)


def validate_transaction_structure(transaction: Dict) -> bool:
    """
    Validate the structure of a transaction.

    Args:
        transaction: Transaction dictionary to validate

    Returns:
        True if valid structure, False otherwise
    """
    required_fields = ['sender_public_key', 'recipient_address', 'value']
    return all(field in transaction for field in required_fields)


logger = setup_logging()
