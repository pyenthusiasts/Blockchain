"""
Transaction class and utilities for blockchain transactions.
"""

from collections import OrderedDict
from typing import Dict, Any, Optional
from .wallet import Wallet


class Transaction:
    """
    Represents a transaction in the blockchain.

    Attributes:
        sender_public_key: Public key of the sender
        recipient_address: Address of the recipient
        value: Amount to transfer
        signature: Digital signature of the transaction
    """

    def __init__(
        self,
        sender_public_key: str,
        recipient_address: str,
        value: float,
        signature: Optional[bytes] = None
    ):
        """
        Initialize a new Transaction.

        Args:
            sender_public_key: Sender's public key
            recipient_address: Recipient's address
            value: Transaction amount
            signature: Optional transaction signature
        """
        self.sender_public_key = sender_public_key
        self.recipient_address = recipient_address
        self.value = value
        self.signature = signature

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert transaction to ordered dictionary.

        Returns:
            OrderedDict containing transaction data
        """
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_address': self.recipient_address,
            'value': self.value
        })

    def sign(self, wallet: Wallet) -> None:
        """
        Sign the transaction with a wallet.

        Args:
            wallet: Wallet instance to sign with

        Raises:
            ValueError: If wallet public key doesn't match sender
        """
        if wallet.address != self.sender_public_key:
            raise ValueError("Wallet does not match transaction sender")
        self.signature = wallet.sign_transaction(self.to_dict())

    def is_valid(self) -> bool:
        """
        Verify the transaction signature.

        Returns:
            True if signature is valid, False otherwise
        """
        if not self.signature:
            return False
        return Wallet.verify_signature(
            self.sender_public_key,
            self.signature,
            self.to_dict()
        )

    def __repr__(self) -> str:
        """
        String representation of the transaction.

        Returns:
            Formatted transaction information
        """
        sender_short = self.sender_public_key[:20] if len(self.sender_public_key) > 20 else self.sender_public_key
        recipient_short = self.recipient_address[:20] if len(self.recipient_address) > 20 else self.recipient_address
        return f"Transaction(from={sender_short}..., to={recipient_short}..., value={self.value})"

    @staticmethod
    def create_coinbase(recipient_address: str, reward: float) -> Dict[str, Any]:
        """
        Create a coinbase (mining reward) transaction.

        Args:
            recipient_address: Address to receive the reward
            reward: Reward amount

        Returns:
            Transaction dictionary for mining reward
        """
        return {
            'sender_public_key': 'network',
            'recipient_address': recipient_address,
            'value': reward
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        """
        Create a Transaction from a dictionary.

        Args:
            data: Dictionary containing transaction data

        Returns:
            New Transaction instance
        """
        return cls(
            sender_public_key=data['sender_public_key'],
            recipient_address=data['recipient_address'],
            value=data['value'],
            signature=data.get('signature')
        )
