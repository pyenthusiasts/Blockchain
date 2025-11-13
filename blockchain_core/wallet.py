"""
Wallet class for managing cryptographic keys and signing transactions.
"""

import json
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class Wallet:
    """
    Represents a cryptocurrency wallet with public/private key pair.

    Attributes:
        private_key: ECDSA private key
        public_key: ECDSA public key
        address: Serialized public key used as address
    """

    def __init__(self, private_key=None):
        """
        Initialize a new Wallet.

        Args:
            private_key: Optional existing private key (for importing wallets)
        """
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = ec.generate_private_key(ec.SECP256K1())

        self.public_key = self.private_key.public_key()
        self.address = self.serialize_public_key()

    def serialize_public_key(self) -> str:
        """
        Serialize the public key to PEM format.

        Returns:
            PEM-formatted public key string
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def sign_transaction(self, transaction: Dict[str, Any]) -> bytes:
        """
        Sign a transaction with the private key.

        Args:
            transaction: Transaction dictionary to sign

        Returns:
            Digital signature as bytes
        """
        transaction_string = json.dumps(transaction, sort_keys=True).encode()
        signature = self.private_key.sign(
            transaction_string,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def export_private_key(self) -> str:
        """
        Export the private key in PEM format.

        Returns:
            PEM-formatted private key string

        Warning:
            Keep private keys secure and never share them!
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

    @classmethod
    def from_private_key(cls, private_key_pem: str) -> 'Wallet':
        """
        Create a Wallet from an existing private key.

        Args:
            private_key_pem: PEM-formatted private key string

        Returns:
            New Wallet instance with the imported key
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        return cls(private_key=private_key)

    @staticmethod
    def verify_signature(
        public_key_pem: str,
        signature: bytes,
        transaction: Dict[str, Any]
    ) -> bool:
        """
        Verify a transaction signature.

        Args:
            public_key_pem: PEM-formatted public key string
            signature: Digital signature to verify
            transaction: Original transaction data

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            transaction_string = json.dumps(transaction, sort_keys=True).encode()
            public_key.verify(
                signature,
                transaction_string,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Error verifying signature: {e}")
            return False

    def get_balance(self, blockchain) -> float:
        """
        Get the wallet's balance from the blockchain.

        Args:
            blockchain: Blockchain instance to query

        Returns:
            Current balance
        """
        return blockchain.get_balance(self.address)

    def __repr__(self) -> str:
        """
        String representation of the wallet.

        Returns:
            Wallet address (truncated)
        """
        return f"Wallet(address={self.address[:50]}...)"
