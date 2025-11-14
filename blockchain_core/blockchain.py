"""
Main Blockchain class implementation.
"""

import hashlib
import json
from time import time
from typing import List, Dict, Any, Optional, Set
from .block import Block
from .transaction import Transaction
from .wallet import Wallet
from .utils import logger


class Blockchain:
    """
    Main blockchain implementation with proof of work consensus.

    Attributes:
        transactions: List of pending transactions
        chain: List of blocks in the blockchain
        nodes: Set of network nodes
        difficulty: Proof of work difficulty level
        miner_rewards: Reward amount for mining a block
    """

    def __init__(self, difficulty: int = 2, miner_rewards: float = 50):
        """
        Initialize a new Blockchain.

        Args:
            difficulty: Number of leading zeros required in block hash
            miner_rewards: Reward amount for successfully mining a block
        """
        self.transactions: List[Dict[str, Any]] = []
        self.chain: List[Block] = []
        self.nodes: Set[str] = set()
        self.difficulty = difficulty
        self.miner_rewards = miner_rewards
        self.create_genesis_block()
        logger.info("Blockchain initialized with difficulty %d", difficulty)

    def create_genesis_block(self) -> None:
        """
        Create the genesis (first) block of the blockchain.
        """
        genesis_block = Block(0, [], time(), "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)
        logger.info("Genesis block created: %s", genesis_block.hash)

    def register_node(self, address: str) -> bool:
        """
        Register a new node in the network.

        Args:
            address: Network address of the node

        Returns:
            True if node was added, False if already registered
        """
        if address in self.nodes:
            return False
        self.nodes.add(address)
        logger.info("Node registered: %s", address)
        return True

    def verify_transaction_signature(
        self,
        sender_public_key: str,
        signature: bytes,
        transaction: Dict[str, Any]
    ) -> bool:
        """
        Verify a transaction signature.

        Args:
            sender_public_key: Sender's public key
            signature: Transaction signature
            transaction: Transaction data

        Returns:
            True if signature is valid, False otherwise
        """
        return Wallet.verify_signature(sender_public_key, signature, transaction)

    def add_transaction(
        self,
        sender_public_key: str,
        recipient_address: str,
        value: float,
        signature: bytes
    ) -> bool:
        """
        Add a new transaction to the pending transactions.

        Args:
            sender_public_key: Sender's public key
            recipient_address: Recipient's address
            value: Transaction amount
            signature: Transaction signature

        Returns:
            True if transaction was added, False if invalid
        """
        from collections import OrderedDict

        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_address': recipient_address,
            'value': value
        })

        # Verify signature
        if not self.verify_transaction_signature(sender_public_key, signature, transaction):
            logger.warning("Transaction rejected: Invalid signature")
            return False

        # Check sender balance
        sender_balance = self.get_balance(sender_public_key)
        if sender_balance < value:
            logger.warning("Transaction rejected: Insufficient balance (has: %f, needs: %f)",
                         sender_balance, value)
            return False

        self.transactions.append(transaction)
        logger.info("Transaction added: %s -> %s (%.2f)",
                   sender_public_key[:20], recipient_address[:20], value)
        return True

    def last_block(self) -> Block:
        """
        Get the last block in the chain.

        Returns:
            The most recent block
        """
        return self.chain[-1]

    def add_block(self, block: Block, proof: str, miner_address: str) -> bool:
        """
        Add a new block to the blockchain.

        Args:
            block: Block to add
            proof: Proof of work hash
            miner_address: Address of the miner

        Returns:
            True if block was added, False if invalid
        """
        previous_hash = self.last_block().hash

        # Verify previous hash
        if previous_hash != block.previous_hash:
            logger.error("Block rejected: Invalid previous hash")
            return False

        # Verify proof of work
        if not self.valid_proof(block.transactions, block.previous_hash, proof, self.difficulty):
            logger.error("Block rejected: Invalid proof of work")
            return False

        block.hash = proof
        self.chain.append(block)
        self.transactions = []

        # Add mining reward transaction for next block
        self.transactions.append({
            'sender_public_key': 'network',
            'recipient_address': miner_address,
            'value': self.miner_rewards
        })

        logger.info("Block added: index=%d, hash=%s", block.index, block.hash[:16])
        return True

    @staticmethod
    def valid_proof(
        transactions: List[Dict[str, Any]],
        last_hash: str,
        proof: str,
        difficulty: int
    ) -> bool:
        """
        Validate a proof of work.

        Args:
            transactions: List of transactions in the block
            last_hash: Hash of the previous block
            proof: Proof of work to validate
            difficulty: Required difficulty level

        Returns:
            True if proof is valid, False otherwise
        """
        transactions_serialized = json.dumps(transactions, sort_keys=True).encode()
        last_hash_bytes = str(last_hash).encode()
        proof_bytes = str(proof).encode()
        guess = transactions_serialized + last_hash_bytes + proof_bytes
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def proof_of_work(self) -> int:
        """
        Find a valid proof of work for the current transactions.

        Returns:
            Valid proof (nonce)
        """
        last_block = self.last_block()
        last_hash = last_block.hash
        proof = 0

        logger.info("Starting proof of work (difficulty: %d)...", self.difficulty)
        while not self.valid_proof(self.transactions, last_hash, proof, self.difficulty):
            proof += 1

        logger.info("Proof of work found: %d", proof)
        return proof

    def mine(self, miner_address: str) -> Optional[int]:
        """
        Mine a new block.

        Args:
            miner_address: Address to receive mining reward

        Returns:
            Index of the new block, or None if mining failed
        """
        logger.info("Mining new block for miner: %s", miner_address[:20])

        # Add mining reward
        self.transactions.append({
            'sender_public_key': 'network',
            'recipient_address': miner_address,
            'value': self.miner_rewards
        })

        last_block = self.last_block()
        proof = self.proof_of_work()
        previous_hash = last_block.hash

        block = Block(
            index=last_block.index + 1,
            transactions=self.transactions.copy(),
            timestamp=time(),
            previous_hash=previous_hash
        )

        if self.add_block(block, proof, miner_address):
            logger.info("Block mined successfully: index=%d", block.index)
            return block.index

        logger.error("Failed to mine block")
        return None

    def get_balance(self, address: str) -> float:
        """
        Calculate the balance for an address.

        Args:
            address: Address to check

        Returns:
            Current balance
        """
        balance = 150.0  # Initial balance

        for block in self.chain:
            for transaction in block.transactions:
                if 'recipient_address' in transaction and transaction['recipient_address'] == address:
                    balance += transaction['value']
                if 'sender_public_key' in transaction and transaction['sender_public_key'] == address:
                    balance -= transaction['value']

        return balance

    def is_valid_chain(self, chain: Optional[List[Block]] = None) -> bool:
        """
        Validate the blockchain.

        Args:
            chain: Optional chain to validate (defaults to self.chain)

        Returns:
            True if chain is valid, False otherwise
        """
        if chain is None:
            chain = self.chain

        if len(chain) == 0:
            return False

        # Check genesis block
        genesis = chain[0]
        if genesis.index != 0 or genesis.previous_hash != "0":
            return False

        # Validate each block
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            # Check hash linkage
            if current_block.previous_hash != previous_block.hash:
                logger.error("Chain invalid: broken hash linkage at block %d", i)
                return False

            # Check block hash validity
            if not current_block.is_valid():
                logger.error("Chain invalid: invalid block hash at block %d", i)
                return False

        return True

    def get_chain_length(self) -> int:
        """
        Get the length of the blockchain.

        Returns:
            Number of blocks in the chain
        """
        return len(self.chain)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert blockchain to dictionary representation.

        Returns:
            Dictionary containing blockchain data
        """
        return {
            'chain': [block.to_dict() for block in self.chain],
            'pending_transactions': self.transactions,
            'difficulty': self.difficulty,
            'miner_rewards': self.miner_rewards,
            'length': len(self.chain)
        }

    def __repr__(self) -> str:
        """
        String representation of the blockchain.

        Returns:
            Formatted blockchain information
        """
        return f"Blockchain(length={len(self.chain)}, difficulty={self.difficulty})"
