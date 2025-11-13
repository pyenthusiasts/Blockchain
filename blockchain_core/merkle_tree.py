"""
Merkle Tree implementation for efficient transaction verification.
"""

import hashlib
import json
from typing import List, Optional, Dict, Any, Tuple
from .utils import compute_hash


class MerkleNode:
    """
    Represents a node in the Merkle tree.
    """

    def __init__(self, data: str = '', left: Optional['MerkleNode'] = None, right: Optional['MerkleNode'] = None):
        """
        Initialize a Merkle tree node.

        Args:
            data: Data or hash value
            left: Left child node
            right: Right child node
        """
        self.left = left
        self.right = right

        # If leaf node, hash the data; otherwise, hash the concatenation of children
        if left is None and right is None:
            self.hash = compute_hash(data)
        else:
            left_hash = left.hash if left else ''
            right_hash = right.hash if right else ''
            self.hash = compute_hash(left_hash + right_hash)

    def __repr__(self) -> str:
        """String representation of the node."""
        return f"MerkleNode(hash={self.hash[:16]}...)"


class MerkleTree:
    """
    Merkle Tree for efficient transaction verification.

    A Merkle tree is a binary tree where:
    - Leaf nodes contain hashes of data
    - Non-leaf nodes contain hashes of their children
    - The root hash represents all data in the tree
    """

    def __init__(self, transactions: List[Dict[str, Any]]):
        """
        Initialize a Merkle tree from transactions.

        Args:
            transactions: List of transaction dictionaries
        """
        self.transactions = transactions
        self.root: Optional[MerkleNode] = None
        self.leaves: List[MerkleNode] = []
        self._build_tree()

    def _build_tree(self):
        """Build the Merkle tree from transactions."""
        if not self.transactions:
            self.root = MerkleNode('')
            return

        # Create leaf nodes
        self.leaves = [
            MerkleNode(json.dumps(tx, sort_keys=True))
            for tx in self.transactions
        ]

        # Build tree bottom-up
        current_level = self.leaves.copy()

        while len(current_level) > 1:
            next_level = []

            # Process pairs of nodes
            for i in range(0, len(current_level), 2):
                left = current_level[i]

                # If odd number of nodes, duplicate the last one
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = current_level[i]

                # Create parent node
                parent = MerkleNode('', left, right)
                next_level.append(parent)

            current_level = next_level

        # Root is the last remaining node
        self.root = current_level[0] if current_level else MerkleNode('')

    def get_root_hash(self) -> str:
        """
        Get the Merkle root hash.

        Returns:
            Root hash string
        """
        return self.root.hash if self.root else ''

    def get_proof(self, transaction: Dict[str, Any]) -> List[Tuple[str, str]]:
        """
        Generate a Merkle proof for a transaction.

        A Merkle proof is a list of hashes needed to reconstruct the path
        from a leaf to the root.

        Args:
            transaction: Transaction to prove

        Returns:
            List of (hash, position) tuples where position is 'left' or 'right'
        """
        # Find the transaction in leaves
        tx_hash = compute_hash(json.dumps(transaction, sort_keys=True))
        try:
            index = next(i for i, leaf in enumerate(self.leaves) if leaf.hash == tx_hash)
        except StopIteration:
            return []

        proof = []
        current_level = self.leaves.copy()

        while len(current_level) > 1:
            next_level = []
            next_index = -1

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]

                parent = MerkleNode('', left, right)
                next_level.append(parent)

                # Track which parent contains our node
                if i == index or i + 1 == index:
                    next_index = len(next_level) - 1

                    # Add sibling hash to proof
                    if i == index:
                        # Current node is left, add right sibling
                        proof.append((right.hash, 'right'))
                    else:
                        # Current node is right, add left sibling
                        proof.append((left.hash, 'left'))

            current_level = next_level
            index = next_index

        return proof

    def verify_proof(self, transaction: Dict[str, Any], proof: List[Tuple[str, str]], root_hash: str) -> bool:
        """
        Verify a Merkle proof.

        Args:
            transaction: Transaction to verify
            proof: Merkle proof (list of hash, position tuples)
            root_hash: Expected root hash

        Returns:
            True if proof is valid, False otherwise
        """
        # Start with transaction hash
        current_hash = compute_hash(json.dumps(transaction, sort_keys=True))

        # Apply each step in the proof
        for sibling_hash, position in proof:
            if position == 'left':
                # Sibling is on the left
                current_hash = compute_hash(sibling_hash + current_hash)
            else:
                # Sibling is on the right
                current_hash = compute_hash(current_hash + sibling_hash)

        # Check if we arrived at the root
        return current_hash == root_hash

    def get_tree_height(self) -> int:
        """
        Get the height of the Merkle tree.

        Returns:
            Tree height
        """
        if not self.root:
            return 0

        def get_height(node: Optional[MerkleNode]) -> int:
            if node is None:
                return 0
            return 1 + max(get_height(node.left), get_height(node.right))

        return get_height(self.root)

    def get_tree_size(self) -> int:
        """
        Get the total number of nodes in the tree.

        Returns:
            Number of nodes
        """
        if not self.root:
            return 0

        def count_nodes(node: Optional[MerkleNode]) -> int:
            if node is None:
                return 0
            return 1 + count_nodes(node.left) + count_nodes(node.right)

        return count_nodes(self.root)

    def visualize(self, node: Optional[MerkleNode] = None, prefix: str = '', is_tail: bool = True) -> str:
        """
        Generate a visual representation of the tree.

        Args:
            node: Node to visualize (defaults to root)
            prefix: Prefix for current line
            is_tail: Whether this is the last child

        Returns:
            String representation of the tree
        """
        if node is None:
            node = self.root

        if node is None:
            return "Empty tree"

        result = prefix + ("└── " if is_tail else "├── ") + f"{node.hash[:16]}...\n"

        children = []
        if node.left:
            children.append(node.left)
        if node.right and node.right != node.left:
            children.append(node.right)

        for i, child in enumerate(children):
            extension = "    " if is_tail else "│   "
            result += self.visualize(child, prefix + extension, i == len(children) - 1)

        return result

    def __repr__(self) -> str:
        """String representation of the Merkle tree."""
        return f"MerkleTree(transactions={len(self.transactions)}, root_hash={self.get_root_hash()[:16]}...)"


def create_merkle_tree(transactions: List[Dict[str, Any]]) -> MerkleTree:
    """
    Create a Merkle tree from transactions.

    Args:
        transactions: List of transaction dictionaries

    Returns:
        MerkleTree instance
    """
    return MerkleTree(transactions)


def verify_transaction_in_block(
    transaction: Dict[str, Any],
    merkle_root: str,
    merkle_proof: List[Tuple[str, str]]
) -> bool:
    """
    Verify that a transaction is included in a block using its Merkle proof.

    Args:
        transaction: Transaction to verify
        merkle_root: Merkle root hash of the block
        merkle_proof: Merkle proof for the transaction

    Returns:
        True if transaction is in the block, False otherwise
    """
    # Start with transaction hash
    current_hash = compute_hash(json.dumps(transaction, sort_keys=True))

    # Apply proof steps
    for sibling_hash, position in merkle_proof:
        if position == 'left':
            current_hash = compute_hash(sibling_hash + current_hash)
        else:
            current_hash = compute_hash(current_hash + sibling_hash)

    return current_hash == merkle_root
