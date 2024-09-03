# Blockchain Application - Simple Demo

A breakdown of this Blockchain structure's main components:

- Blockchain Class:

  - Manages the chain of blocks and transactions.
  - Includes methods for registering nodes, adding transactions, mining blocks, validating transactions and proofs, computing balances, etc.
  - Uses SHA-256 hashing for block and transaction integrity.
 
- Block Class:

  - Represents each block in the blockchain with an index, list of transactions, timestamp, previous block's hash, nonce, and its own hash.

- Wallet Class:

  - Handles wallet functionalities such as generating private/public key pairs, serializing public keys, and signing transactions.

- Main Function:

  - Demonstrates the blockchain in action by creating a blockchain instance, wallet instances for a sender and a miner, mining blocks, and performing transactions.

- Proof of Work (PoW):

  - Implements PoW for block mining, where miners must find a nonce that, when combined with block data, results in a hash with a specified number of leading zeros (difficulty).
