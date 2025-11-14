# API Documentation

Complete API reference for the Blockchain implementation.

## Table of Contents

- [Blockchain Class](#blockchain-class)
- [Block Class](#block-class)
- [Wallet Class](#wallet-class)
- [Transaction Class](#transaction-class)
- [Utility Functions](#utility-functions)

---

## Blockchain Class

Main class for managing the blockchain.

### Constructor

```python
Blockchain(difficulty: int = 2, miner_rewards: float = 50)
```

**Parameters:**
- `difficulty` (int): Number of leading zeros required in block hash
- `miner_rewards` (float): Reward amount for mining a block

**Example:**
```python
blockchain = Blockchain(difficulty=4, miner_rewards=25)
```

### Methods

#### `create_genesis_block()`

Creates the genesis (first) block of the blockchain.

**Returns:** None

---

#### `register_node(address: str) -> bool`

Register a new node in the network.

**Parameters:**
- `address` (str): Network address of the node

**Returns:** bool - True if node was added, False if already registered

**Example:**
```python
blockchain.register_node("http://192.168.1.1:5000")
```

---

#### `add_transaction(sender_public_key: str, recipient_address: str, value: float, signature: bytes) -> bool`

Add a new transaction to the pending transactions pool.

**Parameters:**
- `sender_public_key` (str): Sender's public key
- `recipient_address` (str): Recipient's address
- `value` (float): Transaction amount
- `signature` (bytes): Transaction signature

**Returns:** bool - True if transaction was added, False if invalid

**Example:**
```python
success = blockchain.add_transaction(
    sender_wallet.address,
    recipient_wallet.address,
    50,
    signature
)
```

---

#### `mine(miner_address: str) -> Optional[int]`

Mine a new block with pending transactions.

**Parameters:**
- `miner_address` (str): Address to receive mining reward

**Returns:** Optional[int] - Index of the new block, or None if mining failed

**Example:**
```python
block_index = blockchain.mine(miner_wallet.address)
if block_index:
    print(f"Block {block_index} mined successfully!")
```

---

#### `get_balance(address: str) -> float`

Calculate the balance for an address.

**Parameters:**
- `address` (str): Address to check

**Returns:** float - Current balance

**Example:**
```python
balance = blockchain.get_balance(wallet.address)
```

---

#### `is_valid_chain(chain: Optional[List[Block]] = None) -> bool`

Validate the blockchain integrity.

**Parameters:**
- `chain` (Optional[List[Block]]): Optional chain to validate (defaults to self.chain)

**Returns:** bool - True if chain is valid, False otherwise

**Example:**
```python
if blockchain.is_valid_chain():
    print("Blockchain is valid!")
```

---

#### `get_chain_length() -> int`

Get the length of the blockchain.

**Returns:** int - Number of blocks in the chain

---

#### `to_dict() -> Dict[str, Any]`

Convert blockchain to dictionary representation.

**Returns:** dict - Dictionary containing blockchain data

**Example:**
```python
blockchain_data = blockchain.to_dict()
```

---

#### `last_block() -> Block`

Get the last block in the chain.

**Returns:** Block - The most recent block

---

#### `proof_of_work() -> int`

Find a valid proof of work for the current transactions.

**Returns:** int - Valid proof (nonce)

---

#### `valid_proof(transactions: List[Dict], last_hash: str, proof: str, difficulty: int) -> bool` (static)

Validate a proof of work.

**Parameters:**
- `transactions` (List[Dict]): List of transactions
- `last_hash` (str): Hash of the previous block
- `proof` (str): Proof to validate
- `difficulty` (int): Required difficulty level

**Returns:** bool - True if proof is valid

---

## Block Class

Represents a single block in the blockchain.

### Constructor

```python
Block(index: int, transactions: List[Dict], timestamp: float, previous_hash: str, nonce: int = 0)
```

**Parameters:**
- `index` (int): Block position in the chain
- `transactions` (List[Dict]): List of transaction dictionaries
- `timestamp` (float): Block creation timestamp
- `previous_hash` (str): Hash of the previous block
- `nonce` (int): Proof of work nonce (default: 0)

**Example:**
```python
block = Block(1, transactions, time(), "previous_hash")
```

### Methods

#### `compute_hash() -> str`

Compute SHA-256 hash of the block.

**Returns:** str - Hexadecimal hash string

---

#### `to_dict() -> Dict[str, Any]`

Convert block to dictionary representation.

**Returns:** dict - Dictionary containing all block data

---

#### `is_valid() -> bool`

Check if block hash is valid.

**Returns:** bool - True if hash matches computed hash

---

#### `from_dict(data: Dict[str, Any]) -> Block` (classmethod)

Create a Block instance from a dictionary.

**Parameters:**
- `data` (dict): Dictionary containing block data

**Returns:** Block - New Block instance

---

## Wallet Class

Manages cryptographic keys and transaction signing.

### Constructor

```python
Wallet(private_key=None)
```

**Parameters:**
- `private_key` (optional): Existing private key for importing wallets

**Example:**
```python
# Create new wallet
wallet = Wallet()

# Import from existing key
wallet = Wallet(private_key=existing_key)
```

### Attributes

- `private_key`: ECDSA private key
- `public_key`: ECDSA public key
- `address`: Serialized public key used as address

### Methods

#### `serialize_public_key() -> str`

Serialize the public key to PEM format.

**Returns:** str - PEM-formatted public key string

---

#### `sign_transaction(transaction: Dict[str, Any]) -> bytes`

Sign a transaction with the private key.

**Parameters:**
- `transaction` (dict): Transaction dictionary to sign

**Returns:** bytes - Digital signature

**Example:**
```python
signature = wallet.sign_transaction(transaction_data)
```

---

#### `export_private_key() -> str`

Export the private key in PEM format.

**Returns:** str - PEM-formatted private key string

**Warning:** Keep private keys secure!

**Example:**
```python
private_key = wallet.export_private_key()
```

---

#### `from_private_key(private_key_pem: str) -> Wallet` (classmethod)

Create a Wallet from an existing private key.

**Parameters:**
- `private_key_pem` (str): PEM-formatted private key string

**Returns:** Wallet - New Wallet instance with the imported key

**Example:**
```python
wallet = Wallet.from_private_key(private_key_pem)
```

---

#### `verify_signature(public_key_pem: str, signature: bytes, transaction: Dict) -> bool` (staticmethod)

Verify a transaction signature.

**Parameters:**
- `public_key_pem` (str): PEM-formatted public key string
- `signature` (bytes): Digital signature to verify
- `transaction` (dict): Original transaction data

**Returns:** bool - True if signature is valid

**Example:**
```python
is_valid = Wallet.verify_signature(public_key, signature, transaction)
```

---

## Transaction Class

Represents a transaction in the blockchain.

### Constructor

```python
Transaction(sender_public_key: str, recipient_address: str, value: float, signature: Optional[bytes] = None)
```

**Parameters:**
- `sender_public_key` (str): Sender's public key
- `recipient_address` (str): Recipient's address
- `value` (float): Transaction amount
- `signature` (Optional[bytes]): Transaction signature

**Example:**
```python
tx = Transaction(sender_wallet.address, recipient_address, 50)
```

### Methods

#### `to_dict() -> Dict[str, Any]`

Convert transaction to ordered dictionary.

**Returns:** OrderedDict - Transaction data

---

#### `sign(wallet: Wallet) -> None`

Sign the transaction with a wallet.

**Parameters:**
- `wallet` (Wallet): Wallet instance to sign with

**Raises:** ValueError if wallet doesn't match sender

**Example:**
```python
transaction.sign(sender_wallet)
```

---

#### `is_valid() -> bool`

Verify the transaction signature.

**Returns:** bool - True if signature is valid

---

#### `create_coinbase(recipient_address: str, reward: float) -> Dict` (staticmethod)

Create a coinbase (mining reward) transaction.

**Parameters:**
- `recipient_address` (str): Address to receive the reward
- `reward` (float): Reward amount

**Returns:** dict - Transaction dictionary

**Example:**
```python
coinbase = Transaction.create_coinbase(miner_address, 50)
```

---

#### `from_dict(data: Dict[str, Any]) -> Transaction` (classmethod)

Create a Transaction from a dictionary.

**Parameters:**
- `data` (dict): Dictionary containing transaction data

**Returns:** Transaction - New Transaction instance

---

## Utility Functions

### `compute_hash(data: Any) -> str`

Compute SHA-256 hash of data.

**Parameters:**
- `data` (Any): Data to hash (will be JSON serialized if not string)

**Returns:** str - Hexadecimal hash string

**Example:**
```python
from blockchain_core.utils import compute_hash

hash_value = compute_hash({'key': 'value'})
```

---

### `validate_address(address: str) -> bool`

Validate a blockchain address format.

**Parameters:**
- `address` (str): Address string to validate

**Returns:** bool - True if valid, False otherwise

**Example:**
```python
from blockchain_core.utils import validate_address

is_valid = validate_address(wallet_address)
```

---

### `serialize_transaction(transaction: Dict) -> str`

Serialize a transaction to a consistent format.

**Parameters:**
- `transaction` (dict): Transaction dictionary

**Returns:** str - JSON string representation

---

### `validate_transaction_structure(transaction: Dict) -> bool`

Validate the structure of a transaction.

**Parameters:**
- `transaction` (dict): Transaction dictionary to validate

**Returns:** bool - True if valid structure

---

### `setup_logging(level: str = 'INFO') -> logging.Logger`

Set up logging configuration.

**Parameters:**
- `level` (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

**Returns:** logging.Logger - Configured logger instance

**Example:**
```python
from blockchain_core.utils import setup_logging

logger = setup_logging('DEBUG')
```

---

## Configuration

Configuration constants are available in `config/config.py`:

```python
from config import DIFFICULTY, MINER_REWARD, INITIAL_BALANCE

# Mining settings
DIFFICULTY          # Default: 2
MINER_REWARD        # Default: 50
INITIAL_BALANCE     # Default: 150

# Cryptography
CURVE              # Default: 'SECP256K1'
HASH_ALGORITHM     # Default: 'SHA256'

# Network
DEFAULT_PORT       # Default: 5000
MAX_NODES         # Default: 100

# Logging
LOG_LEVEL         # Default: 'INFO'
LOG_FORMAT        # Default: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
```

---

## Error Handling

All methods include appropriate error handling. Common exceptions:

- `ValueError`: Invalid parameters or data
- `InvalidSignature`: Signature verification failed
- `Exception`: General errors with descriptive messages

**Example:**
```python
try:
    blockchain.add_transaction(sender, recipient, amount, signature)
except ValueError as e:
    print(f"Invalid transaction: {e}")
except Exception as e:
    print(f"Error: {e}")
```

---

## Type Hints

The codebase uses Python type hints for better code clarity:

```python
def add_transaction(
    self,
    sender_public_key: str,
    recipient_address: str,
    value: float,
    signature: bytes
) -> bool:
    ...
```

---

## Best Practices

1. **Always validate transactions** before adding them to the blockchain
2. **Keep private keys secure** - never expose them in logs or public interfaces
3. **Validate the chain** regularly to ensure integrity
4. **Use appropriate difficulty** for your use case
5. **Handle exceptions** properly in production code
6. **Test thoroughly** before deploying

---

For more examples, see the `examples/` directory in the repository.
