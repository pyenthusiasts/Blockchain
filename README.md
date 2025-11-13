# 🔗 Blockchain - A Comprehensive Python Implementation

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

A complete, feature-rich blockchain implementation in Python with cryptographic security, proof-of-work consensus, and a user-friendly CLI interface.

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [Python API](#python-api)
  - [Command Line Interface](#command-line-interface)
- [Components](#-components)
- [Testing](#-testing)
- [Examples](#-examples)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- **🔐 Cryptographic Security**: ECDSA key pairs with SECP256K1 curve
- **⛏️ Proof of Work**: Configurable difficulty mining algorithm
- **💰 Digital Wallets**: Secure wallet management with public/private key pairs
- **📝 Transaction Signing**: Digital signatures for transaction verification
- **🔍 Chain Validation**: Complete blockchain integrity validation
- **🌐 Network Nodes**: Support for distributed node registration
- **💻 CLI Interface**: User-friendly command-line tools
- **🧪 Comprehensive Tests**: Full test coverage with pytest
- **📊 Detailed Logging**: Built-in logging for debugging and monitoring
- **🐳 Docker Support**: Containerized deployment ready

## 🏗️ Architecture

The blockchain is organized into modular components:

```
Blockchain/
├── blockchain_core/       # Core blockchain implementation
│   ├── blockchain.py      # Main blockchain class
│   ├── block.py          # Block structure and validation
│   ├── wallet.py         # Wallet and cryptographic functions
│   ├── transaction.py    # Transaction handling
│   └── utils.py          # Utility functions
├── cli/                  # Command-line interface
├── config/               # Configuration settings
├── tests/                # Unit and integration tests
├── examples/             # Usage examples
└── docs/                 # Documentation

```

### Main Components

#### Blockchain Class

Manages the chain of blocks and transactions, including:
- Block creation and validation
- Transaction pool management
- Proof of work consensus
- Balance calculation
- Chain validation

#### Block Class

Represents each block in the blockchain with:
- Index and timestamp
- List of transactions
- Previous block hash
- Nonce for proof of work
- Computed hash

#### Wallet Class

Handles wallet functionalities:
- Generate private/public key pairs (ECDSA SECP256K1)
- Serialize and export keys
- Sign transactions
- Verify signatures

#### Transaction Class

Manages transaction operations:
- Transaction creation and validation
- Digital signature verification
- Structured transaction data

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/pyenthusiasts/Blockchain.git
cd Blockchain

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Docker Installation

```bash
# Build the Docker image
docker build -t blockchain .

# Run the container
docker run -it blockchain
```

## 🚀 Quick Start

### Basic Example

```python
from blockchain_core import Blockchain, Wallet

# Create a blockchain
blockchain = Blockchain(difficulty=2, miner_rewards=50)

# Create wallets
alice = Wallet()
bob = Wallet()

# Mine a block
blockchain.mine(alice.address)

# Create a transaction
from collections import OrderedDict

transaction = OrderedDict({
    'sender_public_key': alice.address,
    'recipient_address': bob.address,
    'value': 10
})

signature = alice.sign_transaction(transaction)
blockchain.add_transaction(alice.address, bob.address, 10, signature)

# Mine to confirm
blockchain.mine(alice.address)

# Check balances
print(f"Alice's balance: {blockchain.get_balance(alice.address)}")
print(f"Bob's balance: {blockchain.get_balance(bob.address)}")
```

## 💡 Usage

### Python API

#### Creating a Blockchain

```python
from blockchain_core import Blockchain

# Create with default settings
blockchain = Blockchain()

# Create with custom settings
blockchain = Blockchain(difficulty=4, miner_rewards=25)
```

#### Creating and Managing Wallets

```python
from blockchain_core import Wallet

# Create a new wallet
wallet = Wallet()

# Export private key
private_key = wallet.export_private_key()

# Import wallet from private key
imported_wallet = Wallet.from_private_key(private_key)

# Sign a transaction
signature = wallet.sign_transaction(transaction_data)
```

#### Creating Transactions

```python
from collections import OrderedDict

# Create transaction data
transaction = OrderedDict({
    'sender_public_key': sender_wallet.address,
    'recipient_address': recipient_wallet.address,
    'value': 50
})

# Sign the transaction
signature = sender_wallet.sign_transaction(transaction)

# Add to blockchain
blockchain.add_transaction(
    sender_wallet.address,
    recipient_wallet.address,
    50,
    signature
)
```

#### Mining Blocks

```python
# Mine a new block
block_index = blockchain.mine(miner_wallet.address)

if block_index:
    print(f"Block {block_index} mined successfully!")
```

#### Checking Balances

```python
balance = blockchain.get_balance(wallet.address)
print(f"Balance: {balance}")
```

#### Validating the Chain

```python
if blockchain.is_valid_chain():
    print("Blockchain is valid!")
else:
    print("Blockchain has been compromised!")
```

### Command Line Interface

The blockchain includes a comprehensive CLI for all operations.

#### Create a Wallet

```bash
# Create and display wallet
blockchain create-wallet

# Save wallet to file
blockchain create-wallet -o mywallet.json
```

#### Check Balance

```bash
blockchain balance <address>
```

#### Mine Blocks

```bash
# Mine with default difficulty
blockchain mine <miner_address>

# Mine with custom difficulty
blockchain mine <miner_address> -d 4
```

#### Send Transactions

```bash
blockchain send <sender_wallet_file> <recipient_address> <amount>
```

#### View Blockchain

```bash
# View summary
blockchain chain

# View detailed information
blockchain chain --detail
```

#### View Pending Transactions

```bash
blockchain pending
```

#### Validate Blockchain

```bash
blockchain validate
```

#### Export Blockchain

```bash
blockchain export blockchain_data.json
```

#### Show Statistics

```bash
blockchain info
```

## 🧩 Components

### Blockchain (`blockchain_core/blockchain.py`)

Main blockchain implementation with:
- Genesis block creation
- Transaction management
- Proof of work algorithm
- Block addition and validation
- Balance calculation
- Network node management

### Block (`blockchain_core/block.py`)

Block structure with:
- Index, timestamp, transactions
- Previous hash linkage
- Nonce for mining
- Hash computation
- Validation methods

### Wallet (`blockchain_core/wallet.py`)

Cryptographic wallet with:
- ECDSA key generation (SECP256K1)
- Key serialization and export
- Transaction signing
- Signature verification

### Transaction (`blockchain_core/transaction.py`)

Transaction handling with:
- Structured transaction format
- Digital signatures
- Validation methods
- Coinbase transactions

### Utils (`blockchain_core/utils.py`)

Utility functions:
- Hash computation
- Address validation
- Transaction serialization
- Logging setup

## 🧪 Testing

The project includes comprehensive unit tests with pytest.

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=blockchain_core

# Run specific test file
pytest tests/test_blockchain.py

# Run with verbose output
pytest -v
```

### Test Coverage

- ✅ Block creation and validation
- ✅ Wallet generation and signing
- ✅ Transaction creation and validation
- ✅ Blockchain operations
- ✅ Proof of work
- ✅ Chain validation
- ✅ Balance calculations
- ✅ Utility functions

## 📚 Examples

### Basic Usage

See `examples/basic_usage.py` for a complete basic example covering:
- Blockchain creation
- Wallet management
- Mining
- Transactions
- Balance checking

Run it:
```bash
python examples/basic_usage.py
```

### Advanced Features

See `examples/advanced_features.py` for advanced usage:
- Multiple transactions
- Wallet import/export
- Transaction validation
- Failed transaction handling
- Chain exploration
- Blockchain export

Run it:
```bash
python examples/advanced_features.py
```

## ⚙️ Configuration

Configuration is managed in `config/config.py`:

```python
# Mining settings
DIFFICULTY = 2              # Number of leading zeros required
MINER_REWARD = 50          # Reward for mining a block
INITIAL_BALANCE = 150      # Initial wallet balance

# Cryptography
CURVE = 'SECP256K1'        # Elliptic curve for ECDSA
HASH_ALGORITHM = 'SHA256'  # Hash algorithm

# Network
DEFAULT_PORT = 5000        # Default network port
MAX_NODES = 100           # Maximum network nodes

# Logging
LOG_LEVEL = 'INFO'        # Logging level
```

## 🐳 Docker Support

### Build and Run

```bash
# Build image
docker build -t blockchain .

# Run container
docker run -it blockchain

# Run with volume mount
docker run -it -v $(pwd)/data:/app/data blockchain
```

### Docker Compose

```bash
# Start services
docker-compose up

# Stop services
docker-compose down
```

## 📊 API Documentation

For detailed API documentation, see `docs/API.md`.

## 🔒 Security Considerations

- **Private Keys**: Always keep private keys secure and never share them
- **Initial Balance**: The default initial balance is for demonstration purposes
- **Network Security**: In production, implement proper network security
- **Consensus**: The proof-of-work difficulty should be adjusted based on network needs

## 🛣️ Roadmap

- [ ] REST API implementation
- [ ] Consensus algorithm improvements (PoS)
- [ ] Smart contract support
- [ ] Web interface
- [ ] Merkle tree implementation
- [ ] Enhanced networking capabilities
- [ ] Database persistence

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest

# Run linting
flake8 blockchain_core tests

# Format code
black blockchain_core tests
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

**Python Enthusiasts** - [GitHub](https://github.com/pyenthusiasts)

## 🙏 Acknowledgments

- Inspired by Bitcoin and Ethereum implementations
- Built with Python's cryptography library
- Thanks to all contributors

## 📮 Contact

For questions, issues, or suggestions:
- Open an issue on GitHub
- Email: [Contact through GitHub]

---

**⭐ If you find this project useful, please consider giving it a star!**
