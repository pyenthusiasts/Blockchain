# Quick Start Guide

Get up and running with the blockchain in 5 minutes!

## Installation

```bash
# Clone the repository
git clone https://github.com/pyenthusiasts/Blockchain.git
cd Blockchain

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Basic Usage

### 1. Simple Python Script

```python
from blockchain_core import Blockchain, Wallet

# Create blockchain
blockchain = Blockchain(difficulty=2, miner_rewards=50)

# Create wallets
alice = Wallet()
bob = Wallet()

# Mine a block
blockchain.mine(alice.address)
print(f"Alice's balance: {blockchain.get_balance(alice.address)}")

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

print(f"Alice's balance: {blockchain.get_balance(alice.address)}")
print(f"Bob's balance: {blockchain.get_balance(bob.address)}")
```

### 2. Using the CLI

```bash
# Create a wallet
blockchain create-wallet -o mywallet.json

# Mine a block (replace <address> with your wallet address)
blockchain mine <address>

# Check balance
blockchain balance <address>

# View blockchain
blockchain chain

# Get statistics
blockchain info
```

### 3. Using the REST API

```bash
# Start the API server
python -m api.blockchain_api

# In another terminal, test the API
curl http://localhost:5000/

# Create a wallet
curl -X POST http://localhost:5000/wallet/new

# Get blockchain stats
curl http://localhost:5000/stats
```

## Running Examples

```bash
# Basic usage
python examples/basic_usage.py

# Advanced features
python examples/advanced_features.py

# API client
# (Make sure API server is running first)
python examples/api_client_example.py
```

## Using Persistence

```python
from blockchain_core import (
    Blockchain,
    save_blockchain_to_db,
    load_blockchain_from_db
)

# Create and populate blockchain
blockchain = Blockchain()
# ... add blocks and transactions ...

# Save to database
save_blockchain_to_db(blockchain, 'my_blockchain.db')

# Load later
blockchain = load_blockchain_from_db('my_blockchain.db')
```

## Using Merkle Trees

```python
from blockchain_core import MerkleTree

# Create tree from transactions
transactions = [
    {'sender': 'Alice', 'recipient': 'Bob', 'value': 10},
    {'sender': 'Bob', 'recipient': 'Charlie', 'value': 20}
]

tree = MerkleTree(transactions)
root_hash = tree.get_root_hash()

# Generate and verify proofs
proof = tree.get_proof(transactions[0])
is_valid = tree.verify_proof(transactions[0], proof, root_hash)
print(f"Proof valid: {is_valid}")
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=blockchain_core

# Run specific tests
pytest tests/test_blockchain.py

# Run only fast tests
pytest -m "not slow"
```

## Using Make Commands

```bash
# See all available commands
make help

# Run tests
make test

# Run linters
make lint

# Format code
make format

# Run benchmarks
make benchmark

# Build Docker image
make docker-build

# Full CI pipeline
make ci
```

## Docker Usage

```bash
# Build image
docker build -t blockchain .

# Run container
docker run -it blockchain

# Using docker-compose
docker-compose up
```

## Development Setup

```bash
# Initialize development environment
make init

# Install pre-commit hooks
pre-commit install

# Run pre-commit checks
pre-commit run --all-files
```

## Next Steps

- Read the full [README.md](README.md)
- Check out [API Documentation](docs/API.md)
- Review [Contributing Guidelines](CONTRIBUTING.md)
- Explore [Examples](examples/)
- Run [Benchmarks](tests/benchmarks.py)

## Troubleshooting

### Import Errors

If you get import errors, make sure you've installed the package:
```bash
pip install -e .
```

### Cryptography Errors

Install/upgrade the cryptography library:
```bash
pip install --upgrade cryptography
```

### Test Failures

Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

## Quick Reference

| Task | Command |
|------|---------|
| Create wallet | `blockchain create-wallet` |
| Mine block | `blockchain mine <address>` |
| Check balance | `blockchain balance <address>` |
| View chain | `blockchain chain` |
| Run tests | `pytest` |
| Start API | `python -m api.blockchain_api` |
| Run example | `python examples/basic_usage.py` |
| Format code | `make format` |
| Run benchmarks | `make benchmark` |

## Support

- GitHub Issues: [Report bugs](https://github.com/pyenthusiasts/Blockchain/issues)
- Documentation: [Full docs](docs/)
- Examples: [Examples directory](examples/)

Happy blockchain building! 🚀
