"""
Advanced features example for the blockchain implementation.

This example demonstrates:
- Multiple transactions
- Transaction validation
- Wallet import/export
- Blockchain validation
- Chain exploration
"""

import json
from blockchain_core import Blockchain, Wallet, Transaction
from config import DIFFICULTY, MINER_REWARD


def print_section(title):
    """Print a section header."""
    print(f"\n{'=' * 60}")
    print(f"{title}")
    print('=' * 60)


def main():
    print_section("Blockchain Advanced Features Example")

    # Initialize blockchain
    blockchain = Blockchain(difficulty=2, miner_rewards=MINER_REWARD)

    # Create multiple wallets
    print("\n📝 Creating multiple wallets...")
    wallets = {
        'Alice': Wallet(),
        'Bob': Wallet(),
        'Charlie': Wallet(),
        'Miner': Wallet()
    }

    for name, wallet in wallets.items():
        print(f"   {name}: {wallet.address[:40]}...")

    # Demonstrate wallet export/import
    print_section("Wallet Export/Import")

    print("\n1. Exporting Alice's wallet...")
    alice_private_key = wallets['Alice'].export_private_key()
    print("   ✓ Private key exported (keep this secret!)")

    print("\n2. Importing wallet from private key...")
    imported_wallet = Wallet.from_private_key(alice_private_key)
    print(f"   ✓ Wallet imported successfully")
    print(f"   ✓ Addresses match: {wallets['Alice'].address == imported_wallet.address}")

    # Mine initial blocks
    print_section("Mining Initial Blocks")

    print("\nMining 3 blocks for the miner...")
    for i in range(3):
        print(f"   Mining block {i + 1}...", end=" ")
        blockchain.mine(wallets['Miner'].address)
        print("✓")

    print(f"\n✓ Chain length: {blockchain.get_chain_length()}")
    print(f"✓ Miner's balance: {blockchain.get_balance(wallets['Miner'].address)}")

    # Create multiple transactions
    print_section("Creating Multiple Transactions")

    transactions_to_create = [
        ('Miner', 'Alice', 30),
        ('Miner', 'Bob', 20),
        ('Miner', 'Charlie', 15),
    ]

    from collections import OrderedDict

    for sender_name, recipient_name, amount in transactions_to_create:
        sender_wallet = wallets[sender_name]
        recipient_wallet = wallets[recipient_name]

        transaction = OrderedDict({
            'sender_public_key': sender_wallet.address,
            'recipient_address': recipient_wallet.address,
            'value': amount
        })

        signature = sender_wallet.sign_transaction(transaction)

        if blockchain.add_transaction(
            sender_wallet.address,
            recipient_wallet.address,
            amount,
            signature
        ):
            print(f"   ✓ {sender_name} → {recipient_name}: {amount}")
        else:
            print(f"   ✗ Failed: {sender_name} → {recipient_name}: {amount}")

    print(f"\n✓ Pending transactions: {len(blockchain.transactions)}")

    # Mine to confirm transactions
    print("\nMining block to confirm transactions...")
    blockchain.mine(wallets['Miner'].address)
    print("✓ Block mined and transactions confirmed")

    # Display balances
    print_section("Account Balances")

    for name, wallet in wallets.items():
        balance = blockchain.get_balance(wallet.address)
        print(f"   {name:10s}: {balance:8.2f}")

    # Demonstrate failed transaction (insufficient balance)
    print_section("Transaction Validation")

    print("\n1. Attempting transaction with insufficient balance...")
    transaction = OrderedDict({
        'sender_public_key': wallets['Charlie'].address,
        'recipient_address': wallets['Bob'].address,
        'value': 1000  # More than Charlie has
    })

    signature = wallets['Charlie'].sign_transaction(transaction)

    if blockchain.add_transaction(
        wallets['Charlie'].address,
        wallets['Bob'].address,
        1000,
        signature
    ):
        print("   ✗ Transaction should have failed!")
    else:
        print("   ✓ Transaction correctly rejected (insufficient balance)")

    # Demonstrate invalid signature
    print("\n2. Attempting transaction with invalid signature...")
    transaction = OrderedDict({
        'sender_public_key': wallets['Alice'].address,
        'recipient_address': wallets['Bob'].address,
        'value': 5
    })

    # Sign with wrong wallet
    wrong_signature = wallets['Charlie'].sign_transaction(transaction)

    if blockchain.add_transaction(
        wallets['Alice'].address,
        wallets['Bob'].address,
        5,
        wrong_signature
    ):
        print("   ✗ Transaction should have failed!")
    else:
        print("   ✓ Transaction correctly rejected (invalid signature)")

    # Create a valid transaction
    print("\n3. Creating a valid transaction...")
    transaction = OrderedDict({
        'sender_public_key': wallets['Alice'].address,
        'recipient_address': wallets['Bob'].address,
        'value': 5
    })

    signature = wallets['Alice'].sign_transaction(transaction)

    if blockchain.add_transaction(
        wallets['Alice'].address,
        wallets['Bob'].address,
        5,
        signature
    ):
        print("   ✓ Valid transaction accepted")
        blockchain.mine(wallets['Miner'].address)
        print("   ✓ Transaction mined and confirmed")

    # Blockchain validation
    print_section("Blockchain Validation")

    print("\nValidating the entire blockchain...")
    if blockchain.is_valid_chain():
        print("✓ Blockchain is valid!")
    else:
        print("✗ Blockchain is invalid!")

    # Chain exploration
    print_section("Chain Exploration")

    print(f"\nTotal blocks: {blockchain.get_chain_length()}")
    print(f"Total transactions across all blocks: {sum(len(block.transactions) for block in blockchain.chain)}")

    print("\nBlock details:")
    for block in blockchain.chain:
        print(f"\n   Block #{block.index}")
        print(f"   Hash: {block.hash[:32]}...")
        print(f"   Transactions: {len(block.transactions)}")
        print(f"   Timestamp: {block.timestamp:.2f}")

    # Export blockchain
    print_section("Blockchain Export")

    print("\nExporting blockchain to dictionary...")
    blockchain_dict = blockchain.to_dict()
    print(f"✓ Exported {len(blockchain_dict['chain'])} blocks")
    print(f"✓ Pending transactions: {len(blockchain_dict['pending_transactions'])}")

    print("\nSaving blockchain to file...")
    with open('blockchain_export.json', 'w') as f:
        json.dump(blockchain_dict, f, indent=2)
    print("✓ Blockchain saved to blockchain_export.json")

    # Final summary
    print_section("Final Summary")

    print("\nBlockchain Statistics:")
    print(f"   Blocks mined: {blockchain.get_chain_length()}")
    print(f"   Difficulty: {blockchain.difficulty}")
    print(f"   Miner reward: {blockchain.miner_rewards}")
    print(f"   Network nodes: {len(blockchain.nodes)}")
    print(f"   Blockchain valid: {blockchain.is_valid_chain()}")

    print("\n" + "=" * 60)
    print("Advanced example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
