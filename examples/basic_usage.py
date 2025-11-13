"""
Basic usage example for the blockchain implementation.

This example demonstrates:
- Creating a blockchain
- Creating wallets
- Mining blocks
- Creating transactions
- Checking balances
"""

from blockchain_core import Blockchain, Wallet
from config import DIFFICULTY, MINER_REWARD


def main():
    print("=" * 60)
    print("Blockchain Basic Usage Example")
    print("=" * 60)

    # Step 1: Create a new blockchain
    print("\n1. Creating a new blockchain...")
    blockchain = Blockchain(difficulty=DIFFICULTY, miner_rewards=MINER_REWARD)
    print(f"   ✓ Blockchain created with {len(blockchain.chain)} block (genesis)")
    print(f"   ✓ Difficulty: {blockchain.difficulty}")
    print(f"   ✓ Miner reward: {blockchain.miner_rewards}")

    # Step 2: Create wallets
    print("\n2. Creating wallets...")
    alice_wallet = Wallet()
    bob_wallet = Wallet()
    miner_wallet = Wallet()
    print(f"   ✓ Alice's wallet: {alice_wallet.address[:50]}...")
    print(f"   ✓ Bob's wallet: {bob_wallet.address[:50]}...")
    print(f"   ✓ Miner's wallet: {miner_wallet.address[:50]}...")

    # Step 3: Check initial balances
    print("\n3. Checking initial balances...")
    alice_balance = blockchain.get_balance(alice_wallet.address)
    bob_balance = blockchain.get_balance(bob_wallet.address)
    miner_balance = blockchain.get_balance(miner_wallet.address)
    print(f"   Alice's balance: {alice_balance}")
    print(f"   Bob's balance: {bob_balance}")
    print(f"   Miner's balance: {miner_balance}")

    # Step 4: Mine a block
    print("\n4. Mining the first block...")
    print("   (This may take a few seconds...)")
    block_index = blockchain.mine(miner_wallet.address)
    print(f"   ✓ Block mined! Index: {block_index}")
    print(f"   ✓ Chain length: {blockchain.get_chain_length()}")

    # Step 5: Check miner's balance after mining
    print("\n5. Checking miner's balance after mining...")
    miner_balance = blockchain.get_balance(miner_wallet.address)
    print(f"   Miner's new balance: {miner_balance}")

    # Step 6: Create a transaction
    print("\n6. Creating a transaction: Alice sends 10 to Bob...")
    from collections import OrderedDict

    transaction = OrderedDict({
        'sender_public_key': alice_wallet.address,
        'recipient_address': bob_wallet.address,
        'value': 10
    })

    # Sign the transaction
    signature = alice_wallet.sign_transaction(transaction)

    # Add transaction to blockchain
    if blockchain.add_transaction(alice_wallet.address, bob_wallet.address, 10, signature):
        print("   ✓ Transaction added to pending transactions")
    else:
        print("   ✗ Transaction failed")

    # Step 7: Mine another block to confirm the transaction
    print("\n7. Mining a block to confirm the transaction...")
    block_index = blockchain.mine(miner_wallet.address)
    print(f"   ✓ Block mined! Index: {block_index}")

    # Step 8: Check final balances
    print("\n8. Checking final balances...")
    alice_balance = blockchain.get_balance(alice_wallet.address)
    bob_balance = blockchain.get_balance(bob_wallet.address)
    miner_balance = blockchain.get_balance(miner_wallet.address)
    print(f"   Alice's balance: {alice_balance}")
    print(f"   Bob's balance: {bob_balance}")
    print(f"   Miner's balance: {miner_balance}")

    # Step 9: Validate the blockchain
    print("\n9. Validating the blockchain...")
    if blockchain.is_valid_chain():
        print("   ✓ Blockchain is valid!")
    else:
        print("   ✗ Blockchain is invalid!")

    # Step 10: Display blockchain info
    print("\n10. Blockchain Summary:")
    print(f"    Total blocks: {blockchain.get_chain_length()}")
    print(f"    Pending transactions: {len(blockchain.transactions)}")
    print(f"    Difficulty: {blockchain.difficulty}")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
