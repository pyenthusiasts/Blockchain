"""
Example of using the Blockchain REST API client.

This example demonstrates how to interact with the blockchain through the REST API.
"""

import requests
import json
from collections import OrderedDict
import time

# API base URL
BASE_URL = "http://localhost:5000"


def print_section(title):
    """Print a section header."""
    print(f"\n{'=' * 60}")
    print(f"{title}")
    print('=' * 60)


def print_response(response):
    """Pretty print API response."""
    try:
        data = response.json()
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(data, indent=2)}")
    except:
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")


def main():
    print_section("Blockchain REST API Client Example")

    # Check if API is running
    print("\n1. Checking API status...")
    try:
        response = requests.get(f"{BASE_URL}/")
        print_response(response)
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to API server")
        print("Please start the API server with: python -m api.blockchain_api")
        return

    # Get blockchain info
    print_section("2. Get Blockchain Information")
    response = requests.get(f"{BASE_URL}/chain")
    print_response(response)

    # Create a new wallet
    print_section("3. Create New Wallet")
    response = requests.post(f"{BASE_URL}/wallet/new")
    print_response(response)

    wallet_data = response.json()
    wallet_address = wallet_data['address']
    print(f"\n✓ Wallet created: {wallet_address[:50]}...")

    # Check balance
    print_section("4. Check Wallet Balance")
    response = requests.get(f"{BASE_URL}/balance/{wallet_address}")
    print_response(response)

    # Mine a block
    print_section("5. Mine a Block")
    print("Mining... This may take a few seconds...")

    response = requests.post(
        f"{BASE_URL}/mine",
        json={'miner_address': wallet_address}
    )
    print_response(response)

    if response.status_code == 201:
        print("✓ Block mined successfully!")

    # Check updated balance
    print_section("6. Check Updated Balance")
    response = requests.get(f"{BASE_URL}/balance/{wallet_address}")
    print_response(response)

    # Get chain length
    print_section("7. Get Chain Length")
    response = requests.get(f"{BASE_URL}/chain/length")
    print_response(response)

    # Get pending transactions
    print_section("8. Get Pending Transactions")
    response = requests.get(f"{BASE_URL}/transactions/pending")
    print_response(response)

    # Validate blockchain
    print_section("9. Validate Blockchain")
    response = requests.get(f"{BASE_URL}/chain/validate")
    print_response(response)

    # Get statistics
    print_section("10. Get Blockchain Statistics")
    response = requests.get(f"{BASE_URL}/stats")
    print_response(response)

    # Register nodes
    print_section("11. Register Network Nodes")
    response = requests.post(
        f"{BASE_URL}/nodes/register",
        json={
            'nodes': [
                'http://192.168.1.1:5000',
                'http://192.168.1.2:5000'
            ]
        }
    )
    print_response(response)

    # Get registered nodes
    print_section("12. Get Registered Nodes")
    response = requests.get(f"{BASE_URL}/nodes")
    print_response(response)

    # Get specific block
    print_section("13. Get Specific Block")
    response = requests.get(f"{BASE_URL}/block/0")  # Genesis block
    print_response(response)

    print_section("Example Complete!")
    print("\n✓ Successfully demonstrated all API endpoints")
    print("\nAPI Endpoints Summary:")
    print("  GET  /                        - API information")
    print("  GET  /chain                   - Full blockchain")
    print("  GET  /chain/validate          - Validate chain")
    print("  GET  /chain/length            - Chain length")
    print("  POST /mine                    - Mine new block")
    print("  GET  /transactions/pending    - Pending transactions")
    print("  POST /transactions/new        - Create transaction")
    print("  GET  /balance/<address>       - Check balance")
    print("  POST /nodes/register          - Register nodes")
    print("  GET  /nodes                   - Get nodes")
    print("  POST /wallet/new              - Create wallet")
    print("  GET  /stats                   - Statistics")
    print("  GET  /block/<index>           - Get block")


class BlockchainAPIClient:
    """
    A simple client class for interacting with the Blockchain API.
    """

    def __init__(self, base_url="http://localhost:5000"):
        """
        Initialize the API client.

        Args:
            base_url: Base URL of the API server
        """
        self.base_url = base_url

    def get_chain(self):
        """Get the full blockchain."""
        response = requests.get(f"{self.base_url}/chain")
        return response.json()

    def get_chain_length(self):
        """Get the blockchain length."""
        response = requests.get(f"{self.base_url}/chain/length")
        return response.json()['length']

    def validate_chain(self):
        """Validate the blockchain."""
        response = requests.get(f"{self.base_url}/chain/validate")
        return response.json()['valid']

    def mine_block(self, miner_address):
        """
        Mine a new block.

        Args:
            miner_address: Address to receive mining reward

        Returns:
            Block index or None
        """
        response = requests.post(
            f"{self.base_url}/mine",
            json={'miner_address': miner_address}
        )
        if response.status_code == 201:
            return response.json()['block_index']
        return None

    def get_balance(self, address):
        """
        Get balance for an address.

        Args:
            address: Wallet address

        Returns:
            Balance amount
        """
        response = requests.get(f"{self.base_url}/balance/{address}")
        return response.json()['balance']

    def create_wallet(self):
        """
        Create a new wallet.

        Returns:
            Wallet data dictionary
        """
        response = requests.post(f"{self.base_url}/wallet/new")
        return response.json()

    def get_pending_transactions(self):
        """Get pending transactions."""
        response = requests.get(f"{self.base_url}/transactions/pending")
        return response.json()['transactions']

    def get_stats(self):
        """Get blockchain statistics."""
        response = requests.get(f"{self.base_url}/stats")
        return response.json()

    def register_nodes(self, nodes):
        """
        Register network nodes.

        Args:
            nodes: List of node URLs

        Returns:
            Response data
        """
        response = requests.post(
            f"{self.base_url}/nodes/register",
            json={'nodes': nodes}
        )
        return response.json()

    def get_block(self, index):
        """
        Get a specific block.

        Args:
            index: Block index

        Returns:
            Block data
        """
        response = requests.get(f"{self.base_url}/block/{index}")
        return response.json()


def demo_client_class():
    """Demonstrate the API client class."""
    print_section("Using BlockchainAPIClient Class")

    client = BlockchainAPIClient()

    try:
        print("\n1. Creating wallet...")
        wallet = client.create_wallet()
        address = wallet['address']
        print(f"   ✓ Wallet created: {address[:50]}...")

        print("\n2. Mining block...")
        block_index = client.mine_block(address)
        print(f"   ✓ Block {block_index} mined")

        print("\n3. Checking balance...")
        balance = client.get_balance(address)
        print(f"   ✓ Balance: {balance}")

        print("\n4. Getting chain length...")
        length = client.get_chain_length()
        print(f"   ✓ Chain length: {length}")

        print("\n5. Validating chain...")
        is_valid = client.validate_chain()
        print(f"   ✓ Chain valid: {is_valid}")

        print("\n6. Getting statistics...")
        stats = client.get_stats()
        print(f"   ✓ Blocks: {stats['blocks']}")
        print(f"   ✓ Transactions: {stats['total_transactions']}")

        print("\n✓ Client class demo complete!")

    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to API server")
        print("Please start the API server with: python -m api.blockchain_api")


if __name__ == "__main__":
    # Run the main example
    main()

    # Also demonstrate the client class
    demo_client_class()
