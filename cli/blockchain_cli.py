#!/usr/bin/env python3
"""
Command-line interface for blockchain operations.
"""

import click
import json
import sys
from pathlib import Path
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

from blockchain_core import Blockchain, Wallet
from config import DIFFICULTY, MINER_REWARD


# Global blockchain instance
blockchain = Blockchain(difficulty=DIFFICULTY, miner_rewards=MINER_REWARD)


def print_success(message):
    """Print success message in green."""
    click.echo(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")


def print_error(message):
    """Print error message in red."""
    click.echo(f"{Fore.RED}✗ {message}{Style.RESET_ALL}", err=True)


def print_info(message):
    """Print info message in blue."""
    click.echo(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    Blockchain CLI - A simple blockchain management tool.

    Manage wallets, mine blocks, send transactions, and explore the blockchain.
    """
    pass


@cli.command()
@click.option('--output', '-o', type=click.Path(), help='Save wallet to file')
def create_wallet(output):
    """Create a new wallet with public/private key pair."""
    try:
        wallet = Wallet()

        print_success("Wallet created successfully!")
        click.echo(f"\n{Fore.CYAN}Address:{Style.RESET_ALL}")
        click.echo(wallet.address)

        if output:
            wallet_data = {
                'address': wallet.address,
                'private_key': wallet.export_private_key()
            }
            with open(output, 'w') as f:
                json.dump(wallet_data, f, indent=2)
            print_success(f"Wallet saved to {output}")
            print_error("⚠ WARNING: Keep your private key secure!")
        else:
            click.echo(f"\n{Fore.YELLOW}Private Key (Keep this secret!):{Style.RESET_ALL}")
            click.echo(wallet.export_private_key())

    except Exception as e:
        print_error(f"Failed to create wallet: {e}")
        sys.exit(1)


@cli.command()
@click.argument('wallet_file', type=click.Path(exists=True))
def load_wallet(wallet_file):
    """Load a wallet from file and display information."""
    try:
        with open(wallet_file, 'r') as f:
            wallet_data = json.load(f)

        wallet = Wallet.from_private_key(wallet_data['private_key'])
        balance = blockchain.get_balance(wallet.address)

        print_success("Wallet loaded successfully!")
        click.echo(f"\n{Fore.CYAN}Address:{Style.RESET_ALL}")
        click.echo(wallet.address)
        click.echo(f"\n{Fore.CYAN}Balance:{Style.RESET_ALL} {balance}")

    except Exception as e:
        print_error(f"Failed to load wallet: {e}")
        sys.exit(1)


@cli.command()
@click.argument('address')
def balance(address):
    """Check the balance of an address."""
    try:
        bal = blockchain.get_balance(address)
        click.echo(f"\n{Fore.CYAN}Balance for {address[:20]}...:{Style.RESET_ALL}")
        click.echo(f"{Fore.GREEN}{bal}{Style.RESET_ALL}")
    except Exception as e:
        print_error(f"Failed to get balance: {e}")
        sys.exit(1)


@cli.command()
@click.argument('miner_address')
@click.option('--difficulty', '-d', default=DIFFICULTY, help='Mining difficulty')
def mine(miner_address, difficulty):
    """Mine a new block."""
    try:
        blockchain.difficulty = difficulty

        print_info(f"Mining with difficulty {difficulty}...")
        click.echo("This may take a while...\n")

        block_index = blockchain.mine(miner_address)

        if block_index:
            print_success(f"Block mined successfully! Block index: {block_index}")
            new_balance = blockchain.get_balance(miner_address)
            click.echo(f"\n{Fore.CYAN}New balance:{Style.RESET_ALL} {new_balance}")
        else:
            print_error("Failed to mine block")
            sys.exit(1)

    except Exception as e:
        print_error(f"Mining failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument('sender_wallet_file', type=click.Path(exists=True))
@click.argument('recipient_address')
@click.argument('amount', type=float)
def send(sender_wallet_file, recipient_address, amount):
    """Send cryptocurrency to another address."""
    try:
        # Load sender wallet
        with open(sender_wallet_file, 'r') as f:
            wallet_data = json.load(f)

        sender_wallet = Wallet.from_private_key(wallet_data['private_key'])

        # Check balance
        balance = blockchain.get_balance(sender_wallet.address)
        if balance < amount:
            print_error(f"Insufficient balance. You have {balance}, trying to send {amount}")
            sys.exit(1)

        # Create and sign transaction
        from collections import OrderedDict
        transaction = OrderedDict({
            'sender_public_key': sender_wallet.address,
            'recipient_address': recipient_address,
            'value': amount
        })
        signature = sender_wallet.sign_transaction(transaction)

        # Add to blockchain
        if blockchain.add_transaction(sender_wallet.address, recipient_address, amount, signature):
            print_success(f"Transaction created: {amount} sent to {recipient_address[:20]}...")
            print_info("Transaction is pending. Mine a block to confirm it.")
        else:
            print_error("Transaction failed")
            sys.exit(1)

    except Exception as e:
        print_error(f"Transaction failed: {e}")
        sys.exit(1)


@cli.command()
def pending():
    """Show pending transactions."""
    try:
        if not blockchain.transactions:
            print_info("No pending transactions")
            return

        click.echo(f"\n{Fore.CYAN}Pending Transactions:{Style.RESET_ALL}\n")

        table_data = []
        for tx in blockchain.transactions:
            sender = tx.get('sender_public_key', '')[:20] + '...' if len(tx.get('sender_public_key', '')) > 20 else tx.get('sender_public_key', '')
            recipient = tx.get('recipient_address', '')[:20] + '...' if len(tx.get('recipient_address', '')) > 20 else tx.get('recipient_address', '')
            value = tx.get('value', 0)
            table_data.append([sender, recipient, value])

        headers = ['From', 'To', 'Amount']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))

    except Exception as e:
        print_error(f"Failed to show pending transactions: {e}")
        sys.exit(1)


@cli.command()
@click.option('--detail', '-d', is_flag=True, help='Show detailed information')
def chain(detail):
    """Display the blockchain."""
    try:
        click.echo(f"\n{Fore.CYAN}Blockchain Information:{Style.RESET_ALL}")
        click.echo(f"Length: {blockchain.get_chain_length()}")
        click.echo(f"Difficulty: {blockchain.difficulty}")
        click.echo(f"Valid: {'Yes' if blockchain.is_valid_chain() else 'No'}\n")

        if detail:
            for block in blockchain.chain:
                click.echo(f"{Fore.YELLOW}Block #{block.index}{Style.RESET_ALL}")
                click.echo(f"  Hash: {block.hash}")
                click.echo(f"  Previous Hash: {block.previous_hash}")
                click.echo(f"  Timestamp: {block.timestamp}")
                click.echo(f"  Transactions: {len(block.transactions)}")
                if block.transactions:
                    for tx in block.transactions:
                        click.echo(f"    - {tx.get('sender_public_key', '')[:20]}... → {tx.get('recipient_address', '')[:20]}...: {tx.get('value', 0)}")
                click.echo()
        else:
            table_data = []
            for block in blockchain.chain:
                table_data.append([
                    block.index,
                    block.hash[:16] + '...',
                    len(block.transactions),
                    f"{block.timestamp:.2f}"
                ])

            headers = ['Index', 'Hash', 'Transactions', 'Timestamp']
            click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))

    except Exception as e:
        print_error(f"Failed to display chain: {e}")
        sys.exit(1)


@cli.command()
def validate():
    """Validate the entire blockchain."""
    try:
        print_info("Validating blockchain...")

        if blockchain.is_valid_chain():
            print_success("Blockchain is valid!")
        else:
            print_error("Blockchain is invalid!")
            sys.exit(1)

    except Exception as e:
        print_error(f"Validation failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument('output_file', type=click.Path())
def export(output_file):
    """Export blockchain to JSON file."""
    try:
        blockchain_data = blockchain.to_dict()

        with open(output_file, 'w') as f:
            json.dump(blockchain_data, f, indent=2)

        print_success(f"Blockchain exported to {output_file}")

    except Exception as e:
        print_error(f"Export failed: {e}")
        sys.exit(1)


@cli.command()
def info():
    """Display blockchain statistics and information."""
    try:
        total_transactions = sum(len(block.transactions) for block in blockchain.chain)

        click.echo(f"\n{Fore.CYAN}Blockchain Statistics:{Style.RESET_ALL}\n")

        stats = [
            ['Blocks', blockchain.get_chain_length()],
            ['Total Transactions', total_transactions],
            ['Pending Transactions', len(blockchain.transactions)],
            ['Difficulty', blockchain.difficulty],
            ['Miner Reward', blockchain.miner_rewards],
            ['Network Nodes', len(blockchain.nodes)],
            ['Valid Chain', 'Yes' if blockchain.is_valid_chain() else 'No']
        ]

        click.echo(tabulate(stats, tablefmt='grid'))

    except Exception as e:
        print_error(f"Failed to get info: {e}")
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()
