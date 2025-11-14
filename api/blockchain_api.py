"""
REST API for the blockchain application.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import logging
from typing import Dict, Any
from collections import OrderedDict

from blockchain_core import Blockchain, Wallet
from config import DIFFICULTY, MINER_REWARD

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global blockchain instance
blockchain = Blockchain(difficulty=DIFFICULTY, miner_rewards=MINER_REWARD)

# Store node identifier
from uuid import uuid4
node_identifier = str(uuid4()).replace('-', '')


@app.route('/', methods=['GET'])
def index():
    """API root endpoint."""
    return jsonify({
        'name': 'Blockchain API',
        'version': '1.0.0',
        'endpoints': {
            'GET /': 'API information',
            'GET /chain': 'Get the full blockchain',
            'GET /chain/validate': 'Validate the blockchain',
            'GET /chain/length': 'Get blockchain length',
            'POST /mine': 'Mine a new block',
            'GET /transactions/pending': 'Get pending transactions',
            'POST /transactions/new': 'Create a new transaction',
            'GET /balance/<address>': 'Get balance for an address',
            'POST /nodes/register': 'Register a new node',
            'GET /nodes': 'Get registered nodes',
            'POST /wallet/new': 'Create a new wallet',
            'GET /stats': 'Get blockchain statistics'
        }
    }), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    """Get the full blockchain."""
    response = blockchain.to_dict()
    return jsonify(response), 200


@app.route('/chain/validate', methods=['GET'])
def validate_chain():
    """Validate the blockchain."""
    is_valid = blockchain.is_valid_chain()
    return jsonify({
        'valid': is_valid,
        'message': 'Blockchain is valid' if is_valid else 'Blockchain is invalid'
    }), 200


@app.route('/chain/length', methods=['GET'])
def chain_length():
    """Get the length of the blockchain."""
    return jsonify({
        'length': blockchain.get_chain_length()
    }), 200


@app.route('/mine', methods=['POST'])
def mine():
    """Mine a new block."""
    data = request.get_json()

    if not data or 'miner_address' not in data:
        return jsonify({
            'error': 'Missing miner_address in request'
        }), 400

    miner_address = data['miner_address']

    logger.info(f"Mining new block for {miner_address[:20]}...")
    block_index = blockchain.mine(miner_address)

    if block_index:
        return jsonify({
            'message': 'Block mined successfully',
            'block_index': block_index,
            'block': blockchain.chain[block_index].to_dict()
        }), 201
    else:
        return jsonify({
            'error': 'Mining failed'
        }), 500


@app.route('/transactions/pending', methods=['GET'])
def get_pending_transactions():
    """Get all pending transactions."""
    return jsonify({
        'transactions': blockchain.transactions,
        'count': len(blockchain.transactions)
    }), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """Create a new transaction."""
    data = request.get_json()

    required_fields = ['sender_public_key', 'recipient_address', 'value', 'signature']
    if not all(field in data for field in required_fields):
        return jsonify({
            'error': f'Missing required fields. Required: {required_fields}'
        }), 400

    # Convert signature from hex string to bytes if needed
    signature = data['signature']
    if isinstance(signature, str):
        signature = bytes.fromhex(signature)

    success = blockchain.add_transaction(
        data['sender_public_key'],
        data['recipient_address'],
        data['value'],
        signature
    )

    if success:
        return jsonify({
            'message': 'Transaction added successfully',
            'transaction': {
                'sender': data['sender_public_key'][:20] + '...',
                'recipient': data['recipient_address'][:20] + '...',
                'value': data['value']
            }
        }), 201
    else:
        return jsonify({
            'error': 'Transaction validation failed'
        }), 400


@app.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    """Get the balance for an address."""
    balance = blockchain.get_balance(address)
    return jsonify({
        'address': address[:20] + '...' if len(address) > 20 else address,
        'balance': balance
    }), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    """Register new network nodes."""
    data = request.get_json()

    if not data or 'nodes' not in data:
        return jsonify({
            'error': 'Missing nodes list in request'
        }), 400

    nodes = data['nodes']
    if not isinstance(nodes, list):
        return jsonify({
            'error': 'nodes must be a list'
        }), 400

    added = []
    for node in nodes:
        if blockchain.register_node(node):
            added.append(node)

    return jsonify({
        'message': f'{len(added)} node(s) registered',
        'total_nodes': len(blockchain.nodes),
        'nodes': list(blockchain.nodes)
    }), 201


@app.route('/nodes', methods=['GET'])
def get_nodes():
    """Get all registered nodes."""
    return jsonify({
        'nodes': list(blockchain.nodes),
        'count': len(blockchain.nodes)
    }), 200


@app.route('/wallet/new', methods=['POST'])
def create_wallet():
    """Create a new wallet."""
    wallet = Wallet()

    return jsonify({
        'message': 'Wallet created successfully',
        'address': wallet.address,
        'private_key': wallet.export_private_key(),
        'warning': 'Keep your private key secure and never share it!'
    }), 201


@app.route('/stats', methods=['GET'])
def get_stats():
    """Get blockchain statistics."""
    total_transactions = sum(len(block.transactions) for block in blockchain.chain)

    return jsonify({
        'blocks': blockchain.get_chain_length(),
        'total_transactions': total_transactions,
        'pending_transactions': len(blockchain.transactions),
        'difficulty': blockchain.difficulty,
        'miner_reward': blockchain.miner_rewards,
        'network_nodes': len(blockchain.nodes),
        'valid': blockchain.is_valid_chain(),
        'node_identifier': node_identifier
    }), 200


@app.route('/block/<int:index>', methods=['GET'])
def get_block(index):
    """Get a specific block by index."""
    if index < 0 or index >= len(blockchain.chain):
        return jsonify({
            'error': f'Block index {index} not found'
        }), 404

    block = blockchain.chain[index]
    return jsonify(block.to_dict()), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'error': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal error: {error}")
    return jsonify({
        'error': 'Internal server error'
    }), 500


def run_server(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask server."""
    logger.info(f"Starting Blockchain API server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run_server(port=port, debug=True)
