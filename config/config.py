"""
Configuration settings for the blockchain application.
"""

# Mining settings
DIFFICULTY = 2
MINER_REWARD = 50
INITIAL_BALANCE = 150

# Cryptography settings
CURVE = 'SECP256K1'
HASH_ALGORITHM = 'SHA256'

# Network settings
DEFAULT_PORT = 5000
MAX_NODES = 100

# Blockchain settings
GENESIS_TIMESTAMP = 0
GENESIS_PREVIOUS_HASH = "0"
GENESIS_INDEX = 0

# Logging
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
