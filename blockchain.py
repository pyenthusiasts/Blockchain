import hashlib
import json
from time import time
import binascii
from collections import OrderedDict
from uuid import uuid4
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class Blockchain:
    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.difficulty = 2
        self.miner_rewards = 50
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], time(), "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    def register_node(self, address):
        self.nodes.add(address)

    def verify_transaction_signature(self, sender_public_key, signature, transaction):
        public_key = serialization.load_pem_public_key(sender_public_key.encode())
        try:
            public_key.verify(signature, json.dumps(transaction, sort_keys=True).encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def add_transaction(self, sender_public_key, recipient_address, value, signature):
        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_address': recipient_address,
            'value': value
        })

        if self.verify_transaction_signature(sender_public_key, signature, transaction):
            self.transactions.append(transaction)
            return True
        return False

    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof, miner_address):
        previous_hash = self.last_block().hash
        if previous_hash != block.previous_hash:
            return False
        if not Blockchain.valid_proof(block.transactions, block.previous_hash, proof, self.difficulty):
            return False
        block.hash = proof
        self.chain.append(block)
        self.transactions = []
        self.transactions.append({
            'sender_public_key': 'network',
            'recipient_address': miner_address,
            'value': self.miner_rewards
        })
        return True

    @staticmethod
    def valid_proof(transactions, last_hash, proof, difficulty):
        transactions_serialized = json.dumps(transactions, sort_keys=True).encode()
        last_hash_bytes = str(last_hash).encode()
        proof_str = str(proof).encode()
        guess = (transactions_serialized + last_hash_bytes + proof_str)
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def proof_of_work(self):
        last_block = self.last_block()
        last_hash = last_block.hash
        proof = 0
        while not self.valid_proof(self.transactions, last_hash, proof, self.difficulty):
            proof += 1
        return proof

    def mine(self, miner_address):
        self.transactions.append({
            'sender_public_key': 'network',
            'recipient_address': miner_address,
            'value': self.miner_rewards
        })

        last_block = self.last_block()
        proof = self.proof_of_work()
        previous_hash = last_block.hash
        block = Block(index=last_block.index + 1, transactions=self.transactions, timestamp=time(),
                      previous_hash=previous_hash)
        if self.add_block(block, proof, miner_address):
            return block.index
        return None

    # Here you can modify the balance. An example here is 150.
    def get_balance(self, address):
        balance = 150
        for block in self.chain:
            for transaction in block.transactions:
                if 'recipient_address' in transaction and transaction['recipient_address'] == address:
                    balance += transaction['value']
                if 'sender_public_key' in transaction and transaction['sender_public_key'] == address:
                    balance -= transaction['value']
        return balance


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()


class Wallet:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
        self.address = self.serialize_public_key()

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def sign_transaction(self, transaction):
        signature = self.private_key.sign(
            json.dumps(transaction, sort_keys=True).encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature


def main():
    blockchain = Blockchain()
    wallet = Wallet()
    miner_wallet = Wallet()

    print("Mining started...")
    blockchain.mine(miner_wallet.address)
    print(f"Balance of miner: {blockchain.get_balance(miner_wallet.address)}")

    print("\nCreating a new transaction...")
    sender_balance = blockchain.get_balance(wallet.address)
    if sender_balance >= 1:
        transaction = OrderedDict({
            'sender_public_key': wallet.serialize_public_key(),
            'recipient_address': miner_wallet.address,
            'value': 1
        })

        signature = wallet.sign_transaction(transaction)
        blockchain.add_transaction(wallet.serialize_public_key(), miner_wallet.address, 1, signature)
        print("Transaction successful.")
    else:
        print("Transaction failed: Insufficient balance.")

    print("Mining a new block with the transaction...")
    blockchain.mine(miner_wallet.address)

    print(f"Balance of sender: {blockchain.get_balance(wallet.address)}")
    print(f"Balance of miner: {blockchain.get_balance(miner_wallet.address)}")


if __name__ == "__main__":
    main()

