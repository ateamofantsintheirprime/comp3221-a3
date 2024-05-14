from cryptography.exceptions import InvalidSignature
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from enum import Enum
import hashlib
import json
import re

sender_valid = re.compile('^[a-fA-F0-9]{64}$')
message_valid = re.compile('^[a-zA-z0-9]{0,70}$')
signature_valid = re.compile('^[a-fA-F0-9]{128}$')

TransactionValidationError = Enum('TransactionValidationError', ['INVALID_JSON', 'INVALID_SENDER', 'INVALID_MESSAGE', 'INVALID_SIGNATURE'])

def make_transaction(sender, message, signature, nonce) -> str:
    return json.dumps({'sender': sender, 'message': message, 'signature': signature, 'nonce': nonce})

def transaction_bytes(transaction: dict) -> bytes:
    return json.dumps({k: transaction.get(k) for k in ['sender', 'message', 'nonce']}, sort_keys=True).encode()

def make_signature(private_key: ed25519.Ed25519PrivateKey, message: str, nonce: int) -> str:
    transaction = {'sender': private_key.public_key().public_bytes_raw().hex(), 'message': message, 'nonce': nonce}
    return private_key.sign(transaction_bytes(transaction)).hex()


class Blockchain():
    def  __init__(self):
        self.blockchain = []
        self.pool = []
        gen_block = {"index": 0, 'transactions':[], "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000", "current_hash": "03525042c7132a2ec3db14b7aa1db816e61f1311199ae2a31f3ad1c4312047d1"}
        self.blockchain.append(gen_block)
        self.nonces = {}

    def get_length(self):
        return len(self.blockchain)

    def commit_block(self, block):
        self.pool = [tx for tx in self.pool if tx not in block['transactions']]
        self.blockchain.append(block)

    def block_proposal(self, previous_hash=None):
        block = {
            'index': len(self.blockchain) + 1,
            'transactions': self.pool.copy(),
            'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
        }
        block['current_hash'] = self.calculate_hash(block)
        return block

    def new_block(self, previous_hash=None):
        block = {
            'index': len(self.blockchain) + 1,
            'transactions': self.pool.copy(),
            'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
        }
        block['current_hash'] = self.calculate_hash(block)
        self.pool = []
        self.blockchain.append(block)

    def last_block(self):
        return self.blockchain[-1]

    def calculate_hash(self, block: dict) -> str:
        block_object: str = json.dumps({k: block.get(k) for k in ['index', 'transactions', 'previous_hash']}, sort_keys=True)
        block_string = block_object.encode()
        raw_hash = hashlib.sha256(block_string)
        hex_hash = raw_hash.hexdigest()
        return hex_hash

    def add_transaction(self, transaction: str) -> bool:
        if isinstance((tx := self.validate_transaction(transaction)), dict):
            sender = tx.get('sender')
            self.nonces[sender] = self.nonces.get(sender,0) + 1
            self.pool.append(tx)
            print("[MEM] Stored transaction in the transaction pool: {}".format(tx.get('payload,{}').get('signature')))
            return True
        print(tx)
        return False

    def get_sender_nonce(self, sender_name) -> int:
        return len([b for b in self.blockchain if b.sender==sender_name])

    #def validate_transaction(self, transaction: str) -> dict | TransactionValidationError:
    def validate_transaction(self, transaction: str) -> dict:
        try:
            tx = json.loads(transaction)
        except json.JSONDecodeError:
            return TransactionValidationError.INVALID_JSON

        if not(tx.get('payload',{}).get('sender') and isinstance(tx['payload']['sender'], str) and sender_valid.search(tx['payload']['sender'])):
            print("[TX] Received an invalid transaction, wrong sender - {}".format(tx))
            return TransactionValidationError.INVALID_SENDER

        if not (tx.get('payload', {}).get('message') and isinstance(tx['payload']['message'], str) and message_valid.search(tx['payload']['message'])):      
            print("[TX] Received an invalid transaction, wrong message - {}".format(tx))
            return TransactionValidationError.INVALID_MESSAGE
        
        if not(self.nonces.get(tx.get('payload',{}).get('sender')) == None):
            if not(tx.get('payload',{}).get('nonce') >= self.nonces.get(tx.get('payload',{}).get('sender'))):
                print("[TX] Received an invalid transaction, wrong nonce - {}".format(tx))
                
                return TransactionValidationError.INVALID_NONCE


        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx['payload']['sender']))
        
        if not (tx.get('signature') and isinstance(tx['signature'], str) and signature_valid.search(tx['signature'])):
            print("[TX] Received an invalid transaction, wrong signature message - {}".format(tx))
            return TransactionValidationError.INVALID_SIGNATURE

        try:
            public_key.verify(bytes.fromhex(tx['signature']), self.transaction_bytes(tx))
        except InvalidSignature:
            print("[TX] Received an invalid transaction, wrong signature message - {}".format(tx))
            return TransactionValidationError.INVALID_SIGNATURE

        return tx
