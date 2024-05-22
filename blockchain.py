from cryptography.exceptions import InvalidSignature
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from enum import Enum
import hashlib
import json
import re
from pprint import pprint

sender_valid = re.compile('^[a-fA-F0-9]{64}$')
signature_valid = re.compile('^[a-fA-F0-9]{128}$')

TransactionValidationError = Enum('TransactionValidationError', ['INVALID_JSON', 'INVALID_SENDER', 'INVALID_MESSAGE', 'INVALID_SIGNATURE'])

def make_transaction(sender, message, signature, nonce) -> str:
    #return {'sender': sender, 'message': message, 'signature': signature, 'nonce': nonce}
     return {'sender': sender, 'message': message, 'nonce': nonce, 'signature': signature}

def transaction_bytes(transaction: dict) -> bytes:
    return json.dumps({k: transaction.get(k) for k in ['sender', 'message', 'nonce']}, sort_keys=True).encode()

def make_signature(private_key: ed25519.Ed25519PrivateKey, message: str, nonce: int) -> str:
    transaction = {'sender': private_key.public_key().public_bytes_raw().hex(), 'message': message, 'nonce': nonce}
    return private_key.sign(transaction_bytes(transaction)).hex()


class Blockchain():
    def  __init__(self):
        self.blockchain = []
        self.pool = []
        self.new_block('0' * 64)
        self.nonces = {}

    def commit_block(self, block):
        self.pool = [tx for tx in self.pool if tx not in block['transactions']]
        self.blockchain.append(block)

    def block_proposal(self, previous_hash=None):
        print("creating new block proposal!")
        block = {
            'index': len(self.blockchain),
            'transactions': self.pool.copy(),
            'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
        }
        block['current_hash'] = self.calculate_hash(block)
        print("[PROPOSAL] Created a block proposal: {}".format(block))
        return block

    def new_block(self, previous_hash=None):
        if len(self.blockchain) == 0:
            block = {
            'index': 0,
            'transactions': self.pool.copy(),
            'previous_hash': "0000000000000000000000000000000000000000000000000000000000000000",
            'current_hash': "03525042c7132a2ec3db14b7aa1db816e61f1311199ae2a31f3ad1c4312047d1",
        }
        else:
            block = {
                'index': len(self.blockchain),
                'transactions': self.pool.copy(),
                'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
            }
            block['current_hash'] = self.calculate_hash(block)
        self.pool = []
        self.blockchain.append(block)
        
    def get(self, index):
        return self.blockchain[index]

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
            print("[MEM] Stored transaction in the transaction pool: {}".format(tx.get("signature")))
            return True
        #print(tx)
        return False

    def get_sender_nonce(self, sender_name) -> int:
        return len([b for b in self.blockchain if b.sender==sender_name])

    def validate_transaction(self, tx: dict) -> dict | TransactionValidationError:
        #print("trying to validate: ")
        #print(tx)
        # try:
        # 	tx = json.loads(transaction)
        # except json.JSONDecodeError:
        # 	return TransactionValidationError.INVALID_JSON # I dont want this error check to be here in future.
        # 	# we should check json validity upon message reception

        if not(tx.get('sender') and isinstance(tx['sender'], str) and sender_valid.search(tx['sender'])):
            # print("not(tx.get('sender') and isinstance(tx['sender'], str): ", not(tx.get('sender') and isinstance(tx['sender'], str)))
            # print("sender_valid.search(tx['sender']): ", sender_valid.search(tx['sender']))
            print("[TX] Received an invalid transaction, wrong sender - {}".format(tx))
            return TransactionValidationError.INVALID_SENDER

        if not(tx.get('message') and isinstance(tx['message'], str) and len(tx['message']) <= 70 and tx['message'].isalnum()):
            print("[TX] Received an invalid transaction, wrong message - {}".format(tx))
            return TransactionValidationError.INVALID_MESSAGE
        
        #if sender exists
        if (self.nonces.get(tx.get('sender')) != None):
            if not(tx.get('nonce') > self.nonces.get(tx.get('sender'))):
                print("[TX] Received an invalid transaction, wrong nonce - {}".format(tx))
                return TransactionValidationError

        try:
            if int(tx.get('nonce')) < 0:
                print("[TX] Received an invalid transaction, wrong nonce - {}".format(tx))
                return TransactionValidationError
        except ValueError:
            print("[TX] Received an invalid transaction, wrong nonce - {}".format(tx))
            return TransactionValidationError

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx['sender']))
        if not(tx.get('signature') and isinstance(tx['signature'], str) and signature_valid.search(tx['signature'])):
            print("[TX] Received an invalid transaction, wrong signature mssage - {}".format(tx))
            return TransactionValidationError.INVALID_SIGNATURE
        try:
            public_key.verify(bytes.fromhex(tx['signature']), transaction_bytes(tx))
        except InvalidSignature:
            print("[TX] Received an invalid transaction, wrong signature mssage - {}".format(tx))
            return TransactionValidationError.INVALID_SIGNATURE
        return tx
