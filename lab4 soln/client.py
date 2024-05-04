import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import socket
import time
import random

from blockchain import make_signature, make_transaction
from network import recv_prefixed, send_prefixed

class Client():
	def __init__(self):
		self.private_key = ed25519.Ed25519PrivateKey.generate()
		self.sender = self.private_key.public_key().public_bytes_raw().hex()

		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect(('localhost', 8000))

	def transaction(self, message):
		signature = make_signature(self.private_key, message)
		return make_transaction(self.sender, message, signature)

	def send(self, message):
		transaction = self.transaction(message)
		send_prefixed(self.s, transaction.encode())
		try:
			data = recv_prefixed(self.s).decode()
			print(data)
		except Exception as e:
			print(e)


messages = open("phrases.txt", 'r').read().splitlines()
time.sleep(random.random()*10)
c = Client()

for m in messages:
	time.sleep(random.random()*7)
	c.send(m)
