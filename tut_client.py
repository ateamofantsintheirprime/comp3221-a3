import warnings
with warnings.catch_warnings():
	warnings.simplefilter("ignore")
	import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519

from argparse import Action, ArgumentParser
from functools import partial
import json
import socket
import struct


class ExtendAction(Action):
	def __call__(self, parser, namespace, values, option_string=None):
		items = getattr(namespace, self.dest) or []
		items.extend(values)
		setattr(namespace, self.dest, items)

def recv_exact(sock: socket.socket, msglen):
	chunks = []
	bytes_recd = 0
	while bytes_recd < msglen:
		chunk = sock.recv(min(msglen - bytes_recd, 2048))
		if chunk == b'':
			raise RuntimeError("socket connection broken")
		chunks.append(chunk)
		bytes_recd = bytes_recd + len(chunk)
	return b''.join(chunks)

def send_exact(sock: socket.socket, msg: bytes):
	totalsent = 0
	while totalsent < len(msg):
		sent = sock.send(msg[totalsent:])
		if sent == 0:
			raise RuntimeError("socket connection broken")
		totalsent = totalsent + sent

def recv_prefixed(sock: socket.socket):
	size_bytes = recv_exact(sock, 2)
	size = struct.unpack("!H", size_bytes)[0]
	if size == 0:
		raise RuntimeError("empty message")
	if size > 65535 - 2:
		raise RuntimeError("message too large")
	return recv_exact(sock, size)

def send_prefixed(sock: socket.socket, msg: bytes):
	size = len(msg)
	if size == 0:
		raise RuntimeError("empty message")
	if size > 65535 - 2:
		raise RuntimeError("message too large")
	size_bytes = struct.pack("!H", size)
	send_exact(sock, size_bytes + msg)

def make_transaction(sender, message, signature, nonce) -> str:
	payload = {k: v for k, v in {'sender': sender, 'message': message, 'signature': signature, 'nonce': nonce}.items() if v is not None}
	return json.dumps({'type': 'transaction', 'payload': payload})

def transaction_bytes(transaction: dict) -> bytes:
	return json.dumps(transaction, sort_keys=True).encode()

def make_signature(private_key: ed25519.Ed25519PrivateKey, sender: str, message: str, nonce: int) -> str:
	transaction = {k: v for k, v in {'sender': sender, 'message': message, 'nonce': nonce}.items() if v is not None}
	return private_key.sign(transaction_bytes(transaction)).hex()

def generate_transaction(private_key=None, message=None, nonce=None, sender=None, signature=None,
						 message_type=str, nonce_type=int, sender_type=str, signature_type=str,
						 set_sender=True, set_signature=True):
	if message is not None:
		message = message_type(message)
	if nonce is not None:
		nonce = nonce_type(nonce)
	if sender is not None:
		sender = sender_type(sender)
	if signature is not None:
		signature = signature_type(signature)

	if private_key is not None:
		private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
	else:
		private_key = ed25519.Ed25519PrivateKey.generate()
	print(f'using private key {private_key.private_bytes_raw().hex()}')

	if sender is None and set_sender:
		sender = private_key.public_key().public_bytes_raw().hex()

	if signature is None and set_signature:
		signature = make_signature(private_key, sender, message, nonce)

	return make_transaction(sender, message, signature, nonce)

parser = ArgumentParser()
parser.register('action', 'extend', ExtendAction)
parser.add_argument('--port', type=int, nargs='+', action='extend', required=True)
parser.add_argument('--test', type=int, choices=range(1,6), required=True)

args = parser.parse_args()
nodes: 'list[tuple[str, int]]' = []
for port in args.port:
	nodes.append(('localhost', port))

transaction = {
	1: partial(generate_transaction, message='test', nonce=0, sender="aabbcc"),
	2: partial(generate_transaction, message='test-1', nonce=0),
	3: partial(generate_transaction, message='test', nonce='abc', nonce_type=str),
	4: partial(generate_transaction, message='test', nonce=0, signature="aabbcc"),
	5: partial(generate_transaction, message='test', nonce=0)
}[args.test]()

print(f'transaction: {transaction}')

sockets: 'list[socket.socket]' = []
for node in nodes:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.settimeout(5)
		s.connect((node[0], node[1]))
	except Exception as e:
		print(f'failed to connect to {node[0]}:{node[1]}: {e}')
		s.close()
	else:
		print(f'connected to {node[0]}:{node[1]}')
		sockets.append(s)

for s in sockets:
	print(f'sending to {s.getpeername()}')
	send_prefixed(s, transaction.encode())

for s in sockets:
	print(f'receiving from {s.getpeername()}')
	try:
		data = recv_prefixed(s).decode()
		print(data)
	except Exception as e:
		print(f'failed to receive data from {s}: {e}')
