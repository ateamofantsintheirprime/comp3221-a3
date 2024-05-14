import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from argparse import ArgumentParser
import json, time, errno, random
from threading import Lock, Thread
import socketserver, socket
from pprint import pprint
from builtins import set

from blockchain import Blockchain, make_signature, make_transaction
from network import recv_prefixed, send_prefixed

class MyTCPServer(socketserver.ThreadingTCPServer):
	def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
		self.blockchain = Blockchain()
		self.blockchain_lock = Lock()
		self.block_proposals = set([])
		self.handlers = []
		self.clients = []
		self.consensus_phase = False
		self.consensus_lock = Lock()

		self.serv_addr = server_address

		self.private_key = ed25519.Ed25519PrivateKey.generate()
		self.sender = self.private_key.public_key().public_bytes_raw().hex()
		self.nonce = 0


		# REMOVE THIS!!
		self.phrases = open("phrases.txt", 'r').read().splitlines()
		super().__init__(server_address, RequestHandlerClass, bind_and_activate)

		# # the following several lines has got to be the worst fucking shit ive ever written please please please please fix it
		# wait_for_address_available = True
		# while wait_for_address_available:
		# 	wait_for_address_available = False
		# 	try:
		# 		super().__init__(server_address, RequestHandlerClass, bind_and_activate)
		# 	except OSError as e:
		# 		if e.errno == 48: # Address in use error
		# 			print("waiting for address to be available...")
		# 			wait_for_address_available = True
		# 			time.sleep(.1)
		# 		else:
		# 			raise e

	def handle_commands(self):
		command_socket_addr = (self.serv_addr[0],self.serv_addr[1]+100)
		self.command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.command_socket.bind(command_socket_addr)
		self.command_socket.listen()
		conn, addr = self.command_socket.accept()
		print("connected to controller")
		while True:
			try:
				command = recv_prefixed(conn).decode()
				print("received command: ", command)
				if command == "consensus":
					self.consensus_phase = True
				if command == "transaction":
					self.initiate_transaction(self.phrases[self.nonce])
			except RuntimeError:
				print("lost connection with command socket")
				conn, addr = self.command_socket.accept()
				print("connection re-established with command socket!")

	def node_addresses(self, node_list_path):
		node_addresses = []
		for line in open(node_list_path, 'r').read().splitlines():
			addr = (line.split(":")[0],int(line.split(":")[1]))
			if addr != self.serv_addr:
				node_addresses.append(addr)
		return node_addresses

	def startup(self, node_list_path):
		Thread(target=self.handle_commands,daemon=True).start()
		for node_addr in self.node_addresses(node_list_path):
			Thread(target=Client, args = (node_addr, self),daemon=True).start()
			# self.clients.append(Client(node_addr, self))
		Thread(target=self.protocol_loop, args = ([]), daemon=True).start()

	def initiate_transaction(self, message): # this is so fucking dumb lol. fix these function names and usages. make it GOOD PLEASE FOR THE LOVE OF GOD
		# transaction = self.make_transaction_request(message)
		self.nonce += 1
		self.send_transaction_requests(message)
		with self.consensus_lock:
			if not self.consensus_phase:
				self.new_block_proposal()
				self.consensus_phase = True

	def new_block_proposal(self):
		with self.blockchain_lock:
			self.block_proposals.add(json.dumps(self.blockchain.block_proposal()))

	def protocol_loop(self, f=5):
		while True:
			start = False
			with self.blockchain_lock:
				if len(self.blockchain.pool) != 0:
					with self.consensus_lock:
						self.consensus_phase = True
			with self.consensus_lock:
				if self.consensus_phase:
					start = True
			if start:
				print("beginning consensus protocol..")
				self.block_proposals.add(json.dumps(self.blockchain.block_proposal()))
				# Send block requests to all other nodes
				print("active clients: ", self.clients)
				for _ in range(f+1):
					print(f"broadcasting block request for round {_}")
					self.send_block_requests()
					print(f"finished round {_}")
					# print("block proposals: ", self.block_proposals)

				decided_block = json.loads(list(self.block_proposals)[0])
				for b in self.block_proposals:
					block = json.loads(b) # im a clown and sets cant store dicts
					print(block)
					if block['current_hash'] < decided_block['current_hash']:
						decided_block = block
				self.block_proposals = set() # clear the block proposals.
				print("decided on the block: ", decided_block)
				with self.blockchain_lock:
					self.blockchain.commit_block(decided_block)
				print("finishing consensus protocol...")
				with self.consensus_lock:
					self.consensus_phase = False
			time.sleep(0.1)


	def make_transaction_request(self, message):
		signature = make_signature(self.private_key, message, self.nonce)
		transaction =  make_transaction(self.sender, message, signature, self.nonce)
		print("making transaction.")
		return {"type": "transaction", "payload" : transaction}
	
	def send_transaction_requests(self, message):
		request = self.make_transaction_request(message)
		results = []
		#threads = []
		for client in self.clients:
			Thread(target=client.send_request, args=(results, request, 5),daemon=True).start() # not sure if this should time out but w/e
			#t.start()
			#threads.append(t)
		while len(results) < len(self.clients) and {"response": True} not in results: # Check until all clients have responded or one validated my tx
			print("waiting for validation... ", results)
			time.sleep(0.1)
		if {"response": True} in results:
			# Transaction has been validated
			print("someone validated my transaction woohoo!")
			with self.blockchain_lock:
				self.blockchain.add_transaction(request['payload'])
			return True
		return False
	
	def make_block_request(self):
		with self.blockchain_lock:
			#print("last block:", self.blockchain.last_block())
			index = self.blockchain.last_block()['index'] + 1
		b_request = {
			'type' : 'values',
			'payload' : index
		}
		return b_request

	def send_block_requests(self) -> set:
		request = self.make_block_request()
		results = []
		threads = []
		print(f"requesting block index {request['payload']}")
		for client in self.clients:
			t = Thread(target=client.send_request, args=(results, request, 5, []))
			threads.append(t)
			t.start()
		for t in threads:
			t.join()
		
		print("results of block request: ", results)
		for block_list in results:
			for block in block_list:
				# print("attempting to add block proposal: ")
				# print(json.dumps(block))
				self.block_proposals.add(json.dumps(block))
		# print("block proposals inside block requests funciton:")
		# print(self.block_proposals)
		return self.block_proposals

class Client():
	def __init__(self, address, server):
		self.server = server
		self.address = address
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.attempt_connect(address)
		self.server.clients.append(self)

	def attempt_connect(self, address):
		# socket.connect(address)
		print(f"attempting to connect to {address}")
		while self.socket.connect_ex(address) != 0:
			time.sleep(1)
			self.socket.close()
			self.socket = socket.socket()
		print(f"successfully connected to {address}")

	def send_request(self, results, message, timeout = 0, default = None):
		data = default
		try:
			send_prefixed(self.socket, json.dumps(message).encode())
			self.socket.settimeout(timeout)
			data = json.loads(recv_prefixed(self.socket).decode())
			self.socket.settimeout(0)
			#print("data reaching client: ", data)
		except (TimeoutError, BrokenPipeError) as e:
			print(e)
			if e.errno == 32:
				print("connection closed!, trying again")
			else:
				print(f"connection to node {self.address[1]} timed out!, trying again")
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			if self.socket.connect_ex(self.address) != 0:
				print("failed to reconnect, killing.")
				self.shut_down()
			else:
				print(f"successfully reconnected to node {self.address}")
				send_prefixed(self.socket, json.dumps(message).encode())
				self.socket.settimeout(timeout)
				data = json.loads(recv_prefixed(self.socket).decode())
				self.socket.settimeout(0)
		except Exception as e:
			print(e)
			print("major error, shutting down")
			self.shut_down()
		results.append(data)
	
	def shut_down(self):
		self.server.clients.remove(self)

class MyTCPHandler(socketserver.BaseRequestHandler):
	server: MyTCPServer

	# def setup(self):
	# # 	self.server.active_handlers.append(self)
	# 	print(f"listening on {self.client_address}")
	# # 	pass

	def handle(self):
		print("new connection")
		self.responding_loop()
		# self.responding_thread = Thread(target=self.responding_loop, args=())
		# self.responding_thread.daemon = True
		# self.responding_thread.start()
		# self.responding_thread.join()
	def finish(self):
		print("connection closed...")

	def transaction_response(self, data):
		with self.server.blockchain_lock:
			added = self.server.blockchain.add_transaction(data)
			# return json.dumps({'response': added}).encode()
		send_prefixed(self.request, json.dumps({'response': added}).encode())

		# if the received transaction was validated, start consensus 
		if added:
			with self.server.consensus_lock:
				self.server.consensus_phase = True

	def block_response(self, index):
		reply = []
		with self.server.blockchain_lock:
			if index <= self.server.blockchain.last_block()['index']:
				reply = [self.server.blockchain.get(index)]
		if reply == [] and index > 0:
			for block in self.server.block_proposals:
				block = json.loads(block) # blocks are stored as strings cos of set() reasons
				if block['index'] == index:
					reply.append(block)
			# Begin my own consensus
			with self.server.consensus_lock:
				self.server.consensus_phase = True

		print(self.server.block_proposals)
		#time.sleep(random.random()*2) # This line needs to be removed in the submitted version
		print(f"serving a block response for index {index}:\n{reply}")
		try:
			send_prefixed(self.request, json.dumps(reply).encode())
		except Exception as e:
			print("failed to serve response: ", e)

	def responding_loop(self):
		while True:
			# print(self.request.settimeout(2))
			# print(self.request.gettimeout())
			data = None
			try:
				data = json.loads(recv_prefixed(self.request).decode())
			except Exception as e:
				print("error responding!", e)
				break
			print("Received from {}:".format(self.client_address))
			print("data reaching server: ", data)
			if data['type'] == 'transaction':
				self.transaction_response(data['payload'])
			elif data['type'] == 'values':
				self.block_response(data['payload'])

	# def finish(self):
	# 	print("connection broken or timed out. trying one more time")
	# 	self.server.active_handlers.remove(self)

if __name__ == '__main__':
	parser = ArgumentParser()
	parser.add_argument('port', type=int)
	args = parser.parse_args()
	port: int = args.port

	HOST = 'localhost'

	with MyTCPServer((HOST, port), MyTCPHandler) as server:
		try:
			server.startup('node-list-test.txt')
			# while True:
			# 	server.handle_request()
			server.serve_forever()
		except KeyboardInterrupt:
			server.server_close()
			print()