import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from cryptography.exceptions import InvalidSignature
from argparse import ArgumentParser
import json, time, errno, random, re
from threading import Lock, Thread
import socketserver, socket
import hashlib
import json

from blockchain import Blockchain, make_signature, make_transaction
from network import recv_prefixed, send_prefixed

class MyTCPServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        self.blockchain = Blockchain()
        self.blockchain_lock = Lock()
        self.block_proposals = set([])
        self.pool = []
        self.handlers = []
        self.clients = []
        self.consensus_phase = False
        self.serv_addr = server_address
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.sender = self.private_key.public_key().public_bytes_raw().hex()
        self.nonce = 0

        
        self.phrases = open("phrases.txt", 'r').read().splitlines()
        print(f"my addr: {self.serv_addr}")
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        time.sleep(1)
    
    def transaction_bytes(self, transaction: dict) -> bytes:
        payload_data = transaction.get('payload', {})
        return json.dumps({k: payload_data.get(k) for k in ['sender', 'message', 'nonce']}, sort_keys=True).encode()
    
    def validate_transaction(self, tx):
        sender_valid = re.compile('^[a-fA-F0-9]{64}$')
        message_valid = re.compile('^[a-zA-z0-9]{0,70}$')
        signature_valid = re.compile('^[a-fA-F0-9]{128}$')
        
        if not (tx.get('payload', {}).get('sender') and isinstance(tx['payload']['sender'], str) and sender_valid.search(tx['payload']['sender'])):
            print(tx.get('sender'))
            print(isinstance(tx['payload']['sender'], str))
            print(sender_valid.search(tx['payload']['sender']))
            print("[TX] Received an invalid transaction, wrong sender - {}".format(tx))
            return False
        
        if not (tx.get('payload', {}).get('message') and isinstance(tx['payload']['message'], str) or message_valid.search(tx['payload']['message'])):
            print("[TX] Received an invalid transaction, wrong message - {}".format(tx))
            return False
        
        if not (tx.get('payload', {}).get('signature') and isinstance(tx['payload']['signature'], str) and signature_valid.search(tx['payload']['signature'])):
            print("[TX] Received an invalid transaction, wrong signature message - {}".format(tx))
            print("BBB")
            return False
        
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx['payload']['sender']))
        try:
            public_key.verify(bytes.fromhex(tx['payload']['signature']), self.transaction_bytes(tx))
            return True
        except InvalidSignature:
            print("[TX] Received an invalid transaction, wrong signature message - {}".format(tx))
            return False
    
    def validate_consensus(self):
        return
    
    def validate_nonce(self, message):
        for c in self.clients:
            if c["public_key"] == message["payload"]["sender"]:
                if c["nonce"] < message["payload"]["nonce"]:
                    return True
                else:
                    return False
                """new_client = {"public_key": message["payload"]["sender"] ,"nonce": 0}
                self.clients.append(new_client)
                return True"""
                
    def validate_pool(self, message):
        for t in self.pool:
            if t["public_key"] == message["payload"]["sender"]:
                if t["nonce"] == message["payload"]["sender"]:
                    return False
        return True

    def client_exists(self, public_key):
        for c in self.clients:
            if isinstance(c, dict) and c["public_key"] == public_key:
                return True
        
        return False
    
    def update_nonce(self, public_key, nonce):
        for c in self.clients:
            if c["public_key"] == public_key:
                c["public_key"] = nonce
        return

    def handle_commands(self):
        command_socket_addr = (self.serv_addr[0],self.serv_addr[1]+100)
        self.command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.command_socket.bind(command_socket_addr)
        self.command_socket.listen()
        print(f"listening for connection to my command socket on: {command_socket_addr}")
        conn, addr = self.command_socket.accept()
        print(f"controller connected.")
        
        raw_message = conn.recv(1024)
        print(raw_message.decode())
        message = None
        
        try:
            message = json.loads(raw_message.decode())
        except json.JSONDecodeError:
            print("JSON FILE NOT LOADABLE")
        
        if message and message['type'] == "values":
            index = message['payload']
            print("BLOCK] Received a block request from node {}: {}".format(addr[0], message))
            if index == self.blockchain.get_length():
                print("valid index")
                if len(self.pool) == 0:
                    print("POOL EMPTY SENDING EMPTY TRANSACTION")
                    block = json.dumps({"index": 2, 'transactions':[], "previous_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "current_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}, sort_keys=True)
                    conn.send(block.encode())
                else:
                    print("SENDING BLOCK IN POOL")
                    block = json.dumps(self.pool[0], sort_keys=True)
                    conn.send(block.encode())

            else:
                print("Receiving block proposal is not of the correct index")

            #self.consensus_broadcast()

        elif message and message['type'] == "transaction":
            print("[NET] Received a transaction from node {}: {}".format(addr[0], message))
            transaction_valid = False

            #checks if message format is correct
            if not self.validate_transaction(message):
                conn.send(json.dumps({"response": "False"}).encode())

            #checks if client exists
            else:
                #If the client is new, the nonce does not to be checked
                if not self.client_exists(message["payload"]["sender"]):
                    #DO WE ADD THE CLIENT INTO THE LIST OF CLIENTS?
                    new_client = {"public_key": message["payload"]["sender"] ,"nonce": 0}
                    
                    conn.send(json.dumps({"response": "True"}).encode())
                    
                    self.pool.append(message)
                    
                    print("[MEM] Stored transaction in the transaction pool: {}".format(message['payload']['signature']))
                    transaction_valid = True

                #if nonce is not valid with stored client
                elif not self.validate_nonce(message):
                    print("[TX] Received an invalid transaction, wrong nonce - {}".format(message))
                    conn.send(json.dumps({"response": "False"}).encode())

                else:
                    #if transaction same public key + nonce transaction does not exist in pool
                    if not self.validate_pool(message):
                        conn.send(json.dumps({"response": "False"}).encode())
                        #NOT SURE IF MESSAGE SHOULD BE WRONG NONCE OR WRONG SENDER
                        print("[TX] Received an invalid transaction, wrong nonce - {}".format(message))
                        
                        
                    else:
                        conn.send(json.dumps({"response": "True"}).encode())

                        self.pool.append(message)

                        self.update_nonce(message["payload"]["sender"], message["payload"]["nonse"])
                        print("[MEM] Stored transaction in the transaction pool: {}".format(message['payload']['signature']))
                        transaction_valid = True


            if transaction_valid:
                index = self.blockchain.get_length()
                block_proposal = self.create_block_proposal(index, [message["payload"]], self.blockchain.last_block()["current_hash"])
                print("[PROPOSAL] Created a block proposal: {}".format(block_proposal))
                    
                block_request = json.dumps({"type": "values", 'payload': index})
                self.consensus(block_request, block_proposal)
        else:
            time.sleep(1)
            
                            
    def consensus(self, block_request, block_proposal, f = 5):
        print("STARTING CONSESNSUS")
        current_block_winner = block_proposal
        
        #for _ in range(f+1):
        for c in self.clients:
            message = c.send_message(block_request)
            response_json = json.loads(message.decode())
            
            if block_proposal["current_hash"] < response_json["current_hash"]:
                print("Current hash is less, disregarding received ")
                
            elif block_proposal["current_hash"] > response_json["current_hash"]:
                current_block_winner = response_json
                print("Current hash is more, updating pool ")
                
            else:
                print("BOTH HASHES ARE THE SAME")
        
        self.blockchain.blockchain.append(current_block_winner)
        print("[CONSENSUS] Appended to the blockchain: {}".format(self.blockchain.last_block()["current_hash"]))
        
                    
    
    def consensus_broadcast(self, block_request, f=5):
        print("beginning consensus protocol..")
        print(self.RequestHandlerClass)
        # Send block requests to all other nodes
        print("active clients: ", self.clients)
        for _ in range(f+1):
            threads = []
            print(f"broadcasting block request for round {_}")
            for client in self.clients:
                t = Thread(target=client.send_message, args=(block_request))
                threads.append(t)
                t.start()
                # received_blocks = client.block_request()
                # self.block_proposals.update(received_blocks)
            print("block proposals: ", self.block_proposals)
            for t in threads:
                t.join()
        print("finishing consensus protocol...")
        
                

    def node_addresses(self, node_list_path):
        node_addresses = []
        for line in open(node_list_path, 'r').read().splitlines()[:3]:
            addr = (line.split(":")[0],int(line.split(":")[1]))
            if addr != self.serv_addr:
                node_addresses.append(addr)
        return node_addresses

    def startup(self, node_list_path):
        Thread(target=self.handle_commands).start()
        for node_addr in self.node_addresses(node_list_path):
            Thread(target=Client, args = (node_addr, self)).start()
            self.clients.append(Client(node_addr, self))

    def make_transaction(self, message):
        transaction = self.make_transaction_request(message)
        self.send_transaction_requests(transaction)
        for cl in self.clients:
            Thread(target=cl.transaction_request, args = ([message])).start()

    def new_block_proposal(self):
        self.block_proposals.append(self.blockchain.block_proposal())


    def make_transaction_request(self, message):
        signature = make_signature(self.server.private_key, message, self.server.nonce)
        transaction =  make_transaction(self.server.sender, message, signature, self.server.nonce)
        print("making transaction.")
        return transaction

    def send_transaction_requests(self, message):
        request = self.make_transaction_request(message)
        results = []
        threads = []
        for client in self.clients:
            t = Thread(target=client.send_request, args=(results, request))
            t.start()
            threads.append(t)
        while len(results) < len(self.clients): # Check until all clients have responded
            if json.dumps({"response": True}) in results:
                # Transaction has been validated
                self.blockchain.add_transaction(request)
                return True
            time.sleep(0.1)
        return False

    def make_block_request(self):
        print("requesting block...")
        print("last block:", self.server.blockchain.last_block())
        index = self.server.blockchain.last_block()['index'] + 1
        b_request = {
            "type" : "values",
            "payload" : index
        }
        return json.dumps(b_request)

    def create_block_proposal(self, index, transactions, previous_hash):
        block_proposal = {"index": index, 'transactions': transactions, "previous_hash": previous_hash}
        json_block_proposal = json.dumps(block_proposal, sort_keys=True)
        new_hash = hashlib.sha256(json_block_proposal.encode("utf-8")).hexdigest()
        block_proposal["current_hash"] = new_hash
        return block_proposal
    
    def send_block_requests(self) -> set:
        request = self.make_block_request()
        results = []
        threads = []
        for client in self.clients:
            t = Thread(target=client.send_request, args=(results, request, True))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        block_responses = set()
        for r in results:
            block_responses.update(r)
        return block_responses

class Client():
    def __init__(self, address, server):
        self.server = server
        self.address = address
        self.listen_address = (address[0], address[1]+100)
        self.connect_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        #self.socket.connect(address)
        # self.s.settimeout(0)
        #print(f"self.s: {self.socket}")
        self.attempt_connect(self.address, self.connect_socket)
        #t = Thread(target=self.attempt_connect, args=([address]))
        #t.start()

        """self.server.clients.append(self)"""

    def attempt_connect(self, address, sock):
        # socket.connect(address)
        while sock.connect_ex(address) != 0:
            time.sleep(1)
            print(f"reattempting connection to {address}")
            sock.close()
            sock = socket.socket()
        # 	print(errno.errorcode[socket.connect_ex(address)])
        # 	socket.close()

        
        print(f"successfully connected to {address}")

    def send_message(self, message):
        if self.connected == False:
            self.send_socket.connect(self.listen_address)
            self.connected = True
        self.send_socket.send(message.encode())
        print("sent message")
        response_message = self.send_socket.recv(1024)
        return response_message
    

    def send_request(self, results, message, timeout = 0):
        self.socket.settimeout(timeout)
        send_prefixed(self.socket, message.encode())
        try:
            data = recv_prefixed(self.socket).decode()
            self.socket.settimeout(0)
            print(data)
        except Exception as e:
            print(e)
        results.append(data)

    # def transaction_request(self, results, message):
    # 	send_prefixed(self.socket, message.encode())
    # 	try:
    # 		data = recv_prefixed(self.socket).decode()
    # 		print(data)
    # 	except Exception as e:
    # 		print(e)
    # 	results.append(json.loads(data)['response'])

    def block_request(self, b_request):
        self.socket.settimeout(5)
        print("sending block_request", b_request)
        send_prefixed(self.socket, json.dumps(b_request).encode())
        b_response = set([])
        try:
            b_response = recv_prefixed(self.socket).decode()
            b_response = set(json.loads(b_response)) # this will cause a problem
            print(f"received block proposals: {b_response}, from {self.address}")
        except Exception as e:
            print(e)
        
        # self.socket.settimeout(0)
        # self.server.block_proposals.update(b_response)

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

    def transaction_response(self, data):
        with self.server.blockchain_lock:
            added = self.server.blockchain.add_transaction(data)
            # return json.dumps({'response': added}).encode()
        send_prefixed(self.request, json.dumps({'response': added}).encode())

    def block_response(self, index):
        print("serving a block response")
        block_list = []
        for block in self.server.block_proposals:
            if block[index] == index:
                block_list.append(block)
        time.sleep(random.random()*2)
        send_prefixed(self.request, json.dumps(block_list).encode())
        # Begin my own consensus
        if not self.server.consensus_phase:
            self.server.consensus_broadcast()

    def responding_loop(self):
        while True:
            # print(self.request.settimeout(2))
            # print(self.request.gettimeout())
            try:
                data = recv_prefixed(self.request).decode()
            except:
                break
            
            print("Received from {}:".format(self.client_address[0]))
            print(data)
            print("NOT PRINTING")
            if json.loads(data)['type'] == 'transaction':
                self.transaction_response(data)
            elif json.loads(data)['type'] == 'values':
                self.block_response(json.loads(data)['payload'])

    # def finish(self):
    # 	print("connection broken or timed out. trying one more time")
    # 	self.server.active_handlers.remove(self)

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('port', type=int)
    parser.add_argument('node_address', type=str)
    args = parser.parse_args()
    port: int = args.port
    node_address: str = args.node_address

    HOST = 'localhost'

    with MyTCPServer((HOST, port), MyTCPHandler) as server:
        #server.startup('node-list-test.txt')
        try: 
            server.startup(node_address)
        # while True:
        # 	server.handle_request()
            server.serve_forever()
        
        except KeyboardInterrupt:
            server.server_close()
            print()
