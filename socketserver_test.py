import socketserver, json
from argparse import ArgumentParser
from network import recv_prefixed, send_prefixed

class SingleTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            message = recv_prefixed(self.request).decode()
            print(message)
            send_prefixed(self.request, json.dumps({'response': "confirm"}).encode())


class SimpleServer(socketserver.TCPServer):
    timeout = 3

    def handle_timeout(self):
        print("Timeout")

    def __init__(self, server_address, RequestHandlerClass):
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

if __name__ == '__main__':
	parser = ArgumentParser()
	parser.add_argument('port', type=int)
	args = parser.parse_args()
	port: int = args.port

	HOST = 'localhost'

	with SimpleServer((HOST, port), SingleTCPHandler) as server:
		while True:
		    server.handle_request()
		#server.serve_forever()
