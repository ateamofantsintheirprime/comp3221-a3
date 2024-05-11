import socket, time
from network import send_prefixed


port_number = input("type in a node port number to control a node: ")
port_number = int(port_number)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    # each node will listen for commands on their port number + 100
    s.connect(("localhost",port_number+100))
    while True:
        try:
            send_prefixed(s, input("command: ").encode())
        except KeyboardInterrupt:
            print()
            s.close()
            break
except ConnectionRefusedError:
    print("Connection refused, please make sure to start up the node before doing this!")
