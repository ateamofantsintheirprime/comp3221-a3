import socket, time

port_number = input("type in a node port number to tell that node to start consensus protocol: ")
port_number = int(port_number)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost",port_number+100))
# each node will listen for commands on their port number + 100
s.send("transaction".encode())
# time.sleep(5)

# s.send("consensus".encode())