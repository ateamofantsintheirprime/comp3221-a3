import socket, time
from network import send_prefixed


port_number = input("type in a node port number to control a node: ")
port_number = int(port_number)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
<<<<<<< HEAD
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
=======
s.connect(("localhost",port_number+100))
# each node will listen for commands on their port number + 100

trans = json.dumps({"type": "transaction", 'payload': {
    'sender': "a57819938feb51bb3f923496c9dacde3e9f667b214a0fb1653b6bfc0f185363b", "message": "hello", "nonce": 0, "signature": "142e395895e0bf4e4a3a7c3aabf2f59d80c517d24bb2d98a1a24384bc7cb29c9d593ce3063c5dd4f12ae9393f3345174485c052d0f5e87c082f286fd60c7fd0c"
    }})
s.send(trans.encode())

response_message = s.recv(1024)
response_json = json.loads(response_message.decode())
print(response_json["response"])



# s.send("consensus".encode())
>>>>>>> 9836f0888f414f91f31c47c5d4bf548d5f4700b6
