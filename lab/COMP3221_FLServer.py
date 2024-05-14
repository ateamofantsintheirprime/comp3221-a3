import sys, os, torch, socket, threading, copy, random, time, pickle, io, binascii
import torch.nn as nn 

import torch.nn.functional as F
import numpy as np
from torch.utils.data import DataLoader
from client import Client
import matplotlib
import matplotlib.pyplot as plt

from sklearn.datasets import make_regression
from sklearn.model_selection import train_test_split


COMMUNICATION_ROUNDS = 20
CLIENT_COUNT = 5 # dont change this
ADDRESS = '127.0.0.1'
INPUT_FEATURES = 8

port = int(sys.argv[1])
sub_client = int(sys.argv[2])
test_mse = []

clients = {
    'client1' : Client(6001, "client1"),
    'client2' : Client(6002, "client2"),
    'client3' : Client(6003,"client3"),
    'client4' : Client(6004,"client4"),
    'client5' : Client(6005,"client5")
}

def send_finish_message():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = pickle.dumps({"type": "finish"})
    print("Sending finish message")
    for id in clients.keys():
        client = clients[id]
        sock.sendto(message, (ADDRESS,client.port))

def add_client(id, data_size):
    if clients[id] == True:
        raise Exception
    clients[id].active = True
    clients[id].in_queue = True
    clients[id].data_size = data_size
    print(f"Received handshake from {id}")

def receive_packet(socket):
    message, client_address = socket.recvfrom(4096)
    message = pickle.loads(message)
    if message["type"] == "handshake":
        add_client(message['id'], message['data_size'])
    if message["type"] == "model":
        add_model(message)

def listening_loop(socket):
    while True:
        receive_packet(socket)

def add_model(message):
    client_id = message['id']
    if client_id not in clients.keys():
        print(f"error, client {client_id} attempted to send a model before handshaking")
        return
    clients[client_id].latest_model = model_from_bytes(message['model'])
    
    clients[client_id].latest_round = message['round']
    clients[client_id].train_MSE = message['train_MSE']
    clients[client_id].test_MSE = message['test_MSE']

def wait_for_client_training(round_number):
    all_clients_completed = False
    while not all_clients_completed:
        all_clients_completed = True
        test = 0
        usable_clients = [c for c in clients.values() if c.active]
        for c in usable_clients:
            if c.latest_round != round_number:
                all_clients_completed = False
                time.sleep(1) # dont want to spam too hard
                break

def get_total_data_size() -> int:
    return sum([c.data_size for c in clients.values()])


def aggregate_models(global_model):
    # Zero out global model
    for param in global_model.parameters():
        param.data = torch.zeros_like(param.data)
    
    # Not all clients will be active
    usable_clients = [c for c in clients.values() if c.active]
    
    # Get selection of clients for aggregating based on subsampling specifications
    aggregate_clients = usable_clients
    if sub_client != 0:
        aggregate_clients = random.sample(usable_clients, sub_client)

    # Aggregate sampled client models into global model
    t_mse = 0
    for client in aggregate_clients:
        print("Getting local model from: ".format(client.client_id))
        t_mse += client.test_MSE / len(aggregate_clients)
        for server_param, user_param in zip(global_model.parameters(), client.latest_model.parameters()):
            sample_size_ratio = client.data_size / get_total_data_size()
            server_param.data = server_param.data + user_param.data.clone() * sample_size_ratio
    print("Broadcasting new global model")
    test_mse.append(t_mse)   

def model_to_bytes(model):
    buffer = io.BytesIO()
    torch.save(model.state_dict(), buffer)
    return buffer.getvalue()

def model_from_bytes(bytes):

    buffer = io.BytesIO(bytes)
    state_dict = torch.load(buffer)

    model = nn.Linear(state_dict['weight'].shape[1], state_dict['weight'].shape[0])
    model.load_state_dict(state_dict)
    return model

def distribute_global_model(model, round_number):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    model_bytes = model_to_bytes(model)

    message = pickle.dumps({
        "type" : "model",
        "model" : model_bytes,
        "round" : round_number
    })
    for id in clients.keys():
        client = clients[id]
        if client.in_queue:
            client.in_queue = False
            client.active = True
        sock.sendto(message, (ADDRESS, client.port))

def get_num_active_clients(clients):
    active_clients = 0
    for c in clients.values():
        if c.active:
            active_clients += 1
    
    return active_clients

if port != 6000:
    print("Port Server Must be 6000")

print("starting up server")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((ADDRESS, port))

#Waits until first connection is made and adds it to client list.

message, client_address = s.recvfrom(2048)
message = pickle.loads(message)
if message["type"] == "handshake":
    add_client(message['id'], message['data_size'])
else:
    raise Exception
#Once the first connection is made, the program waits 30 seconds before moving on.

listen_thread = threading.Thread(target=listening_loop, args=(s,))
listen_thread.daemon = True
listen_thread.start()

time.sleep(30) # wait 10 seconds for now
print("Starting Federated Learning Now")

global_model = nn.Linear(INPUT_FEATURES, 1)


for i in range(COMMUNICATION_ROUNDS):
    print("Global Iteration {}:".format(i))
    print("Total Number of clients: {}".format(get_num_active_clients(clients)))

    distribute_global_model(global_model, i)
    wait_for_client_training(i)
    aggregate_models(global_model)
    #print(f"ROUND: {i}, mse:", test_mse[-1])
#After T training rounds are completed, send finish messages to clients and close sockets
print(test_mse)
send_finish_message()
listen_thread.join(timeout=1)

# plt.figure(1,figsize=(5, 5))
# plt.plot(test_mse, label="FedAvg", linewidth  = 1)
# #plt.ylim([0.9,  0.99])
# plt.legend(loc='upper right', prop={'size': 12}, ncol=2)
# plt.ylabel('Testing MSE')
# plt.xlabel('Global rounds')
# plt.show()