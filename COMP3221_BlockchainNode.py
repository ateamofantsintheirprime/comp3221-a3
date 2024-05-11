import sys, os, socket, time, io, json


server_port = int(sys.argv[1])
node_list_path = sys.argv[2]
ADDRESS = '127.0.0.1'

my_ipv4 = '192.168.1.111'

node_list = [line.split(":") for line in open(node_list_path, 'r').read().splitlines()]
