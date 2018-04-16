import rsa
import pickle
import socket

my_pubkey, privkey = rsa.newkeys(1024)

pkey = pickle.dumps(my_pubkey)

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("localhost", 5000))

socket.send(pkey)
data = socket.recv(1024)

server_key = pickle.loads(data)


crypto = rsa.encrypt("Hello, world!".encode("utf8"), server_key)
socket.send(crypto)