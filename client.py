import socket
import threading
import pickle
import rsa

SERVER_IP = "localhost"
SERVER_PORT = 5000
BUFFER_SIZE = 1024
KEY_SIZE = 1024

print("Generating public and private keys (%s bytes)" % KEY_SIZE)
KEY_PUBLIC, KEY_PRIVATE = rsa.newkeys(KEY_SIZE)
KEY_PUBLIC_PICKLE = pickle.dumps(KEY_PUBLIC)

class Server(threading.Thread):
	def __init__(self, addr, port, buffer_size=1024):
		threading.Thread.__init__(self)
		self.addr = addr
		self.port = port
		self.buffer_size = buffer_size
		self.server_key = None
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.running = False

	def connect(self):
		self.log("connecting to server at %s:%s" % (self.addr, self.port))
		self.socket.connect((self.addr, self.port))

	def log(self, *args, **kwargs):
		print("(%s:%s) ->" % (self.addr, self.port), *args, **kwargs)

	def send(self, message):
		data = rsa.encrypt(message.encode("utf8"), self.server_key)
		self.socket.send(data)

	def recv(self, data):
		message = rsa.decrypt(data, KEY_PRIVATE)
		self.handle(message)

	def handle(self, message):
		self.log("received:", message)

	def stop(self):
		self.log("ending connection")
		self.socket.shutdown(socket.SHUT_WR)
		self.running = False

	def run(self):
		self.connect()

		self.log("sending own public key to server")
		self.socket.send(KEY_PUBLIC_PICKLE)

		self.log("reveiving server public key")
		data = self.socket.recv(self.buffer_size)
		self.server_key = pickle.loads(data)

		self.log("encrypted connection established")
		self.running = True
		while self.running:
			data = self.socket.recv(self.buffer_size)
			if not data: self.stop()
			else: self.recv(data)
		self.log("loop terminated")

server = Server(SERVER_IP, SERVER_PORT, buffer_size=BUFFER_SIZE)
server.start()

input()
server.send("hello, world")
input()

server.stop()