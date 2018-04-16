import socket
import threading
import pickle
import rsa

SERVER_IP = "0.0.0.0"
SERVER_PORT = 5000
BUFFER_SIZE = 1024
KEY_SIZE = 1024

print("Generating public and private keys (%s bytes)" % KEY_SIZE)
KEY_PUBLIC, KEY_PRIVATE = rsa.newkeys(KEY_SIZE)
KEY_PUBLIC_PICKLE = pickle.dumps(KEY_PUBLIC)

print("Configuring TCP socket connection (%s:%s)" % (SERVER_IP, SERVER_PORT))
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind((SERVER_IP, SERVER_PORT))
socket.listen(1)

class Client(threading.Thread):
	clients = []

	def __init__(self, socket, addr, buffer_size=1024):
		threading.Thread.__init__(self)
		self.socket = socket
		self.addr = addr[0]
		self.port = int(addr[1])
		self.buffer_size = buffer_size
		self.public_key = None
		self.running = False
		self.start()

	def __str__(self):
		return "Client(%s:%s)" % (self.addr, self.port)

	# RSA encrypted wrappers for send and recv
	def recv(self, data):
		message = rsa.decrypt(data, KEY_PRIVATE)
		self.handle(message)

	def send(self, message):
		data = rsa.encrypt(message.encode("utf8"), self.public_key)
		self.socket.send(data)

	def handle(self, message):
		self.log("received:", message)
		self.send("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaah")

	def log(self, *args, **kwargs):
		print("(%s:%s) ->" % (self.addr, self.port), *args, **kwargs)

	def stop(self):
		Client.clients.remove(self)
		self.running = False
		self.log("client disconnected")

	def run(self):
		Client.clients.append(self)

		self.log("awaiting RSA key exchange")
		data = self.socket.recv(self.buffer_size)
		self.public_key = pickle.loads(data)

		self.log("recieved public key, sending server key")
		self.socket.send(KEY_PUBLIC_PICKLE)

		self.log("initiating thread")
		self.running = True
		while self.running:
			try:
				data = self.socket.recv(self.buffer_size)
				if not data: self.stop()
				else: self.recv(data)
			except Exception as e: # TODO: choose specific errors to catch
				self.log("an error occured: %s" % e)
				self.stop()
		self.log("loop terminated")

print("Awaiting incoming connections")
while True:
	conn, addr = socket.accept()
	print("New connection from %s:%s" % (addr[0], addr[1]))
	Client(conn, addr, buffer_size=BUFFER_SIZE)