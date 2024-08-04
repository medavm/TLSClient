

import socket, ssl, time, sys

# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)


HOST = "0.0.0.0"
PORT = 9000


def test():
	context = ssl.create_default_context()
	context.load_cert_chain(certfile="mycert.pem") 
	sock = socket.socket()
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind((HOST, PORT))
	sock.listen(5)
	context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	context.load_cert_chain(certfile="mycert.pem") 
	context.set_ciphers('AES256+ECDH:AES256+EDH')

	while True:

		try:

			print("waiting for client", flush=True)
			client, addr = sock.accept()
			print("client connected", addr, flush=True)
			conn = context.wrap_socket(client, server_side=True)
			data = conn.recv()
			while data:
				print(data.decode(), flush=True)
				data = conn.recv()

		except KeyboardInterrupt:
			sock.close()
			sys.exit(00)


test()
