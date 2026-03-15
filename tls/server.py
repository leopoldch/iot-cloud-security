import os
import socket
import ssl

HOST = "127.0.0.1"
PORT = 8080
BASE_DIR = os.path.dirname(__file__)
CERT_FILE = os.path.join(BASE_DIR, "server.crt")
KEY_FILE = os.path.join(BASE_DIR, "server.key")


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"TLS server listening on {HOST}:{PORT}")

    client_socket, client_address = server_socket.accept()
    with context.wrap_socket(client_socket, server_side=True) as tls_socket:
        print("TLS connection accepted from:", client_address)
        print("TLS version:", tls_socket.version())
        print("Cipher:", tls_socket.cipher()[0])
        data = tls_socket.recv(4096).decode("utf-8")
        print("Data received by the application:", data)
