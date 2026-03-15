import os
import socket
import ssl

HOST = "127.0.0.1"
PORT = 8080
MESSAGE = "Bonjour serveur ! Voici les données du capteur IoT."
BASE_DIR = os.path.dirname(__file__)
CERT_FILE = os.path.join(BASE_DIR, "server.crt")


context = ssl.create_default_context(cafile=CERT_FILE)

with socket.create_connection((HOST, PORT)) as client_socket:
    with context.wrap_socket(client_socket, server_hostname=HOST) as tls_socket:
        print("Server certificate validated.")
        print("TLS version:", tls_socket.version())
        print("Cipher:", tls_socket.cipher()[0])
        tls_socket.sendall(MESSAGE.encode("utf-8"))
        print("Message sent:", MESSAGE)
