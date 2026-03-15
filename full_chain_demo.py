import base64
import json
import os
import socket
import ssl
import threading
import time

from Crypto.PublicKey import RSA

from authentication import IoTDeviceAuthenticator, generate_shared_key
from cryptography.aes import decrypt, encrypt
from cryptography.signature import sign, verify

HOST = "127.0.0.1"
PORT = 8443
TLS_CERT = os.path.join("tls", "server.crt")
TLS_KEY = os.path.join("tls", "server.key")


def run_tls_server(app_key, public_key):
    # helper pour run le serveur tls
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        client_socket, _ = server_socket.accept()

        with context.wrap_socket(client_socket, server_side=True) as tls_socket:
            print("Cloud: TLS connection accepted.")
            print("Cloud: TLS version =", tls_socket.version())
            packet = json.loads(tls_socket.recv(4096).decode("utf-8"))

    iv = base64.b64decode(packet["iv"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    signature = base64.b64decode(packet["signature"])
    plaintext = decrypt(app_key, iv, ciphertext)
    is_valid = verify(public_key, plaintext, signature)

    print("Cloud: app data decrypted =", plaintext)
    print("Cloud: signature valid =", is_valid)


def main():
    
    print("Mutual authentication between sensor and gateway")
    
    auth_key = generate_shared_key()
    sensor = IoTDeviceAuthenticator("sensor", auth_key)
    gateway = IoTDeviceAuthenticator("gateway", auth_key)
    sensor.mutual_authenticate(gateway)
    
    print("Authentication successful.\n")

    print("Application crypto on the sensor data")
    sensor_data = "Temperature: 22C, Humidity: 45%, Soil Moisture: 30%"
    app_key = os.urandom(16)
    rsa_key_pair = RSA.generate(2048)
    iv, ciphertext = encrypt(app_key, sensor_data)
    signature = sign(rsa_key_pair, sensor_data)
    
    print("Data encrypted with AES and signed with RSA.\n")

    print("Send the protected packet through TLS")
    server_thread = threading.Thread(
        target=run_tls_server,
        args=(app_key, rsa_key_pair.publickey()),
        daemon=True,
    )
    
    server_thread.start()
    time.sleep(0.5)

    packet = {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8"),
    }

    context = ssl.create_default_context(cafile=TLS_CERT)
    with socket.create_connection((HOST, PORT)) as client_socket:
        with context.wrap_socket(client_socket, server_hostname=HOST) as tls_socket:
            print("Gateway: server certificate validated.")
            print("Gateway: TLS version =", tls_socket.version())
            tls_socket.sendall(json.dumps(packet).encode("utf-8"))
            print("Gateway: protected packet sent.")

    server_thread.join()

if __name__ == "__main__":
    main()
