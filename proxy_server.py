import socket
from scapy.all import IP, sr1
import pyotp
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# User database (for simplicity, storing in a dictionary)
user_db = {
    'user1': 'password1',
    'user2': 'password2'
}

# TOTP secret for each user (for simplicity, storing in a dictionary)
totp_secrets = {
    'user1': pyotp.random_base32(),
    'user2': pyotp.random_base32()
}

def authenticate_user(username, password):
    return user_db.get(username) == password

def verify_totp(username, token):
    totp = pyotp.TOTP(totp_secrets[username])
    return totp.verify(token)

# AES-256 Encryption and Decryption
def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return base64.b64encode(iv + ct)

def decrypt_message(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def start_proxy_server(host, port, aes_key):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Proxy server listening on {host}:{port}")
    global running
    running = True

    while running:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        handle_client(client_socket, aes_key)

def handle_client(client_socket, aes_key):
    try:
        # Receive authentication data
        auth_data = client_socket.recv(1024)
        username, password, totp_token, encrypted_packet = auth_data.decode().split(':')

        # Verify username and password
        if not authenticate_user(username, password):
            client_socket.send(b"Authentication failed")
            client_socket.close()
            return

        # Verify TOTP
        if not verify_totp(username, totp_token):
            client_socket.send(b"TOTP verification failed")
            client_socket.close()
            return

        # Decrypt the packet
        decrypted_packet = decrypt_message(encrypted_packet, aes_key)

        # Process the packet with Scapy
        packet = IP(decrypted_packet)
        print(f"Decoded packet: {packet.summary()}")

        # Forward the packet to its destination
        response = sr1(packet, timeout=1, verbose=0)

        if response:
            # Encrypt the response and send it back to the client
            encrypted_response = encrypt_message(bytes(response), aes_key)
            client_socket.send(encrypted_response)
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

# Move the aes_key outside the main block so it can be imported
aes_key = os.urandom(32)

if __name__ == "__main__":
    start_proxy_server('0.0.0.0', 8888, aes_key)
