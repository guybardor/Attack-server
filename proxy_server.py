import socket
from scapy.all import IP, sr1
import pyotp
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#ourvpneran@outlook.com
#ourvpnisshit69 

# AES-256 Encryption and Decryption
def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    encrypted_message = base64.b64encode(iv + ct)
    print(f"Encrypting message: {message}")
    print(f"IV: {iv}")
    print(f"Ciphertext: {ct}")
    print(f"Encrypted message: {encrypted_message}")
    return encrypted_message

def decrypt_message(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    print(f"Decrypting ciphertext: {ciphertext}")
    print(f"IV: {iv}")
    print(f"Ciphertext: {ct}")
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ct) + decryptor.finalize()
    print(f"Decrypted message: {decrypted_message}")
    return decrypted_message

def handle_client_connection(client_socket, aes_key):
    try:
        auth_data = client_socket.recv(4096).decode()
        print(f"Received auth_data: {auth_data}")

        decrypted_packet = decrypt_message(auth_data.encode(), aes_key)
        print(f"Received packet: {decrypted_packet}")

        # Respond to client
        response = "Packet received successfully"
        encrypted_response = encrypt_message(response.encode(), aes_key)
        client_socket.send(encrypted_response)

    except Exception as e:
        print(f"Error handling client connection: {e}")
    finally:
        client_socket.close()

def start_proxy_server(aes_key):
    server_ip = "0.0.0.0"
    server_port = int(os.getenv("PORT", 8888))  # Koyeb provides PORT environment variable

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)
    print(f"Server listening on {server_ip}:{server_port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        handle_client_connection(client_socket, aes_key)

if __name__ == "__main__":
    AES_KEY = base64.b64decode(os.getenv("AES_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))  # Ensure this is a base64 encoded key

    start_proxy_server(AES_KEY)
