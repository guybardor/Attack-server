import socket
import pyotp
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from scapy.all import IP, ICMP

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

def send_packet_to_server(server_ip, server_port, aes_key, packet):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    encrypted_packet = encrypt_message(bytes(packet), aes_key).decode('utf-8')

    auth_data = f"{encrypted_packet}"
    client_socket.send(auth_data.encode())

    response = client_socket.recv(4096)
    decrypted_response = decrypt_message(response, aes_key)
    print(f"Received response: {decrypted_response.decode('utf-8')}")

    client_socket.close()

# Example usage
if __name__ == "__main__":
    # This should match the server's AES key
    aes_key = b'\x00' * 32  # Example predefined key, ensure this matches the server's aes_key
    
    # The packet to send
    packet = IP(dst="8.8.8.8") / ICMP()
    
    send_packet_to_server('127.0.0.1', 8888, aes_key, packet)
