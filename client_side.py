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

def send_packet_to_server(server_ip, server_port, username, password, aes_key, packet, totp_secret):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    totp = pyotp.TOTP(totp_secret)
    token = totp.now()

    encrypted_packet = encrypt_message(bytes(packet), aes_key)

    auth_data = f"{username}:{password}:{token}:{encrypted_packet.decode()}"
    client_socket.send(auth_data.encode())

    response = client_socket.recv(4096)
    decrypted_response = decrypt_message(response, aes_key)
    print(f"Received response: {decrypted_response}")

    client_socket.close()

# Example usage
if __name__ == "__main__":
    aes_key = os.urandom(32)  # This should match the server's AES key
    packet = IP(dst="8.8.8.8") / ICMP()
    totp_secret = pyotp.random_base32()  # This should be securely shared with the server
    send_packet_to_server('server_ip', 8888, 'user1', 'password1', aes_key, packet, totp_secret)
