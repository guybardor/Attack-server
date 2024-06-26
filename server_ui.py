import tkinter as tk
from tkinter import messagebox
import socket
from scapy.all import IP, sr1
import pyotp
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import threading

# User database (for simplicity, storing in a dictionary)
user_db = {
    'user1': 'password1',
    'user2': 'password2'
}

# TOTP secret for each user (for simplicity, storing in a dictionary)
totp_secrets = {
    'user1': 'JBSWY3DPEHPK3PXP',
    'user2': 'JBSWY3DPEHPK3PXP'
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
        auth_data = client_socket.recv(1024)
        username, password, totp_token, encrypted_packet = auth_data.decode().split(':')

        if not authenticate_user(username, password):
            client_socket.send(b"Authentication failed")
            client_socket.close()
            return

        if not verify_totp(username, totp_token):
            client_socket.send(b"TOTP verification failed")
            client_socket.close()
            return

        decrypted_packet = decrypt_message(encrypted_packet, aes_key)

        packet = IP(decrypted_packet)
        print(f"Decoded packet: {packet.summary()}")

        response = sr1(packet, timeout=1, verbose=0)

        if response:
            encrypted_response = encrypt_message(bytes(response), aes_key)
            client_socket.send(encrypted_response)
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def start_server():
    global server_thread
    server_thread = threading.Thread(target=start_proxy_server, args=('0.0.0.0', 8888, aes_key))
    server_thread.start()
    messagebox.showinfo("Server", "Server started!")

def stop_server():
    global running
    running = False
    messagebox.showinfo("Server", "Server stopped!")
    server_thread.join()

# UI Setup
app = tk.Tk()
app.title("VPN Proxy Server")

aes_key = os.urandom(32)  # 32-byte key for AES-256

tk.Button(app, text="Start Server", command=start_server).pack(pady=10)
tk.Button(app, text="Stop Server", command=stop_server).pack(pady=10)

app.mainloop()
