import tkinter as tk
from tkinter import messagebox
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

def connect_to_server():
    server_ip = server_ip_entry.get()
    server_port = int(server_port_entry.get())
    username = username_entry.get()
    password = password_entry.get()
    aes_key = os.urandom(32)
    packet = IP(dst="8.8.8.8") / ICMP()
    totp_secret = 'JBSWY3DPEHPK3PXP'
    try:
        send_packet_to_server(server_ip, server_port, username, password, aes_key, packet, totp_secret)
        messagebox.showinfo("Success", "Packet sent and response received!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# UI Setup
app = tk.Tk()
app.title("VPN Client")

tk.Label(app, text="Server IP:").grid(row=0)
tk.Label(app, text="Server Port:").grid(row=1)
tk.Label(app, text="Username:").grid(row=2)
tk.Label(app, text="Password:").grid(row=3)

server_ip_entry = tk.Entry(app)
server_port_entry = tk.Entry(app)
username_entry = tk.Entry(app)
password_entry = tk.Entry(app, show='*')

server_ip_entry.grid(row=0, column=1)
server_port_entry.grid(row=1, column=1)
username_entry.grid(row=2, column=1)
password_entry.grid(row=3, column=1)

tk.Button(app, text="Connect", command=connect_to_server).grid(row=4, column=1, pady=4)

app.mainloop()
