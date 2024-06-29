import tkinter as tk
from tkinter import messagebox
from client_side import send_packet_to_server
import os
from scapy.all import IP, ICMP

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
