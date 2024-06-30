import tkinter as tk
from tkinter import messagebox
from client_side import send_packet_to_server
import os
from scapy.all import IP, ICMP

def connect_to_server():
    server_ip = server_ip_entry.get()
    server_port = int(server_port_entry.get())
    aes_key = b'\x00' * 32  # Use the predefined key for consistency
    packet = IP(dst="8.8.8.8") / ICMP()
    try:
        send_packet_to_server(server_ip, server_port, aes_key, packet)
        messagebox.showinfo("Success", "Packet sent and response received!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# UI Setup
app = tk.Tk()
app.title("VPN Client")

tk.Label(app, text="Server IP:").grid(row=0)
tk.Label(app, text="Server Port:").grid(row=1)

server_ip_entry = tk.Entry(app)
server_port_entry = tk.Entry(app)

server_ip_entry.grid(row=0, column=1)
server_port_entry.grid(row=1, column=1)

tk.Button(app, text="Connect", command=connect_to_server).grid(row=4, column=1, pady=4)

app.mainloop()
