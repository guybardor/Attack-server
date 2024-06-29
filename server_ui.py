import tkinter as tk
from tkinter import messagebox
from proxy_server import start_proxy_server, aes_key
import threading

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

tk.Button(app, text="Start Server", command=start_server).pack(pady=10)
tk.Button(app, text="Stop Server", command=stop_server).pack(pady=10)

app.mainloop()
