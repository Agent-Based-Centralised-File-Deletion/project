import socket
import threading
from .connection_handler import handle_agent

HOST = "0.0.0.0"
PORT = 5000


def start_master():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"[MASTER] Listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(
            target=handle_agent,
            args=(conn, addr),
            daemon=True
        )
        thread.start()



