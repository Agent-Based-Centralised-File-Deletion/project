import socket
import threading

HOST = "0.0.0.0"   
PORT = 5000

def handle_agent(conn, addr):
    """
    Handles communication with a single agent
    """
    agent_ip = addr[0]
    agent_port = addr[1]

    print(f"[MASTER] Agent connected from {agent_ip}:{agent_port}")

    try:

        data = conn.recv(1024).decode()
        print(f"[MASTER] Registration from {agent_ip}: {data}")

       
        message = "HELLO_AGENT"
        conn.sendall(message.encode())
        print(f"[MASTER] Sent to {agent_ip}: {message}")

    except Exception as e:
        print(f"[MASTER] Error with agent {agent_ip}: {e}")

    finally:
        conn.close()
        print(f"[MASTER] Connection closed for {agent_ip}\n")


def start_master():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"[MASTER] Master listening on port {PORT}...\n")

    while True:
        conn, addr = server_socket.accept()

        thread = threading.Thread(
            target=handle_agent,
            args=(conn, addr),
            daemon=True
        )
        thread.start()


