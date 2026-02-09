import socket
import threading
import json
import time

HOST = "0.0.0.0"
PORT = 5000


def handle_agent(conn, addr):
    agent_ip, agent_port = addr
    print(f"[MASTER] Agent connected from {agent_ip}:{agent_port}")

    try:
        # Receive registration
        data = conn.recv(1024).decode()
        print(f"[MASTER] Registration from {agent_ip}: {data}")

        time.sleep(3)

        # Send scan task
        scan_task = {
            "type": "scan_task",
            "task_id": "test_scan_001",
            "target_languages": ["python"],
            "date_filter": None
        }

        msg = json.dumps(scan_task).encode("utf-8")
        conn.sendall(len(msg).to_bytes(4, "big"))
        conn.sendall(msg)
        print(f"[MASTER] Sent scan_task to {agent_ip}")

        # Keep connection alive and receive messages
        while True:
            length_data = conn.recv(4)
            if not length_data:
                break

            length = int.from_bytes(length_data, "big")
            data = conn.recv(length)
            message = json.loads(data.decode())

            print(f"[MASTER] Message from {agent_ip}:")
            print(json.dumps(message, indent=2))

    except Exception as e:
        print(f"[MASTER] Error with agent {agent_ip}: {e}")

    finally:
        print(f"[MASTER] Handler finished for {agent_ip} (keeping connection open)")




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
