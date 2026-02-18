import json
import socket


def receive_message(conn):
    try:
        length_data = conn.recv(4)
        if not length_data:
            return None

        length = int.from_bytes(length_data, "big")
        data = b""

        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                return None
            data += chunk

        return json.loads(data.decode())

    except (socket.error, json.JSONDecodeError) as e:
        print("[MASTER] Protocol receive error:", e)
        return None
