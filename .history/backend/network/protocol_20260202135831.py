import json
import socket


def send_message(conn, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    conn.sendall(len(data).to_bytes(4, "big"))
    conn.sendall(data)


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

    except (socket.error, json.JSONDecodeError):
        return None
