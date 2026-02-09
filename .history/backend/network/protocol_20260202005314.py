import json


def send_message(conn, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    conn.sendall(len(data).to_bytes(4, "big"))
    conn.sendall(data)


def receive_message(conn):
    length_data = conn.recv(4)
    if not length_data:
        return None

    length = int.from_bytes(length_data, "big")
    data = conn.recv(length)
    return json.loads(data.decode())
