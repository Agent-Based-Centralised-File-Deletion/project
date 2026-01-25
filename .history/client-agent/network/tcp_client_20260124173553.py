import socket
import json
import platform

MASTER_IP = "127.0.0.1"  
PORT = 5000

def start_agent():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((MASTER_IP, PORT))

   
    agent_ip = client_socket.getsockname()[0]

    agent_info = {
        "agent_id": platform.node(),     
        "ip_address": agent_ip,
        "os": platform.system()
    }

 
    client_socket.sendall(json.dumps(agent_info).encode())
    print("[AGENT] Sent registration:", agent_info)

    reply = client_socket.recv(1024).decode()
    print("[AGENT] Received from master:", reply)

    client_socket.close()


if __name__ == "__main__":
    start_agent()
