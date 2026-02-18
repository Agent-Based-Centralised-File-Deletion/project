from network.protocol import receive_message

while True:
    message = receive_message(conn)
    if not message:
        break

    print(f"[MASTER] Message from {agent_ip}:")
    print(json.dumps(message, indent=2))
