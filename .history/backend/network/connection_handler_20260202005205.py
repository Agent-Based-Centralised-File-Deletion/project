
from .protocol import receive_message, send_message
from orchestrator.task_dispatcher import dispatch_initial_task


def handle_agent(conn, addr):
    agent_ip, agent_port = addr
    print(f"[MASTER] Agent connected: {agent_ip}:{agent_port}")

    try:
        registration = receive_message(conn)
        print(f"[MASTER] Registration: {registration}")

        dispatch_initial_task(conn)

        while True:
            message = receive_message(conn)
            if not message:
                break

            print(f"[MASTER] Message from {agent_ip}: {message}")

    except Exception as e:
        print(f"[MASTER] Error with {agent_ip}: {e}")

    finally:
        conn.close()
        print(f"[MASTER] Connection closed: {agent_ip}")
