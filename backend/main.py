try:
    from backend.network.tcp_server import start_master
except ModuleNotFoundError:
    from network.tcp_server import start_master

if __name__ == "__main__":
    start_master()
