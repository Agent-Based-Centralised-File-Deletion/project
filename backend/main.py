import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from backend.network.tcp_server import start_master
except ModuleNotFoundError:
    from network.tcp_server import start_master

if __name__ == "__main__":
    start_master()
