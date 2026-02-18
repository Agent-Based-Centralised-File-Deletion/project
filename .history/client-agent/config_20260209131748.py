import os
import socket
import logging

# Configuration
CONFIG = {
    'MASTER_IP': os.getenv('MASTER_IP', '192.168.85.24'),
    'MASTER_PORT': int(os.getenv('MASTER_PORT', 5000)),
    'CLIENT_ID': os.getenv('CLIENT_ID', socket.gethostname()),
    'SCAN_DIRECTORIES': os.getenv('SCAN_DIRS', r'C:\Users\user\Downloads\Network_Test_Folder').split(','),
    'QUARANTINE_DIR': os.getenv('QUARANTINE_DIR', '/quarantine'),
    'LOG_DIR': os.getenv('LOG_DIR', '/logs'),
    'HEARTBEAT_INTERVAL': 30,  # seconds
    'RECONNECT_DELAY': 10,  # seconds
}

# Setup logging
os.makedirs(CONFIG['LOG_DIR'], exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{CONFIG['LOG_DIR']}/agent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ClientAgent')