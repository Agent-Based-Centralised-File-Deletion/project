import os
import socket
import logging


def _int_env(*keys, default):
    for key in keys:
        value = os.getenv(key)
        if value is not None and str(value).strip():
            return int(value)
    return int(default)


def _str_env(*keys, default):
    for key in keys:
        value = os.getenv(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return str(default)


def _scan_dirs():
    raw = _str_env("SCAN_DIRS", default="/scan")
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts or ["/scan"]


# Configuration
CONFIG = {
    # Support both legacy and docker-compose variable names.
    'MASTER_IP': _str_env('MASTER_IP', 'BACKEND_HOST', default='127.0.0.1'),
    'MASTER_PORT': _int_env('MASTER_PORT', 'BACKEND_PORT', default=5000),
    'CLIENT_ID': _str_env('CLIENT_ID', default=socket.gethostname()),
    # Linux-friendly default; comma-separated values remain supported.
    'SCAN_DIRECTORIES': _scan_dirs(),
    'QUARANTINE_DIR': _str_env('QUARANTINE_DIR', default='/quarantine'),
    'LOG_DIR': _str_env('LOG_DIR', default='/logs'),
    'HEARTBEAT_INTERVAL': 30,  
    'RECONNECT_DELAY': 10,  
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
