from pathlib import Path

# ============================================================================
# PATH CONFIGURATION
# ============================================================================
SCRIPT_DIR = Path(__file__).parent.parent.resolve()

# VANILLA HONEYPOT PATHS
VANILLA_HONEYPOT_DIR = SCRIPT_DIR / "vanilla-honeypot"
VANILLA_COWRIE_DIR = VANILLA_HONEYPOT_DIR / "cowrie"
VANILLA_COWRIE_BIN = VANILLA_COWRIE_DIR / "cowrie-env" / "bin" / "cowrie"
VANILLA_LOG_FILE = VANILLA_COWRIE_DIR / "var" / "log" / "cowrie" / "cowrie.log"
VANILLA_JSON_LOG_FILE = VANILLA_COWRIE_DIR / "var" / "log" / "cowrie" / "cowrie.json"
VANILLA_PID_FILE = VANILLA_COWRIE_DIR / "var" / "run" / "cowrie.pid"
VANILLA_DOWNLOADS_DIR = VANILLA_COWRIE_DIR / "var" / "lib" / "cowrie" / "downloads"
VANILLA_TTY_DIR = VANILLA_COWRIE_DIR / "var" / "lib" / "cowrie" / "tty"

# SANDBOXED HONEYPOT PATHS
CONTAINER_DIR = SCRIPT_DIR / "containerised-honeypot"
DOCKERFILE = CONTAINER_DIR / "Dockerfile"
DOCKER_COMPOSE_FILE = CONTAINER_DIR / "docker-compose.yml"

# DOCKER CONFIGURATION
IMAGE_NAME = "cowrie-sandboxed-image"
IMAGE_TAG = "v2"
CONTAINER_NAME = "cowrie-honeypot"
HOST_PORT = "2223"
CONTAINER_PORT = "2222"
CONTAINER_LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie"
CONTAINER_DOWNLOADS_PATH = "/home/cowrie/cowrie/var/lib/cowrie/downloads"
CONTAINER_TTY_PATH = "/home/cowrie/cowrie/var/lib/cowrie/tty"

# KILLSWITCH CONFIGURATION
KILLSWITCH_LOG = "/var/log/honeypot_killswitch.log"

# RESULTS DIRECTORY - all experimental exports land here, one subfolder per experiment
RESULTS_DIR = SCRIPT_DIR / "results"

# STAGING DIR - CONTAINERISED LOGS ARE COPIED HERE AT STOP TIME BEOFRE docker compose down DESTROYS CONTAINER
STAGED_DIR = RESULTS_DIR / "_staged" / "containerised"