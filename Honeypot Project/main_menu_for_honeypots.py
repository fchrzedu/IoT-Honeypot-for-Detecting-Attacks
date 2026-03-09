#!/usr/bin/env python3
"""
Unified Honeypot Management System
Manages both Vanilla and Containerised Cowrie Honeypots
"""
import os
import subprocess
import time
from datetime import datetime
import signal
from pathlib import Path
from colorama import Fore, Style, init
import shutil

# Initialize colorama
init(autoreset=True)


# ============================================================================
# PATH CONFIGURATION
# ============================================================================
SCRIPT_DIR = Path(__file__).parent.resolve()

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


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')


def print_header(text):
    """Print a formatted header"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{text:^60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


def print_separator():
    """Print a separator line"""
    print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}")


def pause():
    """Pause and wait for user input"""
    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")


# ============================================================================
# DOCKER HELPER FUNCTIONS
# ============================================================================

# FIX 1: is_container_running — added missing --format flag.
# Without --format, docker ps returns a table with headers, not just names,
# so the container name would never match reliably.
def is_container_running(container_name):
    """Returns True if the named container is currently running."""
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    return container_name in result.stdout


# FIX 2: is_container_stopped — rewrote entirely.
# Original used curly braces {} which is not valid Python syntax (that's JavaScript).
# Python functions use 'def' with a colon and indented body.
def is_container_stopped(container_name):
    """
    Returns True if the container exists but is currently stopped.
    Uses 'docker ps -a' which lists ALL containers including stopped ones.
    Distinguishes between 'stopped' and 'never created'.
    """
    result = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    return container_name in result.stdout


def copy_file_from_container(container_name, container_path, dest_path):
    """
    Copy a single file from a running container to the host filesystem.
    Returns True on success, False on failure.
    Reference: https://docs.docker.com/engine/reference/commandline/cp/
    """
    result = subprocess.run(
        ["docker", "cp", f"{container_name}:{container_path}", str(dest_path)],
        capture_output=True, text=True
    )
    return result.returncode == 0


def list_files_in_container(container_name, container_path):
    """
    List files inside a container directory.
    Returns a list of filenames, or empty list if directory is empty/inaccessible.
    Note: stdout is a string property — never call it as stdout()
    """
    result = subprocess.run(
        ["docker", "exec", container_name, "ls", container_path],
        capture_output=True, text=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]


# ============================================================================
# HEALTH CHECK
# ============================================================================
def check_aa_profile():
    """
    Verify the cowrie-docker AppArmor profile is loaded at startup.
    Called once when the menu launches.
    """
    result = subprocess.run(
        ["sudo", "aa-status"], capture_output=True, text=True
    )
    if "cowrie-docker" not in result.stdout:
        print(f"{Fore.RED}[!] WARNING: cowrie-docker AppArmor profile is not loaded!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Run: sudo apparmor_parser -r /etc/apparmor.d/containers/cowrie-docker{Style.RESET_ALL}")
        pause()


# ============================================================================
# MAIN MENU
# ============================================================================
def display_main_menu():
    """Display main menu for honeypot selection"""
    clear_screen()
    print_header("HONEYPOT MANAGEMENT SYSTEM")

    print(f"{Fore.GREEN}[1]{Style.RESET_ALL} Manage Vanilla Honeypot")
    print(f"{Fore.GREEN}[2]{Style.RESET_ALL} Manage Sandboxed Honeypot (Docker Compose)\n")
    print(f"{Fore.YELLOW}[E]{Style.RESET_ALL} Export Experimental Logs")
    print(f"{Fore.YELLOW}[R]{Style.RESET_ALL} Restore Network & Docker\n")
    print(f"{Fore.RED}[K]{Style.RESET_ALL} KILLSWITCH")
    print(f"{Fore.RED}[0]{Style.RESET_ALL} Exit")

    print_separator()


# ============================================================================
# VANILLA HONEYPOT FUNCTIONS
# ============================================================================
def display_vanilla_menu():
    """Display vanilla honeypot menu"""
    clear_screen()
    print_header("VANILLA HONEYPOT MENU")

    print(f"{Fore.GREEN}[1]{Style.RESET_ALL} Start Cowrie")
    print(f"{Fore.GREEN}[2]{Style.RESET_ALL} Stop Cowrie")
    print(f"{Fore.GREEN}[3]{Style.RESET_ALL} Restart Cowrie\n")
    print(f"{Fore.GREEN}[4]{Style.RESET_ALL} View Live Logs")
    print(f"{Fore.GREEN}[5]{Style.RESET_ALL} Clear All Data")
    print(f"{Fore.GREEN}[6]{Style.RESET_ALL} Check Status\n")
    print(f"{Fore.YELLOW}[b]{Style.RESET_ALL} Back to Main Menu")
    print(f"{Fore.RED}[0]{Style.RESET_ALL} Exit")

    print_separator()


def vanilla_start_cowrie():
    """Start vanilla Cowrie"""
    clear_screen()
    print_header("Starting Vanilla Cowrie")

    if not VANILLA_COWRIE_BIN.exists():
        print(f"{Fore.RED}ERROR: Cowrie binary not found{Style.RESET_ALL}")
        print(f"Path: {VANILLA_COWRIE_BIN}\n")
        return

    env = os.environ.copy()
    env["PATH"] = str(VANILLA_COWRIE_BIN.parent) + ":" + env.get("PATH", "")

    result = subprocess.run(
        [str(VANILLA_COWRIE_BIN), "start"],
        cwd=VANILLA_COWRIE_DIR,
        env=env,
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(f"{Fore.YELLOW}{result.stderr}{Style.RESET_ALL}")

    if result.returncode == 0:
        print(f"\n{Fore.GREEN}SUCCESS: Cowrie started successfully{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}ERROR: Cowrie start failed (exit code: {result.returncode}){Style.RESET_ALL}")


def vanilla_stop_cowrie():
    """Stop vanilla Cowrie"""
    clear_screen()
    print_header("Stopping Vanilla Cowrie")

    if not VANILLA_COWRIE_BIN.exists():
        print(f"{Fore.RED}ERROR: Cowrie binary not found{Style.RESET_ALL}")
        print(f"Path: {VANILLA_COWRIE_BIN}\n")
        return

    env = os.environ.copy()
    env["PATH"] = str(VANILLA_COWRIE_BIN.parent) + ":" + env.get("PATH", "")

    result = subprocess.run(
        [str(VANILLA_COWRIE_BIN), "stop"],
        cwd=VANILLA_COWRIE_DIR,
        env=env,
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(f"{Fore.YELLOW}{result.stderr}{Style.RESET_ALL}")

    if result.returncode == 0:
        print(f"\n{Fore.GREEN}SUCCESS: Cowrie stopped successfully{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}ERROR: Cowrie stop failed (exit code: {result.returncode}){Style.RESET_ALL}")


def vanilla_restart_cowrie():
    """Restart vanilla Cowrie"""
    clear_screen()
    print_header("Restarting Vanilla Cowrie")

    print("Stopping Cowrie...")
    vanilla_stop_cowrie()

    print(f"\n{Fore.CYAN}Waiting 2 seconds...{Style.RESET_ALL}")
    time.sleep(2)

    print("\nStarting Cowrie...")
    vanilla_start_cowrie()


def vanilla_view_logs():
    """View vanilla Cowrie logs"""
    clear_screen()
    print_header("Viewing Cowrie Logs (Ctrl+C to stop)")

    if not VANILLA_LOG_FILE.exists():
        print(f"{Fore.RED}ERROR: Log file not found{Style.RESET_ALL}")
        print(f"Path: {VANILLA_LOG_FILE}\n")
        return

    print(f"Log file: {VANILLA_LOG_FILE}")
    print_separator()
    print()

    try:
        subprocess.run(["tail", "-f", str(VANILLA_LOG_FILE)])
    except KeyboardInterrupt:
        print(f"\n\n{Fore.GREEN}Stopped viewing logs{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}ERROR: {e}{Style.RESET_ALL}")


def vanilla_clear_logs():
    """Clear vanilla Cowrie logs, downloads, and tty recordings"""
    clear_screen()
    print_header("Clear Vanilla Cowrie Data")

    print(f"{Fore.RED}WARNING: This will clear:{Style.RESET_ALL}")
    print(f"  - cowrie.log and cowrie.json")
    print(f"  - downloads/  (captured malware samples)")
    print(f"  - tty/        (session recordings)")
    print()
    confirm = input(f"Type 'yes' to confirm: ").strip().lower()

    if confirm != 'yes':
        print(f"\n{Fore.YELLOW}Operation cancelled{Style.RESET_ALL}")
        return

    print()

    # Truncate log files — Cowrie holds these file handles open.
    # Deleting causes it to keep writing to a deleted inode.
    for log_file in [VANILLA_LOG_FILE, VANILLA_JSON_LOG_FILE]:
        if log_file.exists():
            log_file.write_text("")
            print(f"{Fore.GREEN}    [+] Cleared: {log_file.name}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}    [!] Not found: {log_file.name}{Style.RESET_ALL}")

    # Delete downloads — safe to delete, Cowrie creates new files per sample
    if VANILLA_DOWNLOADS_DIR.exists():
        dl_files = list(VANILLA_DOWNLOADS_DIR.glob("*"))
        for f in dl_files:
            f.unlink()
        print(f"{Fore.GREEN}    [+] Cleared: downloads/ ({len(dl_files)} file(s) removed){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}    [!] downloads/ not found{Style.RESET_ALL}")

    # Delete tty recordings
    if VANILLA_TTY_DIR.exists():
        tty_files = list(VANILLA_TTY_DIR.glob("*"))
        for f in tty_files:
            f.unlink()
        print(f"{Fore.GREEN}    [+] Cleared: tty/ ({len(tty_files)} file(s) removed){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}    [!] tty/ not found{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}Vanilla honeypot data cleared.{Style.RESET_ALL}")


def vanilla_check_status():
    """Check vanilla Cowrie status"""
    clear_screen()
    print_header("Cowrie Status Check")

    if VANILLA_PID_FILE.exists():
        try:
            pid = VANILLA_PID_FILE.read_text().strip()
            result = subprocess.run(["ps", "-p", pid], capture_output=True, text=True)

            if result.returncode == 0:
                print(f"{Fore.GREEN}Status: RUNNING{Style.RESET_ALL}")
                print(f"PID: {pid}")
            else:
                print(f"{Fore.RED}Status: STOPPED{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}(Stale PID file exists){Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}Status: UNKNOWN{Style.RESET_ALL}")
            print(f"Error: {e}")
    else:
        print(f"{Fore.RED}Status: STOPPED{Style.RESET_ALL}")
        print("(No PID file found)")

    print(f"\n{Fore.CYAN}Checking via Cowrie command...{Style.RESET_ALL}\n")

    if VANILLA_COWRIE_BIN.exists():
        env = os.environ.copy()
        env["PATH"] = str(VANILLA_COWRIE_BIN.parent) + ":" + env.get("PATH", "")

        result = subprocess.run(
            [str(VANILLA_COWRIE_BIN), "status"],
            cwd=VANILLA_COWRIE_DIR,
            env=env,
            capture_output=True,
            text=True
        )

        if result.stdout:
            print(result.stdout.strip())
    else:
        print(f"{Fore.RED}Cowrie binary not found{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Configuration:{Style.RESET_ALL}")
    print(f"Cowrie directory: {VANILLA_COWRIE_DIR}")
    print(f"Log file: {VANILLA_LOG_FILE}")

    if VANILLA_LOG_FILE.exists():
        try:
            result = subprocess.run(
                ["tail", "-n", "5", str(VANILLA_LOG_FILE)],
                capture_output=True, text=True
            )
            if result.stdout:
                print(f"\n{Fore.CYAN}Last 5 log entries:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{result.stdout}{Style.RESET_ALL}")
        except:
            pass


# ============================================================================
# CONTAINERISED (DOCKER COMPOSE) HONEYPOT FUNCTIONS
# ============================================================================
def display_docker_compose_menu():
    """Display Docker Compose honeypot menu"""
    clear_screen()
    print_header("SANDBOXED HONEYPOT MENU (Docker Compose)")

    print(f"{Fore.GREEN}[1]{Style.RESET_ALL} Start Honeypot (detached)")
    print(f"{Fore.GREEN}[2]{Style.RESET_ALL} Start Honeypot (interactive)")
    print(f"{Fore.GREEN}[3]{Style.RESET_ALL} Stop Honeypot")
    print(f"{Fore.GREEN}[4]{Style.RESET_ALL} Restart Honeypot\n")

    print(f"{Fore.GREEN}[5]{Style.RESET_ALL} View Logs")
    print(f"{Fore.GREEN}[6]{Style.RESET_ALL} Check Status")
    print(f"{Fore.GREEN}[7]{Style.RESET_ALL} Rebuild Image")
    print(f"{Fore.GREEN}[8]{Style.RESET_ALL} View Collected Data\n")

    print(f"{Fore.RED}[9]{Style.RESET_ALL} Cleanup (Remove All)")
    print(f"{Fore.YELLOW}[b]{Style.RESET_ALL} Back to Main Menu")
    print(f"{Fore.RED}[0]{Style.RESET_ALL} Exit")

    print_separator()


def docker_compose_build_and_run(detached=True):
    clear_screen()
    print_header(f"Start & Initialise Honeypot ({'Detached' if detached else 'Interactive'})")

    if not DOCKER_COMPOSE_FILE.exists():
        print(f"{Fore.RED}ERROR: docker-compose.yml not found{Style.RESET_ALL}")
        print(f"Path: {DOCKER_COMPOSE_FILE}\n")
        return

    print(f"{Fore.CYAN}Starting honeypot container...{Style.RESET_ALL}")
    print_separator()

    cmd = ["docker", "compose", "up"]
    if detached:
        cmd.append("-d")
    result = subprocess.run(cmd, cwd=CONTAINER_DIR)

    if result.returncode == 0:
        if detached:
            print(f"\n{Fore.GREEN}SUCCESS: Honeypot started{Style.RESET_ALL}")
            print(f"\nSSH Access: ssh -p {HOST_PORT} root@localhost")
            print(f"View Logs:  docker compose logs -f")
    else:
        print(f"\n{Fore.RED}ERROR: Failed to start honeypot!{Style.RESET_ALL}")


def docker_compose_stop():
    """Stop Docker container"""
    clear_screen()
    print_header("Stopping Container")
    print(f"{Fore.YELLOW}Stopping will remove the container completely\nLogs inside the container will be inaccessible afterwards{Style.RESET_ALL}\n")
    export_first = input(f"{Fore.CYAN}Export logs before stopping? (yes/no)> {Style.RESET_ALL}")
    if export_first == "yes":
        export_logs()
        clear_screen()
        print_header("Stopping Container")
        print(f"{Fore.CYAN}Export complete. Stopping container...{Style.RESET_ALL}\n")   


    result = subprocess.run(
        ["docker", "compose", "down"],
        cwd=CONTAINER_DIR,
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print(f"{Fore.GREEN}SUCCESS: Honeypot stopped{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}ERROR: Failed to stop honeypot!{Style.RESET_ALL}")
        if result.stderr:
            print(result.stderr)


def docker_compose_restart():
    """Restart honeypot via docker-compose.yml"""
    clear_screen()
    print_header("Restarting Honeypot...")

    print("Stopping Honeypot...")
    subprocess.run(["docker", "compose", "down"], cwd=CONTAINER_DIR)

    time.sleep(2)
    print("\nStarting honeypot...")
    result = subprocess.run(["docker", "compose", "up", "-d"], cwd=CONTAINER_DIR)

    if result.returncode == 0:
        print(f"\n{Fore.GREEN}SUCCESS: Honeypot restarted{Style.RESET_ALL}")


def docker_compose_logs():
    """View Honeypot logs"""
    clear_screen()
    print_header("Viewing Honeypot Logs (Ctrl+C to stop)")

    print(f"Container: {CONTAINER_NAME}")
    print_separator()
    print()

    try:
        subprocess.run(["docker", "compose", "logs", "-f"], cwd=CONTAINER_DIR)
    except KeyboardInterrupt:
        print(f"\n\n{Fore.GREEN}Stopped viewing logs!{Style.RESET_ALL}")


def docker_compose_status():
    """Check honeypot status"""
    clear_screen()
    print_header("Honeypot Status Check")

    result = subprocess.run(
        ["docker", "compose", "ps"],
        cwd=CONTAINER_DIR,
        capture_output=True,
        text=True
    )

    print(result.stdout)

    container_running = subprocess.run(
        ["docker", "ps", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
        capture_output=True,
        text=True
    )

    if container_running.stdout.strip():
        print(f"\n{Fore.CYAN}Resource Usage:{Style.RESET_ALL}")
        print_separator()
        subprocess.run(["docker", "stats", "--no-stream", CONTAINER_NAME])


def docker_compose_rebuild():
    """Rebuild honeypot image"""
    clear_screen()
    print_header("Rebuilding Honeypot Image")

    print(f"{Fore.YELLOW}This will rebuild the image from scratch{Style.RESET_ALL}\n")
    confirm = input("Continue? (yes/no): ").strip().lower()

    if confirm != 'yes':
        print(f"\n{Fore.YELLOW}Operation cancelled{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}Stopping existing containers...{Style.RESET_ALL}")
    subprocess.run(["docker", "compose", "down"], cwd=CONTAINER_DIR)

    print(f"\n{Fore.CYAN}Building image...{Style.RESET_ALL}")
    print_separator()

    result = subprocess.run(
        ["docker", "compose", "build", "--no-cache"],
        cwd=CONTAINER_DIR
    )

    if result.returncode == 0:
        print(f"\n{Fore.GREEN}SUCCESS: Image rebuilt{Style.RESET_ALL}")
        print("\nYou can now start the honeypot with option [1]")
    else:
        print(f"\n{Fore.RED}ERROR: Build failed!{Style.RESET_ALL}")


def docker_compose_view_data():
    """View collected honeypot data"""
    clear_screen()
    print_header("Collected Honeypot Data")

    log_dir = CONTAINER_DIR / "cowrie-logs"
    downloads_dir = CONTAINER_DIR / "cowrie-downloads"
    tty_dir = CONTAINER_DIR / "cowrie-tty"

    print(f"{Fore.CYAN}Data Directories:{Style.RESET_ALL}\n")

    for dir_path, name in [(log_dir, "Logs"), (downloads_dir, "Downloads"), (tty_dir, "TTY Recordings")]:
        if dir_path.exists():
            files = list(dir_path.glob("*"))
            print(f"{name}: {len(files)} file(s)")
            print(f"  Location: {dir_path}")
        else:
            print(f"{name}: Directory not created yet")
            print(f"  Will be created at: {dir_path}")
        print()

    log_file = log_dir / "cowrie.log"
    if log_file.exists():
        print(f"\n{Fore.CYAN}Recent Log Entries:{Style.RESET_ALL}")
        print_separator()
        try:
            result = subprocess.run(
                ["tail", "-n", "10", str(log_file)],
                capture_output=True, text=True
            )
            print(result.stdout)
        except:
            print(f"{Fore.YELLOW}Could not read log file!{Style.RESET_ALL}")


def docker_compose_cleanup():
    """Remove all honeypot containers, images, and data"""
    clear_screen()
    print_header("Cleanup Honeypot")

    print(f"{Fore.RED}WARNING: This will remove:{Style.RESET_ALL}")
    print("  - All containers")
    print("  - The honeypot image")
    print("  - All collected data (logs, downloads, recordings)")
    print()

    confirm = input("Type 'DELETE' to confirm: ").strip()

    if confirm != 'DELETE':
        print(f"\n{Fore.YELLOW}Operation cancelled{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}Stopping and removing containers...{Style.RESET_ALL}")
    subprocess.run(["docker", "compose", "down", "-v"], cwd=CONTAINER_DIR)

    print(f"{Fore.CYAN}Removing image...{Style.RESET_ALL}")
    subprocess.run(["docker", "rmi", f"{IMAGE_NAME}:{IMAGE_TAG}"], stderr=subprocess.DEVNULL)

    print(f"{Fore.CYAN}Removing data directories...{Style.RESET_ALL}")
    for dir_name in ["cowrie-logs", "cowrie-downloads", "cowrie-tty"]:
        dir_path = CONTAINER_DIR / dir_name
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print(f"  Removed: {dir_name}")

    print(f"\n{Fore.GREEN}SUCCESS: Cleanup complete{Style.RESET_ALL}")


# ============================================================================
# MENU HANDLERS
# ============================================================================
def vanilla_menu_handler():
    """Handle vanilla honeypot menu"""
    while True:
        display_vanilla_menu()
        choice = input(f"{Fore.CYAN}Enter choice> {Style.RESET_ALL}").strip().lower()

        if choice == '0':
            return 'exit'
        elif choice == 'b':
            return 'back'
        elif choice == '1':
            vanilla_start_cowrie()
        elif choice == '2':
            vanilla_stop_cowrie()
        elif choice == '3':
            vanilla_restart_cowrie()
        elif choice == '4':
            vanilla_view_logs()
        elif choice == '5':
            vanilla_clear_logs()
        elif choice == '6':
            vanilla_check_status()
        else:
            clear_screen()
            print(f"\n{Fore.RED}ERROR: Invalid choice{Style.RESET_ALL}")
            pause()
            continue

        if choice not in ['0', 'b']:
            pause()


def docker_compose_menu_handler():
    """Handle Docker honeypot menu"""
    while True:
        display_docker_compose_menu()
        choice = input(f"{Fore.CYAN}Enter choice> {Style.RESET_ALL}").strip().lower()

        if choice == '0':
            return 'exit'
        elif choice == 'b':
            return 'back'
        elif choice == '1':
            docker_compose_build_and_run(detached=True)
        elif choice == '2':
            docker_compose_build_and_run(detached=False)
        elif choice == '3':
            docker_compose_stop()
        elif choice == '4':
            docker_compose_restart()
        elif choice == '5':
            docker_compose_logs()
        elif choice == '6':
            docker_compose_status()
        elif choice == '7':
            docker_compose_rebuild()
        elif choice == '8':
            docker_compose_view_data()
        elif choice == '9':
            docker_compose_cleanup()
        else:
            clear_screen()
            print(f"\n{Fore.RED}ERROR: Invalid choice{Style.RESET_ALL}")
            pause()
            continue

        if choice not in ['0', 'b', '2']:
            pause()


# ============================================================================
# NFTABLES KILLSWITCH
# ============================================================================
def killswitch_block_network():
    """
    Block all network traffic via nftables.
    Reference: https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
    Reference: https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
    """
    nft_rules = """
    table inet killswitch {

        chain input {
            type filter hook input priority 0; policy drop;
            iif lo accept
            ct state established,related accept
        }

        chain forward {
            type filter hook forward priority 0; policy drop;
        }

        chain output {
            type filter hook output priority 0; policy drop;
            oif lo accept
            ct state established,related accept
        }
    }
    """

    flush = subprocess.run(
        ["sudo", "nft", "flush", "ruleset"],
        capture_output=True, text=True
    )
    if flush.returncode != 0:
        print(f"{Fore.RED}[!] Failed to flush nftables ruleset: {flush.stderr}{Style.RESET_ALL}")
        return False

    load = subprocess.run(
        ["sudo", "nft", "-f", "-"],
        input=nft_rules,
        capture_output=True, text=True
    )
    if load.returncode != 0:
        print(f"{Fore.RED}[!] Failed to load nftables rules: {load.stderr}{Style.RESET_ALL}")
        return False

    return True


def killswitch_kill_docker():
    check = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    if CONTAINER_NAME in check.stdout:
        result = subprocess.run(
            ["docker", "stop", "--time", "5", CONTAINER_NAME],
            capture_output=True, text=True
        )
        return result.returncode == 0
    return None


def killswitch_kill_cowrie():
    if VANILLA_PID_FILE.exists():
        try:
            pid = int(VANILLA_PID_FILE.read_text().strip())
            os.kill(pid, 0)
            os.kill(pid, signal.SIGTERM)
            return True, pid
        except ProcessLookupError:
            return None, None
        except (ValueError, PermissionError) as e:
            return False, str(e)
    else:
        result = subprocess.run(
            ["pkill", "-SIGTERM", "-f", "cowrie-env/bin/python"],
            capture_output=True
        )
        return result.returncode == 0, "by process name"


def display_killswitch_menu():
    clear_screen()
    print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.RED}{'!!! EMERGENCY KILL SWITCH !!!':^60}{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")

    print(f"{Fore.YELLOW}This will IMMEDIATELY:{Style.RESET_ALL}")
    print(f"  {Fore.RED}1.{Style.RESET_ALL} Block ALL network traffic at kernel level (nftables)")
    print(f"  {Fore.RED}2.{Style.RESET_ALL} Stop Docker container: {CONTAINER_NAME}")
    print(f"  {Fore.RED}3.{Style.RESET_ALL} Stop vanilla Cowrie process")
    print(f"  {Fore.RED}4.{Style.RESET_ALL} Log the event to {KILLSWITCH_LOG}")
    print()
    print(f"{Fore.YELLOW}To RESTORE: select [R] from the main menu{Style.RESET_ALL}")
    print()
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")

    confirm = input(f"{Fore.RED}Type KILLSWITCH to confirm; press ENTER to cancel> {Style.RESET_ALL}").strip()

    if confirm != "KILLSWITCH":
        print(f"{Fore.GREEN}Killswitch cancelled{Style.RESET_ALL}")
        pause()
        return

    print()
    print(f"{Fore.RED}ACTIVATING KILL SWITCH...{Style.RESET_ALL}")
    print()

    print(f"{Fore.CYAN}(1) BLOCKING ALL NETWORK TRAFFIC VIA nftables...{Style.RESET_ALL}")
    if killswitch_block_network():
        print(f"{Fore.GREEN}    Network blocked at kernel level{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}    UNABLE TO BLOCK NETWORK{Style.RESET_ALL}")
    print()

    print(f"{Fore.CYAN}(2) STOPPING DOCKER CONTAINER ({CONTAINER_NAME})...{Style.RESET_ALL}")
    docker_result = killswitch_kill_docker()
    if docker_result:
        print(f"{Fore.GREEN}    Docker container stopped{Style.RESET_ALL}")
    elif docker_result is None:
        print(f"{Fore.YELLOW}    Docker container was not running{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}    FAILED TO STOP DOCKER CONTAINER{Style.RESET_ALL}")
    print()

    print(f"{Fore.CYAN}(3) STOPPING VANILLA COWRIE...{Style.RESET_ALL}")
    success, detail = killswitch_kill_cowrie()
    if success is True:
        print(f"{Fore.GREEN}    Vanilla Cowrie stopped (PID: {detail}){Style.RESET_ALL}")
    elif success is None:
        print(f"{Fore.YELLOW}    Vanilla Cowrie was not running{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}    COULD NOT STOP COWRIE: {detail}{Style.RESET_ALL}")
    print()

    print(f"{Fore.CYAN}(4) LOGGING EVENT...{Style.RESET_ALL}")
    timestamp = time.strftime('%d-%m-%Y %H:%M:%S')
    try:
        with open(KILLSWITCH_LOG, 'a') as f:
            f.write(f"[{timestamp}] KILL SWITCH ACTIVATED\n")
            f.write(f"[{timestamp}] Activated from: main_menu_for_honeypots.py\n")
    except PermissionError:
        pass
    print()

    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'KILL SWITCH COMPLETE':^60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'TO REINSTATE: select [R] from main menu':^60}{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    pause()


def killswitch_restore():
    clear_screen()
    print_header("Restoring Docker & nftables")
    subprocess.run(["sudo", "nft", "flush", "ruleset"])
    subprocess.run(["sudo", "systemctl", "restart", "docker"])
    print(f"{Fore.GREEN}Network restored. Docker restored.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}You may now restart the honeypots{Style.RESET_ALL}")
    pause()


# ============================================================================
# LOG EXPORT
# ============================================================================
def export_logs():
    clear_screen()
    print_header("EXPORT EXPERIMENTAL LOGS")

    print(f"{Fore.YELLOW}Name this experiment using kebab-case{Style.RESET_ALL}\n")
    experiment_name = input(
        f"{Fore.CYAN}Enter experiment name> {Style.RESET_ALL}"
    ).strip()

    if not experiment_name:
        print(f"{Fore.RED}No name entered. Export cancelled{Style.RESET_ALL}\n")
        pause()
        return

    if " " in experiment_name:
        experiment_name = experiment_name.replace(" ", "-")
        print(f"{Fore.YELLOW}Spaces replaced with dashes: {experiment_name}{Style.RESET_ALL}\n")

    # ── CREATE DIRECTORY STRUCTURE ────────────────────────────────
    timestamp = datetime.now().strftime("%d-%m-%Y_%H%M")
    export_name = f"{experiment_name}_{timestamp}"
    export_dir = RESULTS_DIR / export_name
    vanilla_export_dir = export_dir / "vanilla"
    containerised_export_dir = export_dir / "containerised"

    vanilla_export_dir.mkdir(parents=True, exist_ok=True)
    containerised_export_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{Fore.CYAN}Export directory: {Style.RESET_ALL}{export_dir}")
    print_separator()

    # ── METADATA FILE ─────────────────────────────────────────────
    meta_data_file = export_dir / "experiment-info.txt"
    with open(meta_data_file, 'w') as f:
        f.write(f"EXPERIMENT: {experiment_name}\n")
        f.write(f"EXPORTED: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n")
        f.write(f"-=-=-= VANILLA HONEYPOT -=-=-=\n")
        f.write(f"   source: {VANILLA_COWRIE_DIR}\n")
        f.write(f"   port: SSH 2222\n\n")
        f.write(f"-=-=-= CONTAINERISED HONEYPOT -=-=-=\n")
        f.write(f"   container: {CONTAINER_NAME}\n")
        f.write(f"   port: SSH 2223\n\n")
        f.write(f"-=-=-= HOW TO LOAD LOGS -=-=-=\n")
        f.write(f"  Pandas:\n")
        f.write(f"    import pandas as pd\n")
        f.write(f"    df = pd.read_json('vanilla/cowrie.json', lines=True)\n")
        f.write(f"    df = pd.read_json('containerised/cowrie.json', lines=True)\n\n")
        f.write(f"-=-=-= NOTES -=-=-=\n")
        f.write(f"  cowrie.json : one JSON object per line (JSON Lines format)\n")
        f.write(f"  cowrie.log  : human readable text version of same events\n")
        f.write(f"  downloads/  : captured binaries named by SHA256 hash\n")
        f.write(f"                Cowrie deduplicates — each unique file stored once\n")
    print(f"{Fore.GREEN}[+] experiment-info.txt written{Style.RESET_ALL}")

    # ── EXPORT VANILLA LOGS ───────────────────────────────────────
    print(f"\n{Fore.CYAN}Exporting vanilla honeypot...{Style.RESET_ALL}")
    vanilla_count = 0

    if VANILLA_LOG_FILE.exists():
        shutil.copy2(VANILLA_LOG_FILE, vanilla_export_dir / "cowrie.log")
        size = VANILLA_LOG_FILE.stat().st_size
        print(f"{Fore.GREEN}    cowrie.log  ({size:,} bytes){Style.RESET_ALL}")
        vanilla_count += 1
    else:
        print(f"{Fore.YELLOW}    cowrie.log not found — was Cowrie running?{Style.RESET_ALL}")

    if VANILLA_JSON_LOG_FILE.exists():
        shutil.copy2(VANILLA_JSON_LOG_FILE, vanilla_export_dir / "cowrie.json")
        size = VANILLA_JSON_LOG_FILE.stat().st_size
        print(f"{Fore.GREEN}    cowrie.json ({size:,} bytes){Style.RESET_ALL}")
        vanilla_count += 1
    else:
        print(f"{Fore.YELLOW}    cowrie.json not found — was Cowrie running?{Style.RESET_ALL}")

    vanilla_dl_export = vanilla_export_dir / "downloads"
    vanilla_dl_export.mkdir(exist_ok=True)
    if VANILLA_DOWNLOADS_DIR.exists():
        dl_files = list(VANILLA_DOWNLOADS_DIR.glob("*"))
        for dl_file in dl_files:
            shutil.copy2(dl_file, vanilla_dl_export / dl_file.name)
        count_str = f"{len(dl_files)} file(s)" if dl_files else "empty"
        colour = Fore.GREEN if dl_files else Fore.YELLOW
        print(f"{colour}    downloads/  ({count_str}){Style.RESET_ALL}")
        vanilla_count += len(dl_files)
    else:
        print(f"{Fore.YELLOW}    downloads/ directory not found{Style.RESET_ALL}")

    # ── EXPORT CONTAINERISED LOGS ─────────────────────────────────
    # FIX 3: Check container state before attempting docker cp / docker exec.
    # If stopped, start it temporarily, copy files, then stop it again.
    # Previously the script blindly ran docker cp regardless of container state.
    print(f"\n{Fore.CYAN}Exporting containerised honeypot...{Style.RESET_ALL}")
    container_count = 0
    container_was_started_for_export = False

    if not is_container_running(CONTAINER_NAME):
        if is_container_stopped(CONTAINER_NAME):
            print(f"{Fore.YELLOW}    Container is stopped — starting temporarily to extract logs...{Style.RESET_ALL}")
            start_result = subprocess.run(
                ["docker", "compose", "up", "-d"],
                cwd=CONTAINER_DIR,
                capture_output=True, text=True
            )
            if start_result.returncode == 0:
                time.sleep(3)  # give Cowrie a moment to initialise
                container_was_started_for_export = True
                print(f"{Fore.GREEN}    Container started{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}    Could not start container — containerised logs skipped{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}    Container does not exist — containerised logs skipped{Style.RESET_ALL}")

    if is_container_running(CONTAINER_NAME):
        # cowrie.log
        log_result = subprocess.run(
            ["docker", "cp",
             f"{CONTAINER_NAME}:{CONTAINER_LOG_PATH}/cowrie.log",
             str(containerised_export_dir / "cowrie.log")],
            capture_output=True, text=True
        )
        if log_result.returncode == 0:
            size = (containerised_export_dir / "cowrie.log").stat().st_size
            print(f"{Fore.GREEN}    cowrie.log  ({size:,} bytes){Style.RESET_ALL}")
            container_count += 1
        else:
            print(f"{Fore.YELLOW}    cowrie.log not found in container{Style.RESET_ALL}")

        # cowrie.json
        json_result = subprocess.run(
            ["docker", "cp",
             f"{CONTAINER_NAME}:{CONTAINER_LOG_PATH}/cowrie.json",
             str(containerised_export_dir / "cowrie.json")],
            capture_output=True, text=True
        )
        if json_result.returncode == 0:
            size = (containerised_export_dir / "cowrie.json").stat().st_size
            print(f"{Fore.GREEN}    cowrie.json ({size:,} bytes){Style.RESET_ALL}")
            container_count += 1
        else:
            print(f"{Fore.YELLOW}    cowrie.json not found in container{Style.RESET_ALL}")

        # downloads/ — list then copy individually
        container_dl_export = containerised_export_dir / "downloads"
        container_dl_export.mkdir(exist_ok=True)

        dl_filenames = list_files_in_container(CONTAINER_NAME, CONTAINER_DOWNLOADS_PATH)
        if dl_filenames:
            copied = sum(
                1 for fname in dl_filenames
                if copy_file_from_container(
                    CONTAINER_NAME,
                    f"{CONTAINER_DOWNLOADS_PATH}/{fname}",
                    container_dl_export / fname
                )
            )
            print(f"{Fore.GREEN}    downloads/  ({copied} file(s)){Style.RESET_ALL}")
            container_count += copied
        else:
            print(f"{Fore.YELLOW}    downloads/ is empty{Style.RESET_ALL}")

    # Stop container again only if export started it
    if container_was_started_for_export:
        print(f"{Fore.CYAN}    Stopping container (started for export only)...{Style.RESET_ALL}")
        subprocess.run(
            ["docker", "compose", "down"],
            cwd=CONTAINER_DIR,
            capture_output=True, text=True
        )
        print(f"{Fore.GREEN}    Container stopped{Style.RESET_ALL}")

    # ── CLEAR LIVE DATA AFTER EXPORT ─────────────────────────────
    # Logs truncated, downloads + tty deleted
    print(f"\n{Fore.CYAN}Clearing live data for next experiment...{Style.RESET_ALL}")

    for log_file in [VANILLA_LOG_FILE, VANILLA_JSON_LOG_FILE]:
        if log_file.exists():
            log_file.write_text("")
            print(f"{Fore.GREEN}    Cleared vanilla/{log_file.name}{Style.RESET_ALL}")

    if VANILLA_DOWNLOADS_DIR.exists():
        dl_files = list(VANILLA_DOWNLOADS_DIR.glob("*"))
        for f in dl_files:
            f.unlink()
        print(f"{Fore.GREEN}    Cleared vanilla/downloads/ ({len(dl_files)} file(s)){Style.RESET_ALL}")

    if VANILLA_TTY_DIR.exists():
        tty_files = list(VANILLA_TTY_DIR.glob("*"))
        for f in tty_files:
            f.unlink()
        print(f"{Fore.GREEN}    Cleared vanilla/tty/ ({len(tty_files)} file(s)){Style.RESET_ALL}")

    if is_container_running(CONTAINER_NAME):
        for log_name in ["cowrie.log", "cowrie.json"]:
            result = subprocess.run(
                ["docker", "exec", CONTAINER_NAME,
                 "truncate", "--size=0", f"{CONTAINER_LOG_PATH}/{log_name}"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print(f"{Fore.GREEN}    Cleared containerised/{log_name}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}    Could not clear containerised/{log_name}{Style.RESET_ALL}")

        rm_result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME,
             "sh", "-c", f"rm -f {CONTAINER_DOWNLOADS_PATH}/*"],
            capture_output=True, text=True
        )
        if rm_result.returncode == 0:
            print(f"{Fore.GREEN}    Cleared containerised/downloads/{Style.RESET_ALL}")

        subprocess.run(
            ["docker", "exec", CONTAINER_NAME,
             "sh", "-c", f"rm -f {CONTAINER_TTY_PATH}/*"],
            capture_output=True, text=True
        )
        print(f"{Fore.GREEN}    Cleared containerised/tty/{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}    Container not running — containerised data not cleared{Style.RESET_ALL}")

    # ── SUMMARY ──────────────────────────────────────────────────
    print()
    print_header("EXPORT SUMMARY")
    print(f"  {Fore.CYAN}Experiment   :{Style.RESET_ALL} {experiment_name}")
    print(f"  {Fore.CYAN}Location     :{Style.RESET_ALL} {export_dir}")
    print(f"  {Fore.CYAN}Vanilla      :{Style.RESET_ALL} {vanilla_count} item(s) exported")
    print(f"  {Fore.CYAN}Containerised:{Style.RESET_ALL} {container_count} item(s) exported")
    pause()


# ============================================================================
# MAIN PROGRAM
# ============================================================================
def main():
    """Main program loop"""
    check_aa_profile()

    while True:
        display_main_menu()
        choice = input(f"{Fore.CYAN}Enter choice> {Style.RESET_ALL}").strip()

        if choice == '0':
            clear_screen()
            print(f"\n{Fore.YELLOW}Exiting Honeypot Management System...{Style.RESET_ALL}\n")
            break
        elif choice == '1':
            result = vanilla_menu_handler()
            if result == 'exit':
                clear_screen()
                print(f"\n{Fore.YELLOW}Exiting Honeypot Management System...{Style.RESET_ALL}\n")
                break
        elif choice == '2':
            result = docker_compose_menu_handler()
            if result == 'exit':
                clear_screen()
                print(f"\n{Fore.YELLOW}Exiting Honeypot Management System...{Style.RESET_ALL}\n")
                break
        elif choice in ('e', 'E'):
            export_logs()
        elif choice in ('k', 'K'):
            display_killswitch_menu()
        elif choice in ('r', 'R'):
            killswitch_restore()
        else:
            clear_screen()
            print(f"\n{Fore.RED}ERROR: Invalid choice{Style.RESET_ALL}")
            pause()


if __name__ == "__main__":
    main()
