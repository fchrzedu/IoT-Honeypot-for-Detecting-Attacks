#!/usr/bin/env python3
"""
Unified Honeypot Management System
Manages both Vanilla and Containerised Cowrie Honeypots
"""
import os
import subprocess
import time
import signal
from pathlib import Path
from colorama import Fore, Style, init

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

# KILLSWITCH CONFIGURATION
KILLSWITCH_LOG = "/var/log/honeypot_killswitch.log"



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
# MAIN MENU
# ============================================================================
def display_main_menu():
    """Display main menu for honeypot selection"""
    clear_screen()
    print_header("HONEYPOT MANAGEMENT SYSTEM")
    
    print(f"{Fore.GREEN}[1]{Style.RESET_ALL} Manage Vanilla Honeypot")
    print(f"{Fore.GREEN}[2]{Style.RESET_ALL} Manage Sandboxed Honeypot (Docker Compose)")
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
    print(f"{Fore.GREEN}[3]{Style.RESET_ALL} Restart Cowrie")
    print(f"{Fore.GREEN}[4]{Style.RESET_ALL} View Live Logs")
    print(f"{Fore.GREEN}[5]{Style.RESET_ALL} Clear Logs")
    print(f"{Fore.GREEN}[6]{Style.RESET_ALL} Check Status")
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
    
    if not VANILLA_LOG_FILE.exists():
        print(f"{Fore.RED}ERROR: Log file not found{Style.RESET_ALL}")
        print(f"Path: {VANILLA_LOG_FILE}\n")
        return
    
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
    """Clear vanilla Cowrie logs"""
    clear_screen()
    print_header("Clear Cowrie Logs")
    
    print(f"{Fore.RED}WARNING: This will delete all log content!{Style.RESET_ALL}\n")
    confirm = input(f"Type 'yes' to confirm: ").strip().lower()
    
    if confirm != 'yes':
        print(f"\n{Fore.YELLOW}Operation cancelled{Style.RESET_ALL}")
        return
    
    print()
    try:
        log_files = [VANILLA_LOG_FILE, VANILLA_JSON_LOG_FILE]
        cleared = 0
        
        for log_file in log_files:
            if log_file.exists():
                log_file.write_text("")
                print(f"{Fore.GREEN}Cleared: {log_file.name}{Style.RESET_ALL}")
                cleared += 1
            else:
                print(f"{Fore.YELLOW}Not found: {log_file.name}{Style.RESET_ALL}")
        
        if cleared > 0:
            print(f"\n{Fore.GREEN}SUCCESS: Cleared {cleared} log file(s){Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}No log files found to clear{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"\n{Fore.RED}ERROR: {e}{Style.RESET_ALL}")


def vanilla_check_status():
    """Check vanilla Cowrie status"""
    clear_screen()
    print_header("Cowrie Status Check")
    
    # Check PID file
    if VANILLA_PID_FILE.exists():
        try:
            pid = VANILLA_PID_FILE.read_text().strip()
            result = subprocess.run(
                ["ps", "-p", pid],
                capture_output=True,
                text=True
            )
            
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
    
    # Use cowrie status command
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
    
    # Configuration info
    print(f"\n{Fore.CYAN}Configuration:{Style.RESET_ALL}")
    print(f"Cowrie directory: {VANILLA_COWRIE_DIR}")
    print(f"Log file: {VANILLA_LOG_FILE}")
    
    # Last log entries
    if VANILLA_LOG_FILE.exists():
        try:
            result = subprocess.run(
                ["tail", "-n", "5", str(VANILLA_LOG_FILE)],
                capture_output=True,
                text=True
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
    print_header(f"Start & Initialise Honeypot ({"Detached" if detached else "Interactive"})")
    
    if not DOCKER_COMPOSE_FILE.exists():
        print(f"{Fore.RED}ERROR: docker-compose.yml not found{Style.RESET_ALL}")
        print(f"Path: {DOCKER_COMPOSE_FILE}\n")
        return
    
    print(f"{Fore.CYAN}Starting honeypot container...{Style.RESET_ALL}")
    print_separator()

    cmd = ["docker", "compose", "up"]
    if detached: cmd.append("-d")
    result = subprocess.run(cmd, cwd=CONTAINER_DIR)
    if result.returncode == 0:
        if detached:
            print(f"\n{Fore.GREEN}SUCCESS: Honeypot started{Style.RESET_ALL}")
            print(f"\nSSH Access: ssh -p {HOST_PORT} root@localhost")
            print(f"View Logs:  docker compose logs -f")
            print(f"\nLogs Directory: {CONTAINER_DIR}/cowrie-logs")
    else:
        print(f"\n{Fore.RED}ERROR: Failed to start honeypot!{Style.RESET_ALL}")




def docker_compose_stop():
    """Stop Docker container"""
    clear_screen()
    print_header("Stopping Container")
    
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
        if result.stderr: print(result.stderr)

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
    
    # Check if container is running
    result = subprocess.run(
        ["docker", "compose", "ps"],
        cwd=CONTAINER_DIR,
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    
    # Check resource usage if running
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
    
    # Check for log directories
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
    
    # Show recent log entries if available
    log_file = log_dir / "cowrie.log"
    if log_file.exists():
        print(f"\n{Fore.CYAN}Recent Log Entries:{Style.RESET_ALL}")
        print_separator()
        try:
            result = subprocess.run(
                ["tail", "-n", "10", str(log_file)],
                capture_output=True,
                text=True
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
    import shutil
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

        # Don't pause after interactive mode
        if choice not in ['0', 'b', '2']:
            pause()


# ============================================================================
# NFTABLES KILLSWITCH
# ============================================================================
def killswitch_block_network():
    """Block all network traffic via nftables
    The default templates were used to construct these following rules:
    
    Reference: https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
    Reference: https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
    """

    nft_rules = """
    table inet killswitch {

        chain input {
            type filter hook input priority 0; policy drop;

            # Allow loopback — required for OS internal communication
            iif lo accept

            # Allow established sessions — keeps this terminal alive
            # 'ct state' = connection tracking state
            # Reference: https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_information
            ct state established,related accept

            # Everything else: falls through to policy drop
        }

        chain forward {
            type filter hook forward priority 0; policy drop;
            # Drop all forwarded traffic — this covers Docker container
            # traffic which passes through the host via the forward hook
        }

        chain output {
            type filter hook output priority 0; policy drop;

            # Allow loopback output
            oif lo accept

            # Allow established outbound sessions
            ct state established,related accept

            # Everything else dropped — malware cannot phone home
        }
    }
    """

    # (1) Flush deletes ALL existing nftable rules
    flush = subprocess.run(
        ["sudo", "nft", "flush", "ruleset"],
        capture_output=True, text=True
    )

    if flush.returncode != 0:
        print(f"{Fore.RED}[!] Failed to flush nftables ruleset: {flush.stderr}{Style.RESET_ALL}")
        return False

    # Step 2: load blocking rules into the kernel via stdin
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
    # Check if container is actually running before attempting to stop
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
    else:
        # Container not running — nothing to stop
        return None
    


def killswitch_kill_cowrie():
    if VANILLA_PID_FILE.exists():
        try:
            pid = int(VANILLA_PID_FILE.read_text().strip()) # Read the PID
            os.kill(pid, 0) # kill -0 checks whether process exists without sending real signal

            # process exists, send SIGTERMINATE
            os.kill(pid, signal.SIGTERM)
            return True, pid
        except ProcessLookupError:
            # PID file exists but process is already gone
            return None, None
        except (ValueError, PermissionError) as e:
            return False, str(e)
        
    else:
        # No PID --> kill process via name
        # pkill sends signal to all processes matching the pattern
        result = subprocess.run(
            ["pkill", "-SIGTERM", "-f", "cowrie-env/bin/python"],
            capture_output=True
        )
        return result.returncode == 0, "by process name"





def display_killswitch_menu():
    clear_screen()
    print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.RED}{"!!! EMERGENCY KILL SWITCH !!!":^60}{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")


    print(f"{Fore.YELLOW}This will IMMEDIATELY:{Style.RESET_ALL}")
    print(f"  {Fore.RED}1.{Style.RESET_ALL} Block ALL network traffic at kernel level (nftables)")
    print(f"  {Fore.RED}2.{Style.RESET_ALL} Stop Docker container: {CONTAINER_NAME}")
    print(f"  {Fore.RED}3.{Style.RESET_ALL} Stop vanilla Cowrie process")
    print(f"  {Fore.RED}4.{Style.RESET_ALL} Log the event to log")
    print()
    print(f"{Fore.YELLOW}To RESTORE after VM snapshot rollback:{Style.RESET_ALL}")
    print(f"  sudo nft flush ruleset")
    print()
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    

    confirm = input(f"{Fore.RED}Type KILLSWITCH to confirm; press ENTER to cancel> {Style.RESET_ALL}").strip()

    if confirm != "KILLSWITCH":
        print(f"{Fore.GREEN}Killswitch cancelled")
        pause()
        return
    
    # --- EXECUTE KILLSWITCH ---
    print()
    print(f"{Fore.RED}ACTIVATING KILL SWITCH...{Style.RESET_ALL}")
    print()

    # Block any network
    print(f"{Fore.CYAN}(1) BLOCKING ALL NETWORK TRAFFIC VIA nftables...{Style.RESET_ALL}")
    if killswitch_block_network():
        print(f"{Fore.GREEN}Network succesfully blocked at kernel level{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}UNABLE TO BLOCK NETWORK{Style.RESET_ALL}")
    print()


    # Stop Docker
    print(f"{Fore.CYAN}(2) STOPPING DOCKER CONTAINER ({CONTAINER_NAME})...{Style.RESET_ALL}")    
    docker_result = killswitch_kill_docker()
    if docker_result:
        print(f"{Fore.GREEN}Docker container stopped{Style.RESET_ALL}")
    elif docker_result is None:
        print(f"{Fore.YELLOW}Docker container was not running{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}FAILED TO STOP DOCKER CONTAINER{Style.RESET_ALL}")
    print()

    # Stop Cowrie
    print(f"{Fore.CYAN}(3) STOPPING VANILLA COWRIE...{Style.RESET_ALL}")
    success, detail = killswitch_kill_cowrie()
    if success is True:
        print(f"{Fore.GREEN}Vanilla Cowrie stopped (PID: {detail}){Style.RESET_ALL}")
    elif success is None:
        print(f"{Fore.YELLOW}Vanilla Cowrie was not running{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}COULD NOT STOP COWRIE: {detail}{Style.RESET_ALL}")
    print()

    

    # Log event
    print(f"{Fore.CYAN}(4) LOGGING EVENT WITHIN: {Style.RESET_ALL}{KILLSWITCH_LOG}....")
    timestamp = time.strftime('%d-%m-%Y %H:%M:%S')
    try:
        with open(KILLSWITCH_LOG, 'a') as f:
            f.write(f"[{timestamp}] KILL SWITCH ACTIVATED\n")
            f.write(f"[{timestamp}] Activated from: main_menu_for_honeypots.py\n")
    except PermissionError:
        # Log file requires root — silently skip if not running as root
        pass
    print()

    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'KILL SWITCH COMPLETE':^60}\nTO REINSTATE THE FRAMEWORK, SELECT [R] IN THE MAIN MENU{Style.RESET_ALL}")
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
# HEALTH CHECK
# ============================================================================
def check_aa_profile():
    result = subprocess.run(
        ["sudo", "aa-status"],capture_output=True, text=True
    )
    if "cowrie-docker" not in result.stdout:
        print(f"{Fore.RED}[!] WARNING: cowrie-docker AppArmor profile is not loaded!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Run: sudo apparmor_parser -r /etc/apparmor.d/containers/cowrie-docker{Style.RESET_ALL}")
# ============================================================================
# MAIN PROGRAM
# ============================================================================
def main():
    """Main program loop"""
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

        elif choice == 'K' or choice == 'k':
            display_killswitch_menu()
        elif choice == 'R' or choice == 'r':
            killswitch_restore()
        else:
            clear_screen()
            print(f"\n{Fore.RED}ERROR: Invalid choice{Style.RESET_ALL}")
            pause()


if __name__ == "__main__":
    main()