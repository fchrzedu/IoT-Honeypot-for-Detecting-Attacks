# ============================================================================
# container.py -  CONTAINERISED (DOCKER COMPOSE) HONEYPOT FUNCTIONS
# ============================================================================
import subprocess 
import time 
from colorama import Fore, Style
import shutil

from menu.config import(
    CONTAINER_DIR, DOCKER_COMPOSE_FILE,
    CONTAINER_NAME, HOST_PORT,
    CONTAINER_LOG_PATH, CONTAINER_DOWNLOADS_PATH, CONTAINER_TTY_PATH,
    IMAGE_NAME, IMAGE_TAG)

from menu.utils import(
    clear_screen, print_header, pause, print_separator, is_container_running
)
from menu.staging import clear_app_armor_logs, stage_containerised_logs
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
    print(f"{Fore.RED}[A]{Style.RESET_ALL} Clear AppArmor & Seccomp logs")
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
    
    if not is_container_running(CONTAINER_NAME):
        print(f"{Fore.YELLOW}Container is not running{Style.RESET_ALL}")
        res = subprocess.run(
            # Run docker compose down within cwd (containerised-honeypot/)
            ["docker", "compose", "down"],cwd=CONTAINER_DIR,capture_output=True,text=True)
        if res.returncode == 0:
            print(f"{Fore.GREEN}SUCCESS: {CONTAINER_NAME} removed{Style.RESET_ALL}")
            
    stage_containerised_logs()

    print(f"\n{Fore.CYAN}Bringing container down...{Style.RESET_ALL}")
    res_2 = subprocess.run(
        ["docker", "compose", "down"],cwd=CONTAINER_DIR,capture_output=True,text=True)
    if res_2.returncode == 0:
        print(f"{Fore.GREEN}Honeypot stopped!{Style.RESET_ALL}")
    else:
        print(f"{Style.RED}ERROR: Failed to stop honeypot! {Style.RESET_ALL}")
        if res_2.stderr:print(res_2.stderr)


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


def docker_compose_menu_handler():
    """Handle Docker honeypot menu"""
    while True:
        display_docker_compose_menu()
        choice = input(f"{Fore.CYAN}Enter choice> {Style.RESET_ALL}").strip().lower()

        if choice == '0':
            return 'exit'
        elif choice == 'b':
            return 'back'
        elif choice == 'a' or choice == 'A':
            clear_app_armor_logs()
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

