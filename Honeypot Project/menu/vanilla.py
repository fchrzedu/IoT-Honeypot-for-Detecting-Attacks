import os
import subprocess 
import time

from colorama import Fore, Style
from menu.config import(
    VANILLA_COWRIE_BIN, VANILLA_COWRIE_DIR,
    VANILLA_LOG_FILE, VANILLA_JSON_LOG_FILE,
    VANILLA_PID_FILE, VANILLA_DOWNLOADS_DIR, VANILLA_TTY_DIR

)
from menu.utils import clear_screen, print_header, print_separator, pause 
# ============================================================================
# vanilla.py VANILLA HONEYPOT FUNCTIONS
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
