# ============================================================================
# utils.py — Terminal formatting helpers and Docker utility functions
# These have no side effects and can be imported anywhere safely.
# ============================================================================
import os
import subprocess
 
from colorama import Fore, Style


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
# DOCKER HELPERS
# ============================================================================




# ============================================================================
# DOCKER HELPER FUNCTIONS
# ============================================================================
def is_container_running(container_name):
    """Returns True if the named container is currently running."""
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    return container_name in result.stdout

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

    i.e.: docker cp honeypot:cowrie/home/downloads/ --> destination
    We have to access the actual Docker process
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

