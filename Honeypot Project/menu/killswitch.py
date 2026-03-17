# ============================================================================
# killswitch.py - NFTABLES KILLSWITCH
# ============================================================================

import os
import signal
import subprocess
import time
 
from colorama import Fore, Style
 
from menu.config import CONTAINER_NAME, VANILLA_PID_FILE, KILLSWITCH_LOG
from menu.utils import clear_screen, print_header, pause


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
