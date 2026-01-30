#!/usr/bin/env python3
"""
Main-menu command-line driven menu for both environments
"""
import os
import subprocess
from pathlib import Path
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Path config
SCRIPT_DIR = Path(__file__).parent.resolve() # /home/USER/IoT-Honeypot-for-Detecting-Attacks/Honeypot Project
VANILLA_HONEYPOT_DIR = SCRIPT_DIR / "vanilla-honeypot" # /home/USER/IoT-Honeypot-for-Detecting-Attacks/Honeypot Project/vanilla-honeypot
COWRIE_DIR = VANILLA_HONEYPOT_DIR / "cowrie"
COWRIE_BIN = COWRIE_DIR / "cowrie-env" / "bin" / "cowrie"
LOG_FILE = COWRIE_DIR / "var" / "log" / "cowrie" / "cowrie.log"
PID_FILE = COWRIE_DIR / "var" / "run" / "cowrie.pid"


def display_vanilla_menu():
    print(f"{Fore.CYAN}{'-='*20}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  VANILLA HONEYPOT OPTIONS")
    print(f"{Fore.CYAN}{'-='*20}{Style.RESET_ALL}")
    """Displays menu for vanilla-honeypot/"""
    print(f"{Fore.GREEN}[1]{Style.RESET_ALL} Start Cowrie")
    print(f"{Fore.GREEN}[2]{Style.RESET_ALL} Stop Cowrie")
    print(f"{Fore.GREEN}[3]{Style.RESET_ALL} Restart Cowrie")
    print(f"{Fore.GREEN}[4]{Style.RESET_ALL} View live logs")
    print(f"{Fore.GREEN}[5]{Style.RESET_ALL} Clear logs")
    print(f"{Fore.GREEN}[6]{Style.RESET_ALL} Check status")
    print(f"{Fore.RED}[0]{Style.RESET_ALL} Quit\n")
    print(f"{Fore.CYAN}{'-='*20}{Style.RESET_ALL}")

def start_cowrie():
    print(f"{Fore.YELLOW}Starting Cowrie...{Style.RESET_ALL}")

    if not COWRIE_BIN.exists(): # Check whether cowrie/cowrie-env/bin/cowrie exists
        print(f"{Fore.RED} Cowrie binary not found:{Style.RESET_ALL}")
        print(COWRIE_BIN)
        return

    env = os.environ.copy() # Copy current venv 
    env["PATH"] = str(COWRIE_BIN.parent) + ":" + env.get("PATH", "") 

    result = subprocess.run( 
        [str(COWRIE_BIN), "start"],
        cwd=COWRIE_DIR,
        env=env,
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(f"{Fore.YELLOW}{result.stderr}{Style.RESET_ALL}")

    if result.returncode == 0:
        print(f"{Fore.GREEN}Cowrie started successfully{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Cowrie start failed (code {result.returncode}){Style.RESET_ALL}")
  

def stop_cowrie():
    if not COWRIE_BIN.exists(): # Check whether cowrie/cowrie-env/bin/cowrie exists
        print(f"{Fore.RED} Cowrie binary not found:{Style.RESET_ALL}")
        print(COWRIE_BIN)
        return

    env = os.environ.copy() # Copy current venv 
    env["PATH"] = str(COWRIE_BIN.parent) + ":" + env.get("PATH", "") 

    result = subprocess.run( 
        [str(COWRIE_BIN), "stop"],
        cwd=COWRIE_DIR,
        env=env,
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(f"{Fore.YELLOW}{result.stdout}{Style.RESET_ALL}")
    if result.stderr:
        print(f"{Fore.YELLOW}{result.stderr}{Style.RESET_ALL}")

    if result.returncode == 0:
        print(f"{Fore.GREEN}Cowrie stopped successfully{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Cowrie stopped failed (code {result.returncode}){Style.RESET_ALL}")

def main():
    """main program loop"""
    exit = False
    while not exit:          
        display_vanilla_menu()
        choice = input("Please enter your choice> ")
        
        if choice == '0':
            exit = True
        elif choice == '1':
            start_cowrie()
        elif choice == '2':
            stop_cowrie()
        elif choice == '3':
            print("Restaring Cowrie...\n")
        elif choice == '4':
            print("Logs displayed below:\n")
        elif choice == '5':
            print("Clearing logs...\n")
        elif choice == '6':
            print("Status:\n")
        else:
            print("Please enter a valid choice!\n")
        

if __name__ == "__main__":
    main()