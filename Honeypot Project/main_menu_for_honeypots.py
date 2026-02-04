#!/usr/bin/env python3
"""
Main-menu command-line driven menu for both environments
"""
import os
import subprocess
from pathlib import Path
from colorama import Fore, Back, Style, init
import time

# Initialize colorama
init(autoreset=True)

# Path config
SCRIPT_DIR = Path(__file__).parent.resolve() # /home/USER/IoT-Honeypot-for-Detecting-Attacks/Honeypot Project
VANILLA_HONEYPOT_DIR = SCRIPT_DIR / "vanilla-honeypot" # /home/USER/IoT-Honeypot-for-Detecting-Attacks/Honeypot Project/vanilla-honeypot
COWRIE_DIR = VANILLA_HONEYPOT_DIR / "cowrie"
COWRIE_BIN = COWRIE_DIR / "cowrie-env" / "bin" / "cowrie"
LOG_FILE = COWRIE_DIR / "var" / "log" / "cowrie" / "cowrie.log"
JSON_LOG_FILE = COWRIE_DIR / "var" / "log" / "cowrie" / "cowrie.json"
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

def restart_cowrie():
    
    """Restart Cowrie honeypot"""
    print(f"{Fore.YELLOW}Restarting Cowrie...{Style.RESET_ALL}")
    if not LOG_FILE.exists():
        print(f"{Fore.RED}Log file not found:{Style.RESET_ALL}")
        print(f"   {LOG_FILE}")
        return
    time.sleep(2)
    stop_cowrie()
    time.sleep(2)
    start_cowrie()


def view_logs():
    """View cowrie logs in real time"""
    print(f"{Fore.YELLOW}Viewing Cowrie logs in real time (Press CTRL+C to stop)...{Style.RESET_ALL}")

    if not LOG_FILE.exists():
        print(f"{Fore.RED}Log file not found:{Style.RESET_ALL}")
        print(f"   {LOG_FILE}")
    print(f"{Fore.CYAN}Log file: {LOG_FILE}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}\n")


    try:
        # Use tail f to follow logs
        subprocess.run(["tail", "-f", str(LOG_FILE)])
    except KeyboardInterrupt:
        print(f"{Fore.GREEN}Stopped viewing logs{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error viewing logs: {e}{Style.RESET_ALL}")

def clear_logs():
    print(f"{Fore.YELLOW}Clear Cowrie logs{Style.RESET_ALL}")
    confirm = input(f"{Fore.RED}[WARNING] This will clear ALL logs. Are you sure you wish to proceed? (y/n): {Style.RESET_ALL}").strip().lower()

    if confirm != 'y':
        print(f"{Fore.RED}Cancelled operation{Style.RESET_ALL}")
        return
    try:
        log_files = [
            LOG_FILE,
            JSON_LOG_FILE,
        ]
        cleared = 0

        for log_file in log_files:
            if log_file.exists():
                # Clear file content (empty it but keep file)
                log_file.write_text("")
                time.sleep(1)                
                print(f"{Fore.GREEN}Cleared: {log_file.name}{Style.RESET_ALL}")
                cleared +=1
            else:
                print(f"{Fore.YELLOW}File not found: {log_file.name}{Style.RESET_ALL}")
        if cleared > 0:
            print(f"{Fore.GREEN}Cleared {cleared} log file(s) succesfully!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}No log files found to clear{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error clearing logs: {e}{Style.RESET_ALL}")

            
def check_status():
    """Check whether Cowrie is running"""
    print(f"{Fore.YELLOW}Cowrie health check...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}\n")

    if PID_FILE.exists():
        try:
            pid = PID_FILE.read_text().strip()

            # Check whether process is running
            result = subprocess.run(
                ["ps", "-p", pid],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                print(f"{Fore.GREEN}Status: RUNNING{Style.RESET_ALL}")
                print(f"{Fore.CYAN}PID: {pid}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Status: STOPPED (stale PID file){Style.RESET_ALL}")
                print(f"{Fore.YELLOW}(PID file exists but process not running){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Status: UNKNOWN{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}   Error: {e}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Status: STOPPED{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}(No PID file found){Style.RESET_ALL}")

    # Method 2: Use cowrie status command
    print(f"\n{Fore.CYAN}Checking via Cowrie command...{Style.RESET_ALL}")
    
    if COWRIE_BIN.exists():
        env = os.environ.copy()
        env["PATH"] = str(COWRIE_BIN.parent) + ":" + env.get("PATH", "")
        
        result = subprocess.run(
            [str(COWRIE_BIN), "status"],
            cwd=COWRIE_DIR,
            env=env,
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            print(result.stdout.strip())
    else:
        print(f"{Fore.RED}Cowrie binary not found{Style.RESET_ALL}")


    # Additional info
    print(f"\n{Fore.CYAN}Configuration:{Style.RESET_ALL}")
    print(f"   Cowrie directory: {COWRIE_DIR}")
    print(f"   Log file: {LOG_FILE}")
    
    if LOG_FILE.exists():
        # Get last 3 lines of log
        try:
            result = subprocess.run(
                ["tail", "-n", "3", str(LOG_FILE)],
                capture_output=True,
                text=True
            )
            if result.stdout:
                print(f"\n{Fore.CYAN}Last log entries:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{result.stdout}{Style.RESET_ALL}")
        except:
            pass
    time.sleep(2)

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
            restart_cowrie()
        elif choice == '4':
            view_logs()
        elif choice == '5':
            clear_logs()
        elif choice == '6':
            check_status()
        else:
            print("Please enter a valid choice!\n")
        

if __name__ == "__main__":
    main()