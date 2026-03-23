#!/usr/bin/env python3
"""
Honeypot Management System — entry point
Imports all functionality from the menu/ package.
"""
from colorama import Fore, Style, init

from menu.utils import clear_screen, print_header, print_separator, pause, check_aa_profile
from menu.vanilla import vanilla_menu_handler
from menu.container import docker_compose_menu_handler
from menu.export import export_logs
from menu.killswitch import display_killswitch_menu, killswitch_restore
#from menu.analyse import run_analysis
from menu.process_data import run_analysis
init(autoreset=True)


def display_main_menu():
    clear_screen()
    print_header("HONEYPOT MANAGEMENT SYSTEM")
    print(f"{Fore.GREEN}[1]{Style.RESET_ALL} Manage Vanilla Honeypot")
    print(f"{Fore.GREEN}[2]{Style.RESET_ALL} Manage Sandboxed Honeypot (Docker Compose)\n")
    print(f"{Fore.YELLOW}[E]{Style.RESET_ALL} Export Experimental Logs")

    print(f"{Fore.YELLOW}[A]{Style.RESET_ALL} Analyse Experiment")
    print(f"{Fore.YELLOW}[R]{Style.RESET_ALL} Restore Network & Docker\n")
    print(f"{Fore.RED}[K]{Style.RESET_ALL} KILLSWITCH")
    print(f"{Fore.RED}[0]{Style.RESET_ALL} Exit")
    print_separator()


def main():
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
        elif choice in ('a', 'A'):
             run_analysis()
        else:
            clear_screen()
            print(f"\n{Fore.RED}ERROR: Invalid choice{Style.RESET_ALL}")
            pause()


if __name__ == "__main__":
    main()