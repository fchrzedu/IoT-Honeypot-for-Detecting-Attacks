# ============================================================================
# staging.py - Log staging and AA/Seccomp extraction
# stage_containerised_logs() called automatically when containser is
#   stopped. Copies all logs from live container into STAGED_DIR on the host
#   before docker compose destroys the container filesystem. 
# ============================================================================
import subprocess
from colorama import Fore, Style

from menu.config import (
    CONTAINER_NAME, CONTAINER_LOG_PATH, CONTAINER_DOWNLOADS_PATH, STAGED_DIR)

from menu.utils import copy_file_from_container, list_files_in_container, clear_screen, print_header

def clear_app_armor_logs():
    """Clear all AppArmor logs, and logs of type BPF for seccomp"""
    clear_screen()
    print_header("Clearing AppArmor logs")

    res = subprocess.run(
        ["sudo", "truncate", "-s", "0", "/var/log/audit/audit.log"],
        capture_output=True, text=True)
    
    if res.returncode == 0:
        print(f"{Fore.GREEN}Succesfully cleared {Style.RESET_ALL}/var/log/audit/audit.log")
    else:
        print(f"{Fore.RED}ERROR: Unable to clear{Style.RESET_ALL} /var/log/audit/audit.log")
        print(res.stderr)

def stage_containerised_logs():
    """Copy containerised logs into STAGED_DIR whilst container is running.
    Called automatically at stop time so [E] can read them without restarting."""
    STAGED_DIR.mkdir(parents=True, exist_ok=True)
    staged = 0

    print(f"{Fore.CYAN}  Staging containerised logs before shutdown...{Style.RESET_ALL}")

    # cowrie.log
    res = subprocess.run(
        ["docker", "cp",
         f"{CONTAINER_NAME}:{CONTAINER_LOG_PATH}/cowrie.log",
         str(STAGED_DIR / "cowrie.log")],
        capture_output=True, text=True
    )
    if res.returncode == 0:
        size = (STAGED_DIR / "cowrie.log").stat().st_size
        print(f"{Fore.GREEN}    cowrie.log  ({size:,} bytes){Style.RESET_ALL}")
        staged += 1
    else:
        print(f"{Fore.YELLOW}    cowrie.log not found in container{Style.RESET_ALL}")

    # cowrie.json
    res = subprocess.run(
        ["docker", "cp",
         f"{CONTAINER_NAME}:{CONTAINER_LOG_PATH}/cowrie.json",
         str(STAGED_DIR / "cowrie.json")],
        capture_output=True, text=True
    )
    if res.returncode == 0:
        size = (STAGED_DIR / "cowrie.json").stat().st_size
        print(f"{Fore.GREEN}    cowrie.json ({size:,} bytes){Style.RESET_ALL}")
        staged += 1
    else:
        print(f"{Fore.YELLOW}    cowrie.json not found in container{Style.RESET_ALL}")

    # downloads/
    downloads_dest = STAGED_DIR / "downloads"
    downloads_dest.mkdir(exist_ok=True)
    downloads_fnames = list_files_in_container(CONTAINER_NAME, CONTAINER_DOWNLOADS_PATH)
    if downloads_fnames:
        copied = 0
        for fname in downloads_fnames:
            success = copy_file_from_container(
                CONTAINER_NAME,
                f"{CONTAINER_DOWNLOADS_PATH}/{fname}",
                downloads_dest / fname
            )
            if success:
                copied += 1
        print(f"{Fore.GREEN}    downloads/  ({copied} file(s)){Style.RESET_ALL}")
        staged += copied
    else:
        print(f"{Fore.YELLOW}    downloads/ is empty{Style.RESET_ALL}")

    # AppArmor denials
    aa_res = subprocess.run(
        ["sudo", "grep", "cowrie-docker", "/var/log/audit/audit.log"],
        capture_output=True, text=True
    )
    if aa_res.returncode == 0 and aa_res.stdout.strip():
        denied = []
        for x in aa_res.stdout.splitlines():
            if "DENIED" in x:
                denied.append(x)
        if denied:
            file_contents = ""
            for line in denied:
                file_contents += line + "\n"
            (STAGED_DIR / "apparmor_denials.log").write_text(file_contents)
            print(f"{Fore.GREEN}    apparmor_denials.log  ({len(denied)} denial(s)){Style.RESET_ALL}")
            staged += 1
        else:
            print(f"{Fore.YELLOW}    apparmor_denials.log  (no DENIED entries){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}    apparmor_denials.log  (audit.log unreadable){Style.RESET_ALL}")

    # Seccomp BPF events
    bpf_res = subprocess.run(
        ["sudo", "grep", "type=BPF", "/var/log/audit/audit.log"],
        capture_output=True, text=True
    )
    if bpf_res.returncode == 0 and bpf_res.stdout.strip():
        lines = 0
        for line in bpf_res.stdout.splitlines():
            lines += 1
        (STAGED_DIR / "seccomp_bpf.log").write_text(bpf_res.stdout)
        print(f"{Fore.GREEN}    seccomp_bpf.log       ({lines} event(s)){Style.RESET_ALL}")
        staged += 1
    else:
        print(f"{Fore.YELLOW}    seccomp_bpf.log       (no BPF events){Style.RESET_ALL}")

    # AppArmor profile
    profile_res = subprocess.run(
        ["sudo", "cat", "/etc/apparmor.d/cowrie-docker"],
        capture_output=True, text=True
    )
    if profile_res.returncode == 0:
        (STAGED_DIR / "apparmor_profile.txt").write_text(profile_res.stdout)
        print(f"{Fore.GREEN}    apparmor_profile.txt  (cowrie-docker profile){Style.RESET_ALL}")
        staged += 1
    else:
        print(f"{Fore.YELLOW}    apparmor_profile.txt  (not found){Style.RESET_ALL}")

    print(f"{Fore.GREEN}  Staging complete — {staged} item(s){Style.RESET_ALL}")
    return staged


