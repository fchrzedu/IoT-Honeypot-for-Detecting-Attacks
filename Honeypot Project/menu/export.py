# ============================================================================
# LOG EXPORT
# ============================================================================

import subprocess
import shutil
from datetime import datetime
 
from colorama import Fore, Style
 
from menu.config import (
    RESULTS_DIR, STAGED_DIR,
    VANILLA_LOG_FILE, VANILLA_JSON_LOG_FILE,
    VANILLA_DOWNLOADS_DIR, VANILLA_TTY_DIR,
    CONTAINER_NAME, CONTAINER_LOG_PATH,
    CONTAINER_DOWNLOADS_PATH, CONTAINER_TTY_PATH, VANILLA_COWRIE_DIR
)
from menu.utils import (
    clear_screen, print_header, print_separator, pause,
    is_container_running
)
 
 
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

    # ── EXPORT CONTAINERISED LOGS (from staging_dir) ─────────────────────────────────
    # FIX 3: Check container state before attempting docker cp / docker exec.
    # If stopped, start it temporarily, copy files, then stop it again.
    # Previously the script blindly ran docker cp regardless of container state.
        # Simplified logic via stage_containerised_logs()
    # Container needs to be running for export. If we killswitch, we cannot re-access container without
    #   altering the logs produced. Therefore, we copy from staged  

    print(f"\n{Fore.CYAN}Exporting containerised honeypot...{Style.RESET_ALL}")
    container_count = 0
    if not STAGED_DIR.exists():
        print(f"{Fore.RED}No staged logs found{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Stop container manually to stage logs{Style.RESET_ALL}")
    else:
        for fname in ["cowrie.log", "cowrie.json"]:
            source = STAGED_DIR / fname
            if source.exists() and source.stat().st_size > 0:
                shutil.copy2(source, containerised_export_dir / fname)
                print(f"{Fore.GREEN}{fname} ({source.stat().st_size:}, bytes){Style.RESET_ALL}")
                container_count +=1
            else:
                print(f"{Fore.YELLOW}WARNING: {fname} not in staging{Style.RESET_ALL}")

        staged_download = STAGED_DIR / "downloads"
        containerised_download_export = containerised_export_dir / "downloads"
        containerised_download_export.mkdir(exist_ok=True)
        if staged_download.exists():
            download_files = list(staged_download.glob("*"))
            for x in download_files:
                shutil.copy2(x, containerised_download_export / x.name)
            count_str = f"{len(download_files)} file(s)" if download_files else "empty"
            colour = Fore.GREEN if dl_files else Fore.YELLOW
            print(f"{colour} downloads/ {(count_str)}{Style.RESET_ALL}")
            container_count += len(download_files)

        # Copy apparmor and its profiel
        for filename, label in [
            ("apparmor_denials.log", "AppArmor denials"),
            ("apparmor_profile.txt", "AppArmor profile"),]:
            source = STAGED_DIR / filename
            if source.exists() and source.stat().st_size > 0:
                shutil.copy2(source, containerised_export_dir / filename)
                print(f"{Fore.GREEN} {filename} ({label}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW} {filename} not in staging{Style.RESET_ALL}")
    # CLEAR STAGING DIRECTORY
    if STAGED_DIR.exists():
        shutil.rmtree(STAGED_DIR)
        print(f"{Fore.GREEN} Staging area cleared {Style.RESET_ALL}{(STAGED_DIR)}")

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
