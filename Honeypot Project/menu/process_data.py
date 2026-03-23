from pathlib import Path
import json
import re
import sys
import os
import time

import matplotlib.pyplot as plt


import pandas as pd
from colorama import Fore, Style
from menu.utils_process_data import extract_commands, extract_downloads, extract_sessions, extract_aa_denials, extract_seccomp_bpf
from menu.utils import clear_screen, print_header, print_separator, pause
from menu.display_analysis import generate_charts
sys.path.insert(0, str(Path(__file__).parent.parent))

RESULTS_DIR = Path(__file__).parent.parent / "results"

# https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
# https://syscalls.mebeim.net/?table=x86/64/x64/latest
# Also built from common syscall logs reviewed over + researched
#    and after examining the syscalls produced from different malware samples
SYSCALL_NAMES = {
    "11" : "execve",
    "192":"nmap2",
    "45":"brk",
    "54":  "ioctl",
    "102": "socketcall",
    "119": "sigreturn",
    "90":  "mmap",
    "125": "mprotect"
}

# ------------------------------ DIRECTORY DISCOVERY ------------------------------
def find_dirs():
    dirs = []
    # Iterate through results/
    for dir_found in sorted(RESULTS_DIR.iterdir()):
        # Skip if _staged or not a dir/
        if not dir_found.is_dir() or dir_found.name.startswith("_"):
            continue
        # Elect directory as directory_path/vanilla for vanilla-honeypot results
        vanilla_dir = (dir_found / "vanilla").is_dir()
        containerised_dir = (dir_found / "containerised").is_dir()
        
        #If we've found both result dirs
        if vanilla_dir and containerised_dir:
            dirs.append(dir_found)
    return dirs


# ------------------------------ LOG PARSING ------------------------------
def parse_aa_log(path: Path) -> pd.DataFrame:
    # audit.log is in the format key:value pairs, unlike JSON strings
    if not path.exists() or path.stat().st_size == 0: return pd.DataFrame()

    rows = []

    with open(path, "r") as file:
        for line in file:
            line = line.strip()
            if not line: continue
            # Create var for current row of data
            current_row = {}
            # If the current log is not SECCOMP or AVC, skip
            if not line.startswith("type=AVC") and not line.startswith("type=SECCOMP"): continue
            # Extract the log type: logs start with type=AVC msg=audit(......)
            # Split line on whitespaces, take the first word (type=..), 
            # Split that word on '=' and take the 1st value (not Type but rather AVC/SECCOMP)
            current_row["type"] = line.split()[0].split("=")[1]

            # Extract the audit timestamp from msg=audit(........:####), where timestamp is unix time in ms
            if "audit(" in line:
                # Split on audit( and store timestamp: i.e 12341231312.456              
                # Convert data to approriate format
                audit_part = line.split("audit(")[1].split(")")[0]
                # Take the first part (timestamp + ID), split on timestamp to get time and ID
                timestamp_part, audit_id = audit_part.split(":")
                current_row["timestamp_part"] = float(timestamp_part)
                current_row["audit_id"] = float(audit_id)

            # Extract all key:value pairs after type, timestamp and audit ID
            for part in line.split():# Split all remaining data
                if "=" in part and not part.startswith("type=") and not part.startswith("msg="):
                    # Split data before '=' and after '=', retaning the middle value
                    key, index, value = part.partition("=")
                    current_row[key.strip()] = value.strip().strip('"')
                if current_row: rows.append(current_row)
    if not rows: return pd.DataFrame()

    # Convert timestamp to UTC in seconds
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp_part"], unit="s", utc=True)
    # Drop all duplicate audit events
    if "audit_id" in df.columns:
        df = df.drop_duplicates(subset=["audit_id"])
    return df.sort_values("timestamp").reset_index(drop=True)

def parse_cowrie_json(path: Path) -> pd.DataFrame:
    # Parse in path to cowrie.log as Path, and return as pandas dataframe
    if not path.exists() or path.stat().st_size == 0: return pd.DataFrame()
    
    records = []

    with open(path, "r") as file:
        for line in file:
            line = line.strip()
            if line:
                try: records.append(json.loads(line))
                except: pass
    if not records: return pd.DataFrame()
    dataframe = pd.DataFrame(records)
    dataframe["timestamp"] = pd.to_datetime(dataframe["timestamp"], utc=True)
    return dataframe.sort_values("timestamp").reset_index(drop=True)


# Parse in path to cowrie.log as Path, and return as pandas dataframe
def parse_cowrie_log(path: Path) -> pd.DataFrame:
    # If not exist or path's metadata says size is 0 bytes
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    
    rows = []
    with open(path, "r") as file:
        for line in file:
            if not line: continue
            parts = line.split(" ", maxsplit=2)
            if len(parts) != 3: continue
            # Validate whether the timestamp looks like a timestamp, 
            if not parts[0].startswith("20"): continue            
            rows.append({                   
                "timestamp": parts[0],
                "session" : parts[1],
                "message" : parts[2],})
    if not rows: return pd.DataFrame()
    
    # Convert list to dataframe
    dataframe = pd.DataFrame(rows)
    # Convert timestamps from enoch to UTC (consistent w/ honeypots) 
    dataframe["timestamp"] = pd.to_datetime(dataframe["timestamp"], utc=True)
    # Return dataframe sorted by timestamp, and reset index of this dataframe
    return dataframe.sort_values("timestamp").reset_index(drop=True)


    

# ------------------------------ CROSS EXAMINATION ------------------------------
def cross_check(json_df: pd.DataFrame, log_df: pd.DataFrame) -> dict:
    # Check whether cowrie.json & cowrie.log agree on command count
    json_cmd_count = len(json_df[json_df["eventid"] == "cowrie.command.input"])
    log_cmd_count = len(log_df[log_df["message"].str.startswith("CMD")])
    
    return {
        "json_command_count" : json_cmd_count,
        "log_command_count" : log_cmd_count,
        "agree_flag" : json_cmd_count == log_cmd_count
    }

def compare_data(v_df: pd.DataFrame, c_df: pd.DataFrame) -> dict:
    # Compares vanilla.json against containerised.json
    # Returns dict of findings

    # Extract comamnds for vanilla and cowrie json file
    v_cmd = extract_commands(v_df)
    c_cmd = extract_commands(c_df)
    # Extract downloads for vanilla and cowrie json
    v_dls = extract_downloads(v_df)
    c_dls = extract_downloads(c_df)
    # Extract sessions ......
    v_sesh = extract_sessions(v_df)
    c_sesh = extract_sessions(c_df)
    # Store hashes in a set for enumeration
    v_hashes = set(v_dls["shasum"].dropna())    # Drop any NULL
    c_hashes = set(c_dls["shasum"].dropna())

    # Return a dictionary of comparison results
    return{
        "vanilla_session_count" : len(v_sesh),
        "containerised_session_count" : len(c_sesh),
        "vanilla_average_duration" : v_sesh["duration"].mean(),
        "containerised_average_duration": c_sesh["duration"].mean(),
        "vanilla_cmd_count": len(v_cmd),
        "containerised_cmd_count" : len(c_cmd),
        "commands_match": set(v_cmd["input"]) == set(c_cmd["input"]),
        "hashes_match": c_hashes == v_hashes,
        "shared_hashes": c_hashes & v_hashes,
        "vanilla_only_hashes": v_hashes - c_hashes,
        "containerised_only_hashes": c_hashes - v_hashes,
        "vanilla_cmds" : v_cmd,
        "containerised_cmds": c_cmd,
    }
    

def print_cross_check(label: str, results:dict):
    agree_flag = (f"{Fore.GREEN}TRUE{Style.RESET_ALL}" if results["agree_flag"]
                  else f"{Fore.RED}FALSE{Style.RESET_ALL}")
    print(f"    {label:<16} json={results['json_command_count']}" f" log={results['log_command_count']} {agree_flag}")


def analyse_aa_seccomp_denials(aa_df : pd.DataFrame, seccomp_df : pd.DataFrame) -> dict:
    # Analyse both seccomp and apparmor logs on operation and which process, return results as dict
    aa_by_operation = {}
    aa_by_process = {}
    seccomp_by_syscall = {}
    seccomp_by_process = {}

    if not aa_df.empty:
        # If operation flag exists in apparmor logs, extract it
        if "operation" in aa_df.columns:
            aa_by_operation = aa_df["operation"].value_counts().to_dict()
        # Do the same for process
        if "comm" in aa_df.columns:
            aa_by_process = aa_df["comm"].value_counts().to_dict()

    if not seccomp_df.empty:
        if "syscall" in seccomp_df.columns:
            seccomp_by_syscall = seccomp_df["syscall"].value_counts().to_dict()
        if "comm" in seccomp_df.columns:
            seccomp_by_process = seccomp_df["comm"].value_counts().to_dict()
    return{
        "aa_total" : len(aa_df),
        "seccomp_total" : len(seccomp_df),
        "aa_by_operation" : aa_by_operation,
        "aa_by_process" : aa_by_process,
        "seccomp_syscall" : seccomp_by_syscall,
        "seccomp_by_process" : seccomp_by_process,
        "aa_rows" : aa_df,
        "seccomp_rows" : seccomp_df}

# ------------------------------ DISPLAY LOG SUMMARY ------------------------------
def display_summary(label:str, json_df: pd.DataFrame, log_df: pd.DataFrame):
    # Display the unique counts as a summary for either log
    print(f"\n{Fore.CYAN}{label} Honeypot{Style.RESET_ALL}")
    print_separator()

    print(f"{Fore.GREEN}cowrie.json {len(json_df)} events{Style.RESET_ALL}")
    event_counter = json_df["eventid"].value_counts()
    for event_type, count in event_counter.items():
        print(f"    {count:>4} {event_type}")

    print(f"    {Fore.GREEN}cowrie.log {len(log_df)} lines{Style.RESET_ALL}")

def print_comparison(results : dict):
    print(f"\n{Fore.CYAN}SESSION COMPARISON{Style.RESET_ALL}")
    print_separator()

    # Print session count & average duration
    print(f"    Vanilla:    {results['vanilla_session_count']} session(s)")
    print(f"        average duration {results['vanilla_average_duration']:.1f}s")
    print(f"    Containerised:    {results['containerised_session_count']} session(s)")
    print(f"        average duration {results['containerised_average_duration']:.1f}s")

    # Print command comparison
    print(f"\n{Fore.CYAN}COMMAND COMPARISON{Style.RESET_ALL}")
    print_separator()
    print(f"    Vanilla:    {results["vanilla_cmd_count"]} command event(s)")
    print(f"    Containerised:  {results["containerised_cmd_count"]} command event(s)")    
    match_string_comms = (f"{Fore.GREEN}TRUE{Style.RESET_ALL}" if results["commands_match"] else f"{Fore.RED}FALSE{Style.RESET_ALL}")
    print(f"    Do commands match : {match_string_comms}")

    # Print details of commands
    print(f"\n{Fore.CYAN}COMMAND DETAILS{Style.RESET_ALL}")
    print_separator()
    # iterate through the extracted comms --> row and column
    # Print label + the session ID aligned to the left + timestamp aligned to the left + truncated command up to 100 chars
    print(f"    {'SESSION':<14} {'TIMESTAMP':<32} COMMAND")
    for _, row in results["vanilla_cmds"].iterrows():
        print(f"    [Vanilla] {row['session']:<10} {str(row['timestamp']):<32} {row['input'][:100]}")
    for _, row in results["containerised_cmds"].iterrows():
        print(f"    [Containerised] {row['session']:<10} {str(row['timestamp']):<32} {row['input'][:100]}")
    
    # Print comparison of downloaded content
    print(f"\n{Fore.CYAN}DOWNLOADS DETAILS{Style.RESET_ALL}")
    print_separator()
    # Create green or red label if downloads_vanilla == downloads_container or downloads_vanilla != downloads_container
    hash_string = (f"{Fore.GREEN}TRUE{Style.RESET_ALL}" if results["hashes_match"] else f"{Fore.RED}FALSE{Style.RESET_ALL}")
    print(f"    Hashes match:   {hash_string}")
    print(f"    Shared hashes:  {len(results["shared_hashes"])}")

    if results["vanilla_only_hashes"]:
        print(f"{Fore.YELLOW}Vanilla honeypot hashes:{Style.RESET_ALL}")
        for hash in results["vanilla_only_hashes"]:
            print(f"    {hash}")
    
    if results["containerised_only_hashes"]:
        print(f"{Fore.YELLOW}Containerised honeypot hashes:{Style.RESET_ALL}")
        for hash in results["containerised_only_hashes"]:
            print(f"    {hash}")


def print_denials(results:dict):
    print(f"\n{Fore.CYAN}APPARMOR DENIALS{Style.RESET_ALL}")
    print_separator()
    # Print total denials, and the denial itself
    print(f"Total denials: {results['aa_total']}")
    if results['aa_by_operation']:
        print(f"\nBy Operation:")
        for op, i in results['aa_by_operation'].items():
            print(f"    {i:>4} {op}")
    
    # Print the process causing denial
    if results['aa_by_process']:
        print(f"\n    Detail:")
        print(f"\n    {'TIMESTAMP':<32} {'OPERATION':<10} {'PROCESS':<10} PATH")
        # Iterate through all rows and print time, operation, command and name
        for i, row in results["aa_rows"].iterrows():
            timestamp = str(row.get("timestamp", ""))[:32]
            op = str(row.get("operation", ""))[:10]
            comm = str(row.get("comm", ""))[:10]
            name = str(row.get("name", ""))[:50]
            print(f"    {timestamp:<32} {op:<10} {comm:<8} {name}")
    
    # Print seccomp details
    print(f"\n{Fore.CYAN}SECCOMP DENIALS{Style.RESET_ALL}")
    print_separator()

    # Print total SECCOMP denials
    print(f"Total denials: {results['seccomp_total']}")
    if results["seccomp_syscall"]:
        print(f"\n By Operation: ")
        for op, c in results['seccomp_syscall'].items():
            name = SYSCALL_NAMES.get(op, "unknown")
            print(f"    {c:>4} syscall {op} ({name})")
        if results["seccomp_by_process"]:
            print(f"\n By process:")
            for p, c in results['seccomp_by_process'].items():
                print(f"    {c:>4} {p}")


# ------------------------------ MAIN ANALYSIS ------------------------------
def run_analysis():
    clear_screen()
    print_header("Analysis")

    # Find all directories with results
    dirs_found = find_dirs()
    if not dirs_found:
        print(f"{Fore.RED}ERROR: No experiments found in: {Style.RESET_ALL} {RESULTS_DIR}")
        pause()
        return
    # Print directories and cancel option
    print(f"{Fore.CYAN}Available experiments:\n{Style.RESET_ALL}")
    for index, dir in enumerate(dirs_found):
        print(f"    [{index+1}] {dir.name}")
    print(f"{Fore.YELLOW}    [0] Cancel{Style.RESET_ALL}")

    choice = input(f"{Fore.CYAN}Select experiment: {Style.RESET_ALL}")
    if choice == "0":
        return
    try:
        chosen_result_dir = dirs_found[int(choice) - 1]
        print(f"{Fore.CYAN}Analysing: {Style.RESET_ALL}{chosen_result_dir.name}")
    except:
        print(f"{Fore.RED}Invalid selection{Style.RESET_ALL}")
        pause()
        return
    pause()
    clear_screen()
    print_header(f"RESULTS: {Style.RESET_ALL}{chosen_result_dir.name}")

    # Get the directories for all the files for analysis
    # cowrie.json
    vanilla_json = chosen_result_dir / "vanilla" / "cowrie.json"
    containerised_json = chosen_result_dir / "containerised" / "cowrie.json"
    # Cowrie.log
    vanilla_cowrie_log = chosen_result_dir / "vanilla" / "cowrie.log"
    containerised_cowrie_log = chosen_result_dir / "containerised" / "cowrie.log"
    
    # /var/log/audit/audit.log
    aa_log_path = chosen_result_dir / "containerised" / "apparmor_denials.log"

    vanilla_json_dataframe = parse_cowrie_json(vanilla_json)
    vanilla_cowrie_dataframe = parse_cowrie_log(vanilla_cowrie_log)
    containerised_json_dataframe = parse_cowrie_json(containerised_json)
    containerised_cowrie_dataframe = parse_cowrie_log(containerised_cowrie_log)

    if vanilla_json_dataframe.empty or containerised_json_dataframe.empty:
        print(f"{Fore.RED}ERROR: One or both cowrie(.json)(.log) files are missing or empty.{Style.RESET_ALL}")
        pause()
        return
    
    # Display the summary of the extracted json and log files
    display_summary("Vanilla", vanilla_json_dataframe, vanilla_cowrie_dataframe)
    display_summary("Containerised", containerised_json_dataframe, containerised_cowrie_dataframe)
    
    # Cross examine the contents of both cowrie.json files
    # No need to examine .log, as cowrie.log is for human readability + ,json has the actual data
    print(f"\n{Fore.CYAN}    LOG CROSS-EXAMINATION{Style.RESET_ALL}")
    print_separator()
    print("Containerised.json == Vanilla.json?")
    if not vanilla_cowrie_dataframe.empty:
        print_cross_check("Vanilla", cross_check(vanilla_json_dataframe, vanilla_cowrie_dataframe))
    if not containerised_cowrie_dataframe.empty:
        print_cross_check("Containerised", cross_check(containerised_json_dataframe, containerised_cowrie_dataframe))
       
    # Comparison between dataframes
    results = compare_data(vanilla_json_dataframe, containerised_json_dataframe)
    print_comparison(results)

    # Process AppArmor & Seccomp log data
    apparmor_data_frame = parse_aa_log(aa_log_path)
    if apparmor_data_frame.empty:
        print(f"{Fore.Yellow}No AppArmor / Seccomp logs found. Are you sure you ran the third test?{Style.RESET_ALL}")
    else:
        apparmor_denials = extract_aa_denials(apparmor_data_frame)
        seccomp = extract_seccomp_bpf(apparmor_data_frame)
        denial_results = analyse_aa_seccomp_denials(apparmor_denials, seccomp)
        print_denials(denial_results)


    # Call display_analysis to generate png photos
    # Generate charts, and if AA is empty, send in an empty dataframe
    generate_charts(chosen_result_dir, vanilla_json_dataframe, containerised_json_dataframe, 
                    apparmor_denials if not apparmor_denials.empty else pd.DataFrame())

    
    pause()
    
    
