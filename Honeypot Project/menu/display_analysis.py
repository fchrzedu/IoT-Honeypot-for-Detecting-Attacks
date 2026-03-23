from pathlib import Path
import json
import re
import sys
import os

import matplotlib
matplotlib.use("Agg") # write to file, no GUI
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


import pandas as pd
from colorama import Fore, Style

from menu.utils import clear_screen, print_header, print_separator, pause
from menu.utils_process_data import extract_sessions, extract_commands

sys.path.insert(0, str(Path(__file__).parent.parent))


# ------------------------------ HELPER FUNCS ------------------------------

def _save_figure_to_path(fig, path : Path, filename : str):
    """Save figures to path and close"""
    fig.savefig(path / filename, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"{Fore.GREEN}    Saved: {filename}{Style.RESET_ALL}")

def _shorten_label(cmd:str, max_len: int=25) -> str:
    """Shortens a command string to a readable chart label
    This gets updated depending on the commands a sample runs
    """
    cmd = cmd.strip()
    if len(cmd) <= max_len:return cmd
    return cmd[:max_len] + "..."


# ------------------------------ PHOTO GENERATION ------------------------------
def chart_session_duration(dir:Path, v_json_df:pd.DataFrame, c_json_df:pd.DataFrame, aa_df:pd.DataFrame):
    """Create barcharts based on session duration"""
    # Extract session information from both honeypots
    v_sesh = extract_sessions(v_json_df)
    c_sesh = extract_sessions(c_json_df)
    
    labels = ["Vanilla", "Containerised"]
    durations = [v_sesh["duration"].mean(), c_sesh["duration"].mean()]
    colours = ["#89cff0", "#FF474C"] # Baby blue for vanilla, light red for containerised
    # Define sizing & bars
    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(labels, durations, color=colours, width=0.5)
    # Combine each index value from bar and val into a tuple + add value above each bar
    for bar, val in zip(bars, durations):
        ax.text(
            bar.get_x() + bar.get_width() / 2, # Centers the label hotizontally
            bar.get_height() + 0.3, # Positions label just above the bar
            f"{val:1f}s", ha="center", fontsize=10
        )
    ax.set_label("Average session duration (seconds)")
    ax.set_title("Session Duration: Vanilla vs Containerised")
    ax.set_ylim(0, max(durations) * 1.5)    # Give headroom for labels
    fig.tight_layout()
    _save_figure_to_path(fig, dir, "01_session_duration.png")

def chart_command_timeline(dir:Path, v_json_df:pd.DataFrame, c_json_df:pd.DataFrame, aa_df:pd.DataFrame):
    v_cmds = extract_commands(v_json_df)
    c_cmds = extract_commands(c_json_df)

    if v_cmds.empty and c_cmds.empty:
        print(f"{Fore.YELLOW}    Skipped: 02_command_timeline.png (no commands){Style.RESET_ALL}")
        return

    v_sesh = extract_sessions(v_json_df)
    c_sesh = extract_sessions(c_json_df)

    v_time_zero = v_sesh["connect_time"].min() if not v_sesh.empty else v_cmds["timestamp"].min()
    c_time_zero = c_sesh["connect_time"].min() if not c_sesh.empty else c_cmds["timestamp"].min()

    # Compute elapsed secondes for each command from session connect
    # For each command, subtract its elapsed time from session connect
    v_data = [(elapsed, _shorten_label(row["input"]))
              for i, row in v_cmds.iterrows()
              for elapsed in [(row["timestamp"] - v_time_zero).total_seconds()]]
    c_data = [(elapsed, _shorten_label(row["input"]))
              for i, row in c_cmds.iterrows()
              for elapsed in [(row["timestamp"] - c_time_zero).total_seconds()]]
    # Create labels based off commands
    labels = [label for i, label in v_data]
    # If either honeypot has incorrect / different commands, handle the edge case
    for i, label in c_data:
        if label not in labels: labels.append(label)
    # Map each shortened label to its elapsed time
    v_lookup = {l: elapsed for elapsed, l in v_data}
    c_lookup = {label: elapsed for elapsed, label in c_data}
    # Build lists of bar lenngth in the order of labels = []
    v_times = [v_lookup.get(label, 0) for label in labels]
    c_times = [c_lookup.get(label, 0) for label in labels]
    # Number of command rows
    no = len(labels)
    # Integer (y) positions, one per row
    y = range(no)
    # each bar height
    bar_height = 0.40
    # Figure height scales with the number of commands so rows dont squash
    # max(..) ensures a minimum height
    fig, ax = plt.subplots(figsize=(13, max( 4, no * 1.2)))
    # Draw the bars
    v_bars = ax.barh(
        [i - bar_height / 2 for i in y],
        v_times,
        height=bar_height,
        color="#89cff0",
        label="Vanilla",
        zorder=3
    )
    # Containerised bars sit above the row centre (pos + bar_height / 2)
    c_bars = ax.barh(
        [i + bar_height / 2 for i in y],
        c_times,
        height=bar_height,
        color="#FF474C",
        label="Containerised",
        zorder=3
    )
    # Print labels within bars for vanilla honeypot
    for bar, val, label in zip(v_bars, v_times, labels):
        if val > 0:
            ax.text(
                val / 2,    # Align label horizontally on bar
                bar.get_y() + bar.get_height() / 2, # vertical center of bar
                _shorten_label(label),
                va="center", ha="center", 
                fontsize = 5, color="#1565C0",
                fontweight="bold" )
    for bar, val, label in zip(c_bars, c_times, labels):
        if val > 0:
            ax.text(
                val / 2,
                bar.get_y() + bar.get_height() / 2,
                 _shorten_label(label),
                 va="center", ha="center", 
                fontsize = 5, color="#B71C1C",
                fontweight="bold"                  
            )
    # Elapsed time
    for bar, val in zip(v_bars, v_times):
        if val > 0:
            ax.text(
                val + 0.5,
                bar.get_y() + bar.get_height() / 2,
                f"{val:.1f}s",
                va="center", fontsize=5, color="#1565C0"
            )
    for bar, val in zip(c_bars, c_times):
        if val > 0:
            ax.text(
                val + 0.5,
                bar.get_y() + bar.get_height() / 2,
                f"{val:.1f}s",
                va="center", fontsize=5, color="#B71C1C"
            )
        
    # Format axis
    ax.set_yticks(list(y)) # Replace integer y with command label for each row
    ax.set_yticklabels(labels, fontsize=5)

    ax.set_xlabel("Seconds since session start")
    ax.set_title("Attack Command Timing: Vanilla vs Containerised")

    ax.legend(loc="lower right", fontsize=6)
    ax.grid(axis="x", linestyle="--", alpha=0.4)

    ax.set_xlim(0, max(max(v_times), max(c_times)) * 1.1)

    fig.tight_layout()
    _save_figure_to_path(fig, dir, "02_command_timeline.png")

def chart_apparmor_overview(dir: Path, aa_df: pd.DataFrame):
    """Stacked horizontal bar chart, one bar per process stacked by operation
    Color coding separates cowrie startup noise (grey) vs malware actions (red)"""
    if aa_df.empty or "comm" not in aa_df.columns:
        print(f"    skipped: 03_apparmor_overview.png (no AppArmor data)")
        return

    # Define which processes are malware vs startup noise
    MALWARE_PROCS = {"bash", "cp"}

    # Get all unique processes and operations present in the data
    processes  = aa_df["comm"].unique().tolist()
    operations = aa_df["operation"].unique().tolist()
    # Colour each bar on operation
    OP_COLOURS = {
        # Two grey shared for cowrie & twistd (python) noise
        ("twistd", "mknod") : "#565656",
        ("twistd", "mknod") : "#9E9E9E",
        # Two red shades for malware
        ("bash", "mknod") : "#c82424",
        ("bash", "open") : "#dd4747",
        # CP is also malware (copy) - orange for this
        ("cp", "mknod") : "#FFA500",
        ("cp", "open") : "#FFC458",
    }
    fig, ax = plt.subplots(figsize=(9,5))
    # track left edge for each stacked segmnet per process
    left_bars = {process: 0 for process in processes}
    for o in operations:
        counts = []
        colours = []
        for p in processes:
            # Count denials matching this process + oepration
            count = len(aa_df[(aa_df["comm"] == p) & (aa_df["operation"] == o)])
            counts.append(count)
            colours.append(OP_COLOURS.get((p, o), "#757575"))
         # Draw x-axis bars, 1 per process
        bars = ax.barh(processes, counts, 
                       left=[left_bars[p] for p in processes],
                    color=colours, height=0.5, label=o, zorder=3)
        # Label each non-zero segment and its count
        for bar, count, proc in zip(bars, counts, processes):
            if count > 0:
                ax.text(
                    left_bars[proc] + count / 2, # horizontal bar alignment
                    bar.get_y() + bar.get_height() / 2,# vertical center
                    str(count),
                    va="center", ha="center",
                    fontsize=9, color="white", fontweight="bold"
                )
            left_bars[proc] += count
    
    # Add category label for right side of each bar
    for p in processes:
        category = "Malware action" if p in MALWARE_PROCS else "Cowrie startup noise"
        colour = "#E53935" if p in MALWARE_PROCS else "#757575"
        ax.text(
            left_bars[p] + 0.2,
            processes.index(p),
            category,
            va="center", fontsize=6, color=colour, style="italic"

        )

    ax.set_xlabel("No. of denials")
    ax.set_title("AppArmor denials by Process & Operation")
    ax.set_xlim(0, max(left_bars.values()) * 1.5) # headroom for labels

    # Manual legend for operation types
    legend_handles = [
        mpatches.Patch(color="#9E9E9E", label="mknod (create file)"),
        mpatches.Patch(color="#616161", label="open (read/write file)"),
    ]
    ax.legend(handles=legend_handles, fontsize=8, loc="lower right")
    ax.grid(axis="x", linestyle="--", alpha=0.4)
    fig.tight_layout()
    _save_figure_to_path(fig, dir, "03_apparmor_overview.png")

def chart_apparmor_blocked_paths(dir: Path, aa_df : pd.DataFrame):
    """
    Charts malware-relevant denials 
    broken down to the exact file path
    
    This shows exactly what AppArmor blocks and which persistence mechanisms
    """
    if aa_df.empty or "comm" not in aa_df.columns:
        print(f"    skipped: 04_apparmor_blocked_paths.png (no AppArmor data)")
        return
    # processes
    MALWARE_PROCS = {"bash", "cp"}
    # Filter to only malware denials
    # Copy the process from aa_df if in aa_df and of type comm
    malware_df = aa_df[aa_df["comm"].isin(MALWARE_PROCS).copy()]
    if malware_df.empty:
        print(f"    skipped: 04_apparmor_blocked_paths.png (no denials data)")
    if"name" not in malware_df.columns:
        print(f"    skipped: 04_apparmor_blocked_paths.png (no path data)")

    path_counts = malware_df["name"].value_counts()

    # assign colour per path
    PATH_COLOURS = {
        "/usr/bin/.sh":      "#FB8C00",   # orange — binary copy
        "/etc/init.d/sysd":  "#E53935",   # red    — SysV init
        "/etc/rc.local":     "#8E24AA",   # purple — rc.local boot
        "/dev/tty":          "#00897B",   # teal   — terminal access
    }
    bar_colours = [PATH_COLOURS.get(p, "#757575") for p in path_counts.index]
    fig, ax = plt.subplots(figsize=(10, max(3, len(path_counts) * 1)))

    bars = ax.barh(
        path_counts.index, path_counts.values,
        color=bar_colours, height=0.5, zorder=3
    )
    ax.set_xlabel("Number of denial events")
    ax.set_title("AppArmor: Malware Persistence Paths Blocked")
    ax.set_xlim(0, path_counts.max() * 1.5)
    ax.grid(axis="x", linestyle="--", alpha=0.4)

    # Legend explaining the colour coding by persistence mechanism
    legend_handles = [
        mpatches.Patch(color="#FB8C00", label="/usr/bin/.sh — binary persistence"),
        mpatches.Patch(color="#E53935", label="/etc/init.d/sysd — SysV init"),
        mpatches.Patch(color="#8E24AA", label="/etc/rc.local — boot execution"),
        mpatches.Patch(color="#00897B", label="/dev/tty — terminal access"),
    ]
    ax.legend(handles=legend_handles, fontsize=8, loc="lower right")
    fig.tight_layout()
    _save_figure_to_path(fig, dir, "04_apparmor_blocked_paths.png")


# ------------------------------ MAIN FUNC TO GENERATE CHARTS ------------------------------
def generate_charts(dir: Path, v_json_df: pd.DataFrame, c_json_df: pd.DataFrame, aa_df : pd.DataFrame):
    """Entry point called from process_data.py
    Creates charts/ subdir in results/ and generates all PNG charts"""
    charts_dir = dir / "charts"
    charts_dir.mkdir(exist_ok=True) # Create directory called charts
    
    print(f"{Fore.GREEN}   Visualising analysis...{Style.RESET_ALL}")
    # Call relevant functions to generate charts
    chart_session_duration(charts_dir, v_json_df, c_json_df, aa_df) #01
    chart_command_timeline(charts_dir, v_json_df, c_json_df, aa_df) #02
    chart_apparmor_overview(charts_dir, aa_df)
    chart_apparmor_blocked_paths(charts_dir, aa_df)
