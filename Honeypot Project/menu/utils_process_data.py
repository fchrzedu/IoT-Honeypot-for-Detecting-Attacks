import pandas as pd

# ------------------------------ DATA EXTRACTION ------------------------------
# Each extraction filter was produced from manually examining the .json logs
def extract_commands(df: pd.DataFrame) -> pd.DataFrame:
    # Create boolean mask. only lines marked cowrie.command.input are true
    mask = df["eventid"] == "cowrie.command.input"
    # (1) Only keep rows that match true to the mask
    # (2) Selects only the three columns
    return df[mask][["session", "timestamp", "input"]].reset_index(drop=True)

def extract_downloads(df: pd.DataFrame) -> pd.DataFrame:
    # Create boolean mask for cowrie.session.file_download
    mask = df["eventid"] == "cowrie.session.file_download"
    columns = [c for c in ["session", "timestamp", "url", "shasum"] if c in df.columns]
    return df[mask][columns].reset_index(drop=True)

def extract_sessions(df: pd.DataFrame) -> pd.DataFrame:
    connecting = df[df["eventid"] == "cowrie.session.connect"][["session", "timestamp", "src_ip"]].rename(columns={"timestamp": "connect_time"})
    closed_session = df[df["eventid"] == "cowrie.session.closed"][["session", "duration"]].copy()

    closed_session["duration"] = pd.to_numeric(closed_session["duration"], errors="coerce")
    return connecting.merge(closed_session, on="session", how="left")

def extract_aa_denials(aa_df : pd.DataFrame) -> pd.DataFrame:
    # If logs are empty, or no 'type' (AVC) exists, return empty
    if aa_df.empty or "type" not in aa_df.columns: return pd.DataFrame()
    filt = aa_df["type"] == "AVC"
    # Iterate through all possible AVC columns and for each column that matches log, set true
    cols = [c for c in ["timestamp","operation", "name", "comm", "profile", "requested_mask", "denied_mask"]
               if c in aa_df.columns]
    return aa_df[filt][cols].reset_index(drop=True)

def extract_seccomp_bpf(seccomp_df : pd.DataFrame) -> pd.DataFrame:
    # If logs are empty, or no 'type' (SECCOMP) exists, return empty
    if seccomp_df.empty or "type" not in seccomp_df.columns: return pd.DataFrame()
    filt = seccomp_df["type"] == "SECCOMP"
    cols = [c for c in ["timestamp", "syscall", "comm", "sig", "exe"]
            if c in seccomp_df.columns]
    return seccomp_df[filt][cols].reset_index(drop=True)
