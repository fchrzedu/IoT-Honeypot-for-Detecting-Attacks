# firejail profile for cowrie inside docker
# restricts cowrie access to system resources

include /etc/firejail/globals.local

# deny access to kernel-sensitive files and directoties
blacklist /boot
blacklist /sys/kernel
blacklist /proc/sys
blacklist /proc/kcore
blacklist /proc/mem
blacklist /proc/kmem

# no access to user sensitive data
blacklist /root
blacklist ~/.ssh
blacklist ~/.gnupg
blacklist ~/.git

# restrict filesystem access to neccesary cowrie directories
private-dev
private-tmp
private-etc passwd,shadow,group,hostname,hosts,resolv.conf

# whitelist only cowrie dirs
whitelist /home/cowrie/cowrie/var
whitelist /home/cowrie/cowrie/etc
whitelist /home/cowrie/cowrie/cowrie-env

# no binary execution
noexec /home/cowrie/cowrie/var/log
noexec /home/cowrie/cowrie/var/lin
noexec /tmp

# drop dangerous privs
caps.drop all
caps.keep setgid,setuid,net_bind_services

# memory protection
memory-deny-write-execute

#restrict system calls via syscalls seccomp

#no network access
net none
# localhost only
net lo
# only on interface ethernet0
net eth0

# disable user namespaces
restrict-namespaces

# prevent ptrace operations
disable-mnt
nopivot

# eliminate IPC (inter process comms)
dbus-user none
dbus-system none

# resource limits for DoS
rlimit-nofile 4096
rlimit-nproc 256


