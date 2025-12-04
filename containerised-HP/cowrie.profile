# firejail profile for cowrie inside docker
# restricts cowrie access to system resources

include /etc/firejail/globals.local

net lo

whitelist /tmp/firejail-tmp
whitelist /run/firejail
whitelist /var/cache/firejail
whitelist /home/cowrie/.cache/firejail

writeable-var
writeable-tmp

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
whitelist /usr/lib/python3*
whitelist /usr/share/python3*

# no binary execution
noexec /home/cowrie/cowrie/var/log
noexec /home/cowrie/cowrie/var/lin
noexec /tmp

# drop dangerous privs
caps.drop all
caps.keep setgid,setuid,net_bind_services

# seccomp filtering
#permit most syscalls, prevent dangerous ones
seccomp.blacklist ptrace,process_vm_readv,process_vm_writev,kexec_load,kexec_file_load,bpf,userfaultfd,perf_event_open

# memory protection
memory-deny-write-execute

#restrict system calls via syscalls seccomp
restrict-namespaces

# prevent ptrace
disable-mnt
nopivot

# elimiate IPC
dbus-user none
dbus-systen none

# resource limits for DoS
rlimit-nofile 4096
rlimit-ncproc 256
