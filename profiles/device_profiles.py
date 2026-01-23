DEVICE_PROFILES = {
    "dlink_dcs5020l_camera": {
        # Fields were derived from Shodan and OpenWRT reverse engineering for a D-Link IP Camera
        # Certain fields had to be safely assumed due to info not being publicly accessible i.e. SSH banner, uname output etc
        # https://openwrt.org/toh/d-link/d-link_dcs-5020l_a1?s[]=dcs&s[]=5020l
        # https://www.shodan.io/host/73.227.106.199

        # ============================
        # DEVICE IDENTIFICATION
        # ============================
        "name": "D-Link DCS-5020L IP Camera",
        "manufacturer": "D-Link",
        "model": "DCS-5020L",
        "hardware_version": "A",
        "firmware_version": "1.16",
        "device_type": "IP Camera",

        # ============================
        # HARDWARE SPECIFICATIONS
        # ============================
        "cpu": "Ralink RT3352",
        "cpu_mhz": "400",
        "architecture": "mipsel",
        "ram_mb": "64",
        "flash_mb": "8",

        # ============================
        # SYSTEM INFORMATION
        # ============================
        "kernel_version": "2.6.21",
        "hostname": "DCS-5020L",

        # SSH banner (deduced from 2013 camera release & Dropbear timeline)
        "ssh_banner": "SSH-2.0-dropbear_2013.58",

        # uname -a output (constructed from kernel + arch + build date)
        "uname_output": "Linux DCS-5020L 2.6.21 #1 Wed Aug 10 18:35:44 CST 2013 mipsel GNU/Linux",

        # /proc/cpuinfo - also assumed and built from examples online
        "cpuinfo": """system type\t\t: Ralink RT3352
processor\t\t: 0
cpu model\t\t: MIPS 24KEc V4.12
BogoMIPS\t\t: 265.42
wait instruction\t: yes
microsecond timers\t: yes
tlb_entries\t\t: 32
extra interrupt vector\t: yes
hardware watchpoint\t: yes
ASEs implemented\t: mips16 dsp
shadow register sets\t: 1
core\t\t\t: 0
VCED exceptions\t\t: not available
VCEI exceptions\t\t: not available""",

        # ============================
        # OPERATIONAL DATA
        # ============================
        "available_commands": [
            "ls", "cat", "echo", "ps", "kill",
            "busybox", "sh", "mount", "umount",
            "ifconfig", "ping", "wget", "reboot"
        ],

        "shell_prompt": "# ",

        # Network info
        "mac_prefix": "B0:C5:54",

        # HTTP Server (From shodan)
        "http_server": "alphapd/2.1.8",

        # ========================================
        # DOCUMENTATION & VALIDATION
        # ========================================
        "research_sources": {
            "shodan": "https://www.shodan.io/host/73.227.106.199",
            "openwrt": "https://openwrt.org/toh/d-link/d-link_dcs-5020l_a1",
            "confirmed_fields": [
                "manufacturer", "model", "hardware_version",
                "firmware_version", "cpu", "ram_mb", "flash_mb"
            ],
            "deduced_fields": [
                "ssh_banner (from Dropbear 2013 timeline)",
                "kernel_version (from ALSA 1.0.14rc3 + RT3352 SDK)",
                "architecture (RT3352 = mipsel standard)",
                "cpuinfo (RT3352 datasheet + MIPS 24KEc specs)"
            ]
        },

        "testing_priority": "high",  # Common IoT target, well-documented malware exists
    },



# ===========================================================================================================================================================




    "tplink_archer_a7_router": {     
            # ============================
            # DEVICE IDENTIFICATION
            # ============================
          "name": "TP Link Archer A7 v5 Router",
          "manufacturer": "TP-Link",
          "model": "Archer A7 v5",
          "hardware_version": "5.0", # Unable to find hardware version, used '5.0' from v5
          "firmware_version": "v3.0-r43502",
          "device_type": "MIPS Router",

            # ============================
            # HARDWARE SPECIFICATIONS
            # ============================
            "cpu": "Qualcomm Atheros QCA9563",
            "cpu_mhz": "750",
            "architecture": "mips",
            "ram_mb": "128",
            "flash_mb": "16",
            # ============================
            # SYSTEMS SPECIFICATIONS
            # ============================
            # Reasoning: "Firmware v3.0-r43502" released June 2020
            # Firmware 2020 -> OpenWRT, looked for release closest: Feb 2021 21.02 Linux 5.4
            # June 2020 suggests transition period from Feb -> June: 5.4.188
            "kernel_version": "5.4.188", 
            "hostname": "OpenWrt",  # Standard OpenWRT hostname, user conf so doesn't matter
            "ssh_banner": "SSH-2.0-dropbear_2020.79",
            # Reasoning:
            # - Hostname: OpenWrt (standard)
            # - Kernel: 5.4.188 (OpenWrt 21.02 series)
            # - Build date: Mon Jun 23 (firware date 06/23/20)
            # - Architecture: mips 
            "uname_output": "Linux OpenWrt 5.4.188 #0 SMP Mon Jun 23 10:15:42 2020 Mips GNU/Linux",
            # /proc/cpuinfo (QCA9563 standard output)
            "cpuinfo": """system type\t\t: Qualcomm Atheros QCA956X rev 0
                machine\t\t\t: TP-Link Archer A7 v5
                processor\t\t: 0
                cpu model\t\t: MIPS 74Kc V5.0
                BogoMIPS\t\t: 373.33
                wait instruction\t: yes
                microsecond timers\t: yes
                tlb_entries\t\t: 32
                extra interrupt vector\t: yes
                hardware watchpoint\t: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
                isa\t\t\t: mips1 mips2 mips32r1 mips32r2
                ASEs implemented\t: 
                shadow register sets\t: 1
                kscratch registers\t: 0
                package\t\t\t: 0
                core\t\t\t: 0
                VCED exceptions\t\t: not available
                VCEI exceptions\t\t: not available""",
                # ============================
                # OPERATIONAL DATA
                # ============================
                    "available_commands": [
                        "ls", "cat", "echo", "ps", "kill", "top",
                        "busybox", "sh", "mount", "umount", "df",
                        "ifconfig", "ping", "wget", "curl", "reboot",
                        "iptables", "uci", "opkg"  # OpenWRT-specific commands
                    ],
                "shell_prompt": "root@OpenWrt:~# ",
                
                # Network info
                "mac_prefix": "68:FF:7B", # Shodan OUI

                # HTTP Server IF applicable, routers usually have web UI
                "http_server": "uhttpd",    # OpenWrt standard
                # ========================================
                # DOCUMENTATION & VALIDATION
                # ========================================
                "research_sources": {
        "shodan": "https://www.shodan.io/host/73.112.241.251",
        "openwrt": "https://openwrt.org/toh/tp-link/archer_a7_v5",
        "confirmed_fields": [
            "manufacturer", "model", "ssh_banner",
            "firmware_version", "cpu", "ram_mb", "flash_mb", "architecture"
        ],
        "deduced_fields": [
            "kernel_version (from firmware date June 2020 → OpenWRT 21.02 → Linux 5.4)",
            "hardware_version (v5 from model name)",
            "cpuinfo (QCA9563 datasheet + MIPS 74Kc specs)"
        ]
    },
    
    "testing_priority": "high"    
                
          
    }

}







# ============================================
#	Helper Functions
# ============================================


# Returns a random device profile from DEVICE_PROFILES above
def get_random_profile():
    import random
    profile_name = random.choice(list(DEVICE_PROFILES.keys()))
    return profile_name, DEVICE_PROFILES[profile_name]

# Returns a profile based on its name
def get_profile_by_name(name):
	return DEVICE_PROFILES.get(name, None)


# ============================================
# Testing Function
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("DEVICE PROFILE CATALOGUE - VALIDATION TEST")
    print("=" * 70)
    print(f"\n✓ Total profiles loaded: {len(DEVICE_PROFILES)}")
    
    for profile_id, profile in DEVICE_PROFILES.items():
        print("\n" + "-" * 70)
        print(f"[{profile_id}]")
        print(f"  Name: {profile['name']}")
        print(f"  Architecture: {profile['architecture']}")
        print(f"  SSH Banner: {profile['ssh_banner']}")
        print(f"  Kernel: {profile['kernel_version']}")
    
    print("\n" + "=" * 70)
    print("VALIDATION COMPLETE")
    print("=" * 70)
