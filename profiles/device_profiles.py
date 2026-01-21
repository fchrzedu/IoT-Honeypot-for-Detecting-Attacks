# Device profile catalogue for IoT devices


"dlink_csc5020l_camera":{
# Fields were derived from Shodan and OpenWRT reverse engineering for a D-Link IP Camera
# Certain fields had to be safely assumed due to info not being publically accessible i.e. SSH banner, uname output etc
# https://openwrt.org/toh/d-link/d-link_dcs-5020l_a1?s[]=dcs&s[]=5020l
# https://www.shodan.io/host/73.227.106.199

	# ============================
	# DEVICE IDENTIFICATION
	# ============================

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
	"ram_mb": "64"	# Technically 64 MiB but MB is fine
	"flash_mb": "8",

	# ============================
        # SYSTEM INFORMATION
        # ============================
	"kernel version": "2.6.21",
	"hostname": "DCS-5020L",

	# SSH banner (deduced from 2013 camera release & Dropbear timeline, identified via dropbear_2013.xx
	"ssh_banner": "SSH-2.0-dropbear_2013.58",

	#uname -a output (constructed from kernel + arch + build date)
	"uname_output": "Linux DCS-5020L 2.6.1 #1 wed Aug 10 18:35:44 CST 2013 mipsel GNU/Linux",

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
	"mac_prefix": "B0:C6:54",	# All D-Link cameras on shodan.io have a OUI of B0:C6:54

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
    
    "validation_notes": """
    Profile based on:
    1. Shodan reconnaissance (MAC, firmware, model)
    2. OpenWRT hardware database (CPU, RAM, bootlog)
    3. Ralink RT3352 technical specifications
    4. Dropbear release timeline (2013.58 for mid-2013 device)
    5. Standard MIPS kernel output formats
    
    Confidence level:
    - All hardware specs confirmed
    - System outputs follow documented RT3352 patterns
    - SSH banner consistent with device release timeline
    """,
    
    "testing_priority": "high",  # Common IoT target, well-documented malware exists




}
