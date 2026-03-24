from __future__ import annotations

import json
import os
from typing import Tuple


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
            VCEI exceptions\t\t: not available\n""",

        # ============================
        # OPERATIONAL DATA
        # ============================
        "available_commands": [
            "ls", "cat", "echo", "ps", "kill",
            "busybox", "sh", "mount", "umount",
            "ifconfig", "ping", "wget", "reboot"
        ],

        "shell_prompt": "# ", # simple root for camera

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
          "device_type": "Mips Router",

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
            "uname_output": "Linux OpenWrt 5.4.188 #0 SMP Mon Jun 23 10:15:42 2020 mips GNU/Linux",
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
                VCEI exceptions\t\t: not available\n""",
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


    },


# ===========================================================================================================================================================


    "netgear_r7000_ddwrt": {
        # This is not inheritently an IoT device, but rather a popular ARM router that manages IoT devices therefore it is also vulnearble
        # Source 1 & 2: https://www.shodan.io/host/174.87.123.230 https://www.shodan.io/host/24.183.229.183
                        # Confirmed: Firmware Info, MAC & OUI, http_auth protocol & type, model
                        # Direct filters did not work. Had to look at port 80 (HTTP), also deduced this is a DD-WRT router not an OpenWRT router
        # Source 3 : MAC OUI lookup  https://maclookup.app/macaddress/cc40d0
                        # Confirmed OUI against sources 1 & 2
        # Source 4: DD-WRT WikI
                        # Did attempt to look at communiy forums with filter ' Netgear AND R7000 AND SSH AND Dropbear' - found absolutely nothing.
                        # But DD-WRT wiki did confirm: All hardware specifications, kernel & version
                        # Cross-referenced against OpenWRT, but was not a direct source
        # Source 5: WimsWord blog: https://wimsworld.wordpress.com/2022/05/07/dd-wrt-upgrade/
                        # Spent forever googling looking for R7000 terminal and command line outputs, found someone having an issue upgrading SSH
                        # This deduced: Identical specifications as to all sources, BusyBox version
        # Source 6 : Dropbear Release timeline: https://github.com/mkj/dropbear/releases
                        # Used to construct SSH banner.
                        # 2020.81 Released Oct 29 2020
                        # 2022.81 Released April 1 2022
                        # firmware is dated 4 Feb 2022, therefore 2020.81 is the chosen version
            # ============================
            # DEVICE IDENTIFICATION
            # ============================
          "name": "Netgear Nighthawk R7000 Router (DD-WRT)",
          "manufacturer": "Netgear",
          "model": "Netgear R7000",
          "hardware_version": "v1", # Unable to find hardware version, used v1 as it doesn't matter'
          "firmware_version": "v3.0-r48289 std",        # CONFIRMED by Shodan
          "device_type": "ARM Router",

            # ============================
            # HARDWARE SPECIFICATIONS
            # ============================
            # All of these specifications were derived from DD-WRT wiki,
            "cpu": "Broadcom BCM4709A0",
            "cpu_mhz": "1000",
            "architecture": "armv7l",
            "ram_mb": "256",
            "flash_mb": "128",
            # ============================
            # SYSTEMS SPECIFICATIONS
            # ============================
            "kernel_version": "4.4.302",    # CONFIRMED via DD-WRT wiki
            "hostname": "Netgear-R7000",  #  CONFIRMED via WimsWorld blog
            # SSH banner DEDUCED:
                # Firmware dated 4th Feb 2022
                # Released between feb are: 2020.81 on 29oct 2020 & 2022.81 on April 1 2022
                # Therefore, 2020.81 was chosen - .79 was valid too but some variety for data
                # Moreover, WimsWorld showed no change in SSH banner after new DropBear deployment
            "ssh_banner": "SSH-2.0-dropbear_2020.81",
            # Deduced:
                # Constructed from: Kernel + SMP(dual-core CPU) + firmware date + arv7l
            "uname_output": "Linux Netgear-R7000 4.4.302 #1 SMP Fri Feb 4 03:36:35 UTC 2022 armv7l GNU/Linux",
            # /proc/cpuinfo (QCA9563 standard output)
            "cpuinfo": """Processor\t\t: ARMv7 Processor rev 0 (v7l)
                processor\t\t: 0
                cpu model\t\t: ARMv7 Processor rev 0 (v7l)
                BogoMIPS\t\t: 1199.30
                processor\t\t: 1
                BogoMIPS\t\t: 1199.30
                Features\t\t: half fastmult edsp tls
                CPU implementer\t\t: 0x41
                CPU architecture\t: 7
                CPU variant\t\t: 0x0
                CPU part\t\t: 0xc09
                CPU revision\t\t: 0
                Hardware\t\t: Northstar Prototype
                Revision\t\t: 0000
                Serial\t\t\t: 0000000000000000\n""",
                # ============================
                # OPERATIONAL DATA
                # ============================
                "available_commands": [
                    "ls", "cat", "echo", "ps", "kill", "top",
                    "busybox", "sh", "ash", "mount", "umount", "df",
                    "ifconfig", "ping", "wget", "reboot", "uname",
                    "free", "dmesg", "netstat", # Standard BusyBox
                    ],
                "shell_prompt": "root@Netgear-R7000:~# ",     # CONFIRMED from WimsWorld terminal output

                # Network info
                "mac_prefix": "CC:40:D0", # Shodan OUI

                # HTTP Server IF applicable, routers usually have web UI
                "http_server": "httpd",    # CONFIRMED shodan
                # ========================================
                # DOCUMENTATION & VALIDATION
                # ========================================
                        "research_sources": {
            "shodan_hosts": [
                "https://www.shodan.io/host/174.87.123.230",
                "https://www.shodan.io/host/24.183.229.183",
            ],
            "mac_lookup": "https://maclookup.app/macaddress/cc40d0",
            "ddwrt_wiki": "https://wiki.dd-wrt.com/wiki/index.php/Netgear_R7000",
            "openwrt_toh": "https://openwrt.org/toh/netgear/r7000",
            "busybox_terminal": "https://wimsworld.wordpress.com/2022/05/07/dd-wrt-upgrade/",
            "dropbear_releases": "https://github.com/mkj/dropbear/releases",
            "confirmed_fields": [
                "manufacturer",
                "model",
                "firmware_version (v3.0-r48289 std — Shodan DD-WRT banner)",
                "firmware_date (02/04/22 — Shodan DD-WRT banner)",
                "cpu (BCM4709A0 — DD-WRT wiki)",
                "cpu_mhz (1000 — DD-WRT wiki, dual-core 2x1000MHz)",
                "architecture (armv7l — DD-WRT wiki, ARM Cortex-A9)",
                "ram_mb (256 — DD-WRT wiki)",
                "flash_mb (128 NAND — DD-WRT wiki)",
                "kernel_version (4.4.302 — DD-WRT wiki: Linux kernel 4.4.302-stXX)",
                "hostname (Netgear-R7000 — WimsWorld terminal output)",
                "shell_prompt (root@Netgear-R7000:~# — WimsWorld terminal output)",
                "busybox_version (v1.35.0 — WimsWorld terminal output)",
                "shell_type (ash — WimsWorld terminal output)",
                "mac_prefix (CC:40:D0 — Shodan + maclookup.app confirmed Netgear OUI)",
                "http_server (httpd — Shodan Server: header)",
                "observed_ports (80, 443, 8080 — Shodan result)",
                "http_auth_realm (NETGEAR R7000 — Shodan 401 response)",
                "ssl_cert_cn (www.routerlogin.net — Shodan SSL cert)",
                "ssl_cert_org (NETGEAR, San Jose CA — Shodan SSL cert)",
            ],
        "deduced_fields": [
                "hardware_version (V1 — only revision produced)",
                "ssh_banner (dropbear_2020.81 — firmware Feb 4 2022 predates "
                "Dropbear 2022.82 by ~8 weeks; 2020.81 was the only stable release "
                "between Oct 2020 and Apr 2022; Debian accepted 2022.82-1 on Apr 2 2022)",
                "uname_output (constructed from kernel 4.4.302 + armv7l + firmware date)",
                "cpuinfo (BCM4709A0 Cortex-A9 standard output + BogoMIPS from "
                "ARM Cortex-A9 calibration at 1000MHz)",
            ],
    },

    "testing_priority": "high"


    }
}





# ============================================================================
# Round-Robin State Management
# ============================================================================


_PROFILE_KEYS: list[str] = list(DEVICE_PROFILES.keys())	# Extracts all profile names and stores as an indexed list (this is a dictionary)

# Cache resolved writable path to avoid repeated permission failures - this fixed the containerised-honeypot bug
_RESOLVED_STATE_PATH: dict[str, str] = {}


def _get_candidate_paths(instance_id: str) -> list[str]:
    """Return possible state file paths (ordered by preference)."""
    safe_id = instance_id.replace("/", "_").replace("\\", "_").replace(" ", "_")	# Sanitise the filename ID for system use
    filename = f".profile_state_{safe_id}.json"	

    return [
        f"/home/cowrie/cowrie/var/lib/cowrie/state/{filename}",  # intended location
        f"/tmp/{filename}",  # guaranteed fallback
    ]


def _resolve_state_path(instance_id: str) -> str:
    """
    Resolve and cache a writable path by actually attempting a write.
    This avoids relying on os.access() which is unreliable in containers.
    """
    if instance_id in _RESOLVED_STATE_PATH:
        return _RESOLVED_STATE_PATH[instance_id]

    for path in _get_candidate_paths(instance_id):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)

            # Attempt actual write test
            with open(path, "a"):
                pass

            _RESOLVED_STATE_PATH[instance_id] = path
            return path

        except OSError:
            continue

    # Absolute fallback
    fallback = f"/tmp/.profile_state_{instance_id}.json"
    _RESOLVED_STATE_PATH[instance_id] = fallback
    return fallback


def _read_index(instance_id: str) -> int:
    """Read round-robin index safely."""
    path = _resolve_state_path(instance_id)

    try:
        with open(path, "r") as fh:
            data = json.load(fh)
            idx = int(data.get("index", 0))
            return idx % len(_PROFILE_KEYS)

    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return 0


def _write_index(instance_id: str, index: int) -> None:
    """Write index silently """
    path = _resolve_state_path(instance_id)

    try:
        with open(path, "w") as fh:
            json.dump({"index": index}, fh)

    except OSError:
        # Silent failure → honeypot must never break or spam logs
        pass

def get_next_profile(instance_id: str = "default") -> Tuple[str, dict]:
    """
    Return the next (profile_name, profile_dict) in round-robin order for
    the given honeypot instance, then advance and persist the counter.

    Parameters
    ----------
    instance_id : str
        Value of [honeypot] sensor_name from cowrie.cfg.
        Examples: "vanilla-honeypot", "sandboxed-honeypot"
    """
    current_index = _read_index(instance_id)
    profile_name = _PROFILE_KEYS[current_index]
    profile = DEVICE_PROFILES[profile_name]

    next_index = (current_index + 1) % len(_PROFILE_KEYS)
    _write_index(instance_id, next_index)

    return profile_name, profile


# ============================================================================
# Convenience helpers
# ============================================================================

def get_random_profile() -> Tuple[str, dict]:
    """Return a randomly selected profile (retained for compatibility)."""
    import random
    profile_name = random.choice(_PROFILE_KEYS)
    return profile_name, DEVICE_PROFILES[profile_name]


def get_profile_by_name(name: str) -> dict | None:
    """Return a profile dict by key, or None if not found."""
    return DEVICE_PROFILES.get(name, None)



# ============================================
#	FUNCTIONS USED FOR RANDOM SELECTION
# ============================================

def get_random_profile() -> Tuple[str, dict]:
    """Return a randomly selected profile (retained for compatibility)."""
    import random
    profile_name = random.choice(_PROFILE_KEYS)
    return profile_name, DEVICE_PROFILES[profile_name]


def get_profile_by_name(name: str) -> dict | None:
    """Return a profile dict by key, or None if not found."""
    return DEVICE_PROFILES.get(name, None)
# ============================================
# Testing Function
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("DEVICE PROFILE CATALOGUE — VALIDATION")
    print("=" * 70)
    print(f"\n✓ Total profiles loaded: {len(DEVICE_PROFILES)}")

    for profile_id, profile in DEVICE_PROFILES.items():
        print("\n" + "-" * 70)
        print(f"  [{profile_id}]")
        print(f"  Name         : {profile['name']}")
        print(f"  Architecture : {profile['architecture']}")
        print(f"  SSH Banner   : {profile['ssh_banner']}")
        print(f"  Kernel       : {profile['kernel_version']}")

    print("\n" + "=" * 70)
    print("ROUND-ROBIN TEST (instance_id='vanilla-honeypot')")
    print("=" * 70)
    for i in range(len(DEVICE_PROFILES) * 2):    # Two full cycles
        name, p = get_next_profile("vanilla-honeypot")
        print(f"  Session {i + 1:02d}: {name}  ({p['architecture']})")

    print("\n" + "=" * 70)
    print("ROUND-ROBIN TEST (instance_id='sandboxed-honeypot')")
    print("=" * 70)
    for i in range(len(DEVICE_PROFILES) * 2):
        name, p = get_next_profile("sandboxed-honeypot")
        print(f"  Session {i + 1:02d}: {name}  ({p['architecture']})")

    print("\n" + "=" * 70)
    print("VALIDATION COMPLETE")
    print("=" * 70)
