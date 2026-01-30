# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information
# Original location: /IoT-Honeypot-for-Detecting-Attacks/Honeypot Project/vanilla-honeypot/cowrie/src/cowrie/commands/
"""
modified uname command to work with device_profiles.py

Flow of cowrie object struct
1. command (uname)
2. self.protocol (HoneyPotInteractiveProtocol - the shell)
3. self.protocol.terminal (the terminal emulator)
4. self.protocol.terminal.transport (SSH connection terminal )
5. self.protocol.terminal.transport.session (ssh channel - HAS device_profile)


"""

from __future__ import annotations

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

# Import Cowrie path for Python
import os
import sys
# Remember cowrie structure. cowrie/src/cowrie/commands <-- WE ARE IN COMMANDS, THREE DIRs TO GET TO ROOT
cowrie_root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '/../../..'))
if cowrie_root_path not in sys.path:
    sys.path.insert(0, cowrie_root_path)

# Import device profiles
try:
    from device_profiles import DEVICE_PROFILES # Import device profiles
    PROFILES_LOADED = True	# Set boolean to loaded
except Exception as e:
    PROFILES_LOADED =  False	# Return error w/ exception if unsuccesful
    log.msg(f"[ WARNING ] uname.py: Unable to load device profiles e: {e}")



commands = {}

# ==========
#    HELPER FUNCTIONS MODIFIED FOR PROFILES
# ========

# NEW FUNCTION: Returns processor for uname -p
def processor_type(profile=None):
    if profile and 'cpu' in profile:
        return profile['cpu']
    else:
        return "unknown"

# Returns CPU architecture i.e. x86_64, MIPS, ASM etc...
# profile defined in src/cowrie/ssh/session.py __init__
def hardware_platform(profile=None) -> str:
    if profile and 'architecture' in profile:
        return profile['architecture']
    else:
        return CowrieConfig.get("shell", "hardware_platform", fallback="x86_64")	# Return default Cowrie config if profile architecture no exist

# Returns kernel name (Always Linux for IoT devices) - no change needed
def kernel_name(profile=None) -> str:
    return CowrieConfig.get("shell", "kernel_name", fallback="Linux")

# Returns kernel version from device_profiles:kernel_version
def kernel_version(profile=None) -> str:
    if profile and 'kernel_version' in profile:
        return profile['kernel_version']
    else:
        return CowrieConfig.get("shell", "kernel_version", fallback="3.2.0-4-amd64")

# Returns kernel build string from device_profiles:uname_output
def kernel_build_string(profile=None) -> str:
    if profile and 'uname_output' in profile:
        # Parse output from uname_output, split it and extract build time
        parts = profile['uname_output'].split()

    # Find where build string starts (#)
    for i, part in enumerate(parts):
        if part.startswith('#'):
            # Collect all parts until architecture / OS hit
            build_parts = []
            j = i
            # Stop when we hit known architecture - not needed, but good for future expansion of devices supported
            while j < len(parts):
                if parts[j] in ['mipsel', 'mips', 'armv7l', 'x86_64', 'i686', 'aarch64', 'GNU/Linux']:
                    break
                build_parts.append(parts[j])
                j +=1
            return ' '.join(build_parts)
    # Fallback to default cowrie value
    return CowrieConfig.get(
        "shell", "kernel_build_string", fallback="#1 SMP Debian 3.2.68-1+deb7u1"
    )

# Returns OS (Always GNU/Linux for IoT devices) - can leave as default fallback
def operating_system(profile=None) -> str:
    return CowrieConfig.get("shell", "operating_system", fallback="GNU/Linux")


def uname_help() -> str:
    return """Usage: uname [OPTION]...
Print certain system information.  With no OPTION, same as -s.

  -a, --all                print all information, in the following order,
                             except omit -p and -i if unknown:
  -s, --kernel-name        print the kernel name
  -n, --nodename           print the network node hostname
  -r, --kernel-release     print the kernel release
  -v, --kernel-version     print the kernel version
  -m, --machine            print the machine hardware name
  -p, --processor          print the processor type (non-portable)
  -i, --hardware-platform  print the hardware platform (non-portable)
  -o, --operating-system   print the operating system
      --help     display this help and exit
      --version  output version information and exit

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/uname>
or available locally via: info '(coreutils) uname invocation'\n
"""


def uname_get_some_help() -> str:
    return "Try 'uname --help' for more information."


def uname_fail_long(arg: str) -> str:
    return f"uname: unrecognized option '{arg}'\n{uname_get_some_help()}\n"


def uname_fail_short(arg: str) -> str:
    return f"uname: invalid option -- '{arg}'\n{uname_get_some_help()}\n"


def uname_fail_extra(arg: str) -> str:
    # Note: These are apostrophes, not single quotation marks.
    return f"uname: extra operand ‘{arg}’\n{uname_get_some_help()}\n"


class Command_uname(HoneyPotCommand):
    def full_uname(self) -> str:
        return f"{kernel_name()} {self.protocol.hostname} {kernel_version()} {kernel_build_string()} {hardware_platform()} {operating_system()}\n"

    def call(self) -> None:
        profile = None
    # MODIFICATION HERE
        try:
            # The correct path to the SSH session in Cowrie's architecture:
            # self.protocol → terminal → transport → session
            if hasattr(self.protocol, 'terminal') and self.protocol.terminal:
                if hasattr(self.protocol.terminal, 'transport') and self.protocol.terminal.transport:
                    ssh_session = self.protocol.terminal.transport.session
                    if ssh_session and hasattr(ssh_session, 'device_profile'):
                        profile = ssh_session.device_profile
            
        except Exception as e:
            self.write(f"[EXCEPTION] {type(e).__name__}: {e}\n")   
    

        opts = {
            "name": False,
            "release": False,
            "version": False,
            "os": False,
            "node": False,
            "machine": False,
            "processor" : False,    # added for processor_type()
        }

        flags = [
            (["a", "all"], "__ALL__"),
            (["s", "kernel-name"], "name"),
            (["r", "kernel-release"], "release"),
            (["v", "kernel-version"], "version"),
            (["o", "operating-system"], "os"),
            (["n", "nodename"], "node"),
            (["m", "machine", "i", "hardware-platform"], "machine"),  #  -p removed
            (["p", "processor"], "processor"), # added new flag for -p
        ]

        if not self.args:
            # IF no params output default
            self.write(f"{kernel_name()}\n")
            return

        # getopt-style parsing
        for a in self.args:
            a = a.strip()
            arg_block = []
            was_long = False

            if a == "--help":
                # Help overrides invalid args following --help
                # There's no -h, invalid args before --help still fail.
                self.write(uname_help())
                return
            elif a.startswith("--"):
                # arg name w/o --
                was_long = True
                arg_block.append(a[2:])
            elif a.startswith("-"):
                # letter by letter
                a = a[1:]
                if len(a) == 0:
                    self.write(uname_fail_extra("-"))
                    return

                for split_arg in a:
                    arg_block.append(split_arg)
            else:
                self.write(uname_fail_extra(a))
                return

            for arg in arg_block:
                arg_parsed = False

                # Find a possible flag for each arg.
                for possible_args, target_opt in flags:
                    if arg not in possible_args:
                        continue

                    arg_parsed = True  # Got a hit!

                    # Set all opts for -a/--all, single opt otherwise:
                    if target_opt == "__ALL__":
                        for key in opts.keys():
                            opts[key] = True
                    else:
                        opts[target_opt] = True

                    break  # Next arg please

                if not arg_parsed:
                    self.write(
                        uname_fail_long(a) if was_long else uname_fail_short(arg)
                    )
                    return

        # All the options set, let's get the output
        output = []

        if opts["name"]:
            output.append(kernel_name(profile))
        if opts["node"]:
            if profile and 'hostname' in profile:
                output.append(profile['hostname'])
            else:
                output.append(self.protocol.hostname)
        if opts["release"]:
            output.append(kernel_version(profile))
        if opts["version"]:
            output.append(kernel_build_string(profile))
        if opts["machine"]:
            output.append(hardware_platform(profile))
        if opts["os"]:
            output.append(operating_system(profile))
        if opts["processor"]:
            output.append(processor_type(profile))

        if len(output) < 1:
            output.append(kernel_name(profile))

        self.write(" ".join(output) + "\n")


commands["/bin/uname"] = Command_uname
commands["uname"] = Command_uname
