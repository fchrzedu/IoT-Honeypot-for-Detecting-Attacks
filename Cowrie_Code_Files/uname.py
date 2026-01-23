# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

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
    print(f"[ WARNING ] uname.py: Unable to load device profiles: exception {e}")



commands = {}

"""
def hardware_platform() -> str:
    return CowrieConfig.get("shell", "hardware_platform", fallback="x86_64")
"""

# Returns CPU architecture i.e. x86_64, MIPS, ASM etc...
# profile defined in src/cowrie/ssh/session.py __init__
def hardware_platform(profile=None) -> str:
    if profile and 'architecture' in profile:
        return profile['architecture']
    else:
        return CowrieConfig.get("shell", "hardware_platform", fallback="x86_64")	# Return default Cowrie config if profile architecture no exist

def kernel_name() -> str:
    return CowrieConfig.get("shell", "kernel_name", fallback="Linux")


def kernel_version() -> str:
    return CowrieConfig.get("shell", "kernel_version", fallback="3.2.0-4-amd64")


def kernel_build_string() -> str:
    return CowrieConfig.get(
        "shell", "kernel_build_string", fallback="#1 SMP Debian 3.2.68-1+deb7u1"
    )


def operating_system() -> str:
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
            if hasattr(self.protocol, 'terminal') and self.protocol.terminal:  # Check whether protocol has a terminal
                if hasattr(self.protocol.terminal, 'transport') and self.protocol.terminal.transport:
                    ssh_session = self.protocol.terminal.transport.session
                    if ssh_session and hasattr(ssh_session, 'device_profile'):
                        profile = ssh_session.device_profile
                        self.write(f"[DEBUG] Profile loaded: {profile.get('name', 'Unknown')}\n")
                        self.write(f"[DEBUG] Architecture: {profile.get('architecture', 'N/A')}\n")
                    else:
                        self.write("[DEBUG] Session has no device_profile\n")
                else:
                    self.write("[DEBUG] Terminal has no transport\n")
            else:
                self.write("[DEBUG] Protocol has no terminal\n")
            
            # Test hardware_platform function
            arch = hardware_platform(profile)
            self.write(f"[DEBUG] hardware_platform() returned: {arch}\n\n")
            
        except Exception as e:
            self.write(f"[EXCEPTION] {type(e).__name__}: {e}\n")
    
    

        opts = {
            "name": False,
            "release": False,
            "version": False,
            "os": False,
            "node": False,
            "machine": False,
        }

        flags = [
            (["a", "all"], "__ALL__"),
            (["s", "kernel-name"], "name"),
            (["r", "kernel-release"], "release"),
            (["v", "kernel-version"], "version"),
            (["o", "operating-system"], "os"),
            (["n", "nodename"], "node"),
            (["m", "machine", "p", "processor", "i", "hardware-platform"], "machine"),
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
            output.append(kernel_name())
        if opts["node"]:
            output.append(self.protocol.hostname)
        if opts["release"]:
            output.append(kernel_version())
        if opts["version"]:
            output.append(kernel_build_string())
        if opts["machine"]:
            output.append(hardware_platform())
        if opts["os"]:
            output.append(operating_system())

        if len(output) < 1:
            output.append(kernel_name())

        self.write(" ".join(output) + "\n")


commands["/bin/uname"] = Command_uname
commands["uname"] = Command_uname
