# Custom Cowrie command module — script replay for malware simulation
# Reads a real .sh payload and replays each command through Cowrie's shell,
# producing individual cowrie.command.input log entries per line.
#
# Usage (inside honeypot session):
#   exec /tmp/dvrhelper
#
# cowrie.cfg [honeypot] section required:
#   payloads_path = /home/USER/IoT-Honeypot-for-Detecting-Attacks/Honeypot Project/attacker-simulator/payloads
#   payload_map   = from cowrie.cfg

# Ensure that each new payload you create, add it to cowrie.cfg so that this exec command can register it :)
# FOR THIS TO WORK, FIND __init__.py AND ENTER "exec" WITHIN THE LIST (alphabetically)
 
from __future__ import annotations
 
import os
 
from twisted.python import log
 
from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.honeypot import HoneyPotShell
 
commands: dict = {}
 
 
class Command_exec(HoneyPotCommand):
 
    def start(self) -> None:
        if not self.args:
            self.errorWrite("exec: usage: exec <script_path>\n")
            self.exit()
            return
 
        script_filename = os.path.basename(self.args[0])
 
        # Resolve via payload_map in cowrie.cfg
        payloads_dir = CowrieConfig.get("honeypot", "payloads_path", fallback="")
        payload_map_raw = CowrieConfig.get("honeypot", "payload_map", fallback="")
 
        real_path = None
        for entry in payload_map_raw.split(","):
            if ":" not in entry:
                continue
            vname, rname = entry.strip().split(":", 1)
            if vname.strip() == script_filename:
                candidate = os.path.join(payloads_dir, rname.strip())
                if os.path.isfile(candidate):
                    real_path = candidate
                    break
 
        if real_path is None:
            self.errorWrite(f"exec: {self.args[0]}: Permission denied\n")
            self.exit()
            return
 
        # Read script, skipping comments and blank lines
        with open(real_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [
                l.strip() for l in f
                if l.strip() and not l.strip().startswith("#")
            ]
 
        log.msg(f"[exec.py] Replaying {len(lines)} commands from {real_path}")
 
        # Use same pattern as bash.py — push a non-interactive HoneyPotShell,
        # feed all lines as a single semicolon-joined command string, then pop.
        combined = "; ".join(lines)
        self.protocol.cmdstack.append(HoneyPotShell(self.protocol, interactive=False))
        self.protocol.cmdstack[-1].lineReceived(combined)
        self.protocol.cmdstack.pop()
 
        self.exit()
 
 
commands["exec"] = Command_exec
