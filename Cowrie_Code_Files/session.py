# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import annotations

from typing import Literal

from twisted.conch.ssh import session
from twisted.conch.ssh.common import getNS
from twisted.python import log


class HoneyPotSSHSession(session.SSHSession):
    """
    This is an SSH channel that's used for SSH sessions
    """

    def __init__(self, *args, **kw):
        session.SSHSession.__init__(self, *args, **kw)

        # ========== DEVICE PROFILE ASSIGNMENT ==========
        import os
        import sys
        import random

        # Add cowrie directory to python directory - allows to import device_profiles
	# __file__ = current dir path
	# os.path.dirname(__file__) = returns directory of __file__; returns directory of session.py (this file)
	# os.path.join; goes up 3 directories (to Cowrie)
	# abspath: returns all of the above in Linux filesystem terminology :D
        cowrie_root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
        if cowrie_root_path not in sys.path:
            sys.path.insert(0, cowrie_root_path)

        try:
            # Import device profiles
            from device_profiles import DEVICE_PROFILES

            # Randomly select a device profile for this session
            profile_name = random.choice(list(DEVICE_PROFILES.keys()))

            # Store profile in session object (accessible by all commands)
            self.device_profile = DEVICE_PROFILES[profile_name]	# Creates new attribute in THIS session
            self.device_profile_name = profile_name

            # Log which profile was assigned
            log.msg(
                eventid='cowrie.session.profile',
                format='Assigned device profile: %(profile)s (%(model)s)',
                profile=profile_name,
                model=self.device_profile['model']
            )

        except Exception as e:
            # If device_profiles.py not found or has errors, log and continue
            # Cowrie will use default behavior
            log.msg(f"[WARNING] Failed to load device profile: {e}")
            self.device_profile = None
            self.device_profile_name = "default"

            # ==========  ==========

    def request_env(self, data: bytes) -> Literal[0, 1]:
        name, rest = getNS(data)
        value, rest = getNS(rest)

        if rest:
            log.msg(f"Extra data in request_env: {rest!r}")
            return 1

        log.msg(
            eventid="cowrie.client.var",
            format="request_env: %(name)s=%(value)s",
            name=name.decode("utf-8"),
            value=value.decode("utf-8"),
        )
        # FIXME: This only works for shell, not for exec command
        if self.session:
            self.session.environ[name.decode("utf-8")] = value.decode("utf-8")
        return 0

    def request_agent(self, data: bytes) -> int:
        log.msg(f"request_agent: {data!r}")
        return 0

    def request_x11_req(self, data: bytes) -> int:
        log.msg(f"request_x11: {data!r}")
        return 0

    def closed(self) -> None:
        """
        This is reliably called on session close/disconnect and calls the avatar
        """
        session.SSHSession.closed(self)
        self.client = None

    def eofReceived(self) -> None:
        """
        Redirect EOF to emulated shell. If shell is gone, then disconnect
        """
        if self.session:
            self.session.eofReceived()
        else:
            self.loseConnection()

    def sendEOF(self) -> None:
        """
        Utility function to request to send EOF for this session
        """
        self.conn.sendEOF(self)

    def sendClose(self) -> None:
        """
        Utility function to request to send close for this session
        """
        self.conn.sendClose(self)

    def channelClosed(self) -> None:
        log.msg("Called channelClosed in SSHSession")
