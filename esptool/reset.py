# SPDX-FileCopyrightText: 2014-2023 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import errno
import os
import struct
import time

from .util import FatalError, PrintOnce

# Used for resetting into bootloader on Unix-like systems
if os.name != "nt":
    import fcntl
    import termios

    # Constants used for terminal status lines reading/setting.
    # Taken from pySerial's backend for IO:
    # https://github.com/pyserial/pyserial/blob/master/serial/serialposix.py
    TIOCMSET = getattr(termios, "TIOCMSET", 0x5418)
    TIOCMGET = getattr(termios, "TIOCMGET", 0x5415)
    TIOCM_DTR = getattr(termios, "TIOCM_DTR", 0x002)
    TIOCM_RTS = getattr(termios, "TIOCM_RTS", 0x004)

DEFAULT_RESET_DELAY = 0.05  # default time to wait before releasing boot pin after reset


class ResetStrategy(object):
    print_once = PrintOnce()

    def __init__(self, port, reset_delay=DEFAULT_RESET_DELAY):
        self.port = port
        self.reset_delay = reset_delay

    def __call__(self):
        try:
            self.reset()
        except OSError as e:
            # ENOTTY for TIOCMSET; EINVAL for TIOCMGET
            if e.errno in [errno.ENOTTY, errno.EINVAL]:
                self.print_once(
                    "WARNING: Chip was NOT reset. Setting RTS/DTR lines is not "
                    f"supported for port '{self.port.name}'. Set --before and --after "
                    "arguments to 'no_reset' and switch to bootloader manually to "
                    "avoid this warning."
                )
            else:
                raise

    def reset(self):
        pass

    def _setDTR(self, state):
        self.port.setDTR(state)

    def _setRTS(self, state):
        self.port.setRTS(state)
        # Work-around for adapters on Windows using the usbser.sys driver:
        # generate a dummy change to DTR so that the set-control-line-state
        # request is sent with the updated RTS state and the same DTR state
        self.port.setDTR(self.port.dtr)

    def _setDTRandRTS(self, dtr=False, rts=False):
        status = struct.unpack(
            "I", fcntl.ioctl(self.port.fileno(), TIOCMGET, struct.pack("I", 0))
        )[0]
        if dtr:
            status |= TIOCM_DTR
        else:
            status &= ~TIOCM_DTR
        if rts:
            status |= TIOCM_RTS
        else:
            status &= ~TIOCM_RTS
        fcntl.ioctl(self.port.fileno(), TIOCMSET, struct.pack("I", status))


class ClassicReset(ResetStrategy):
    """
    Classic reset sequence, sets DTR and RTS lines sequentially.
    """

    def reset(self):
        self._setDTR(False)  # IO0=HIGH
        self._setRTS(True)  # EN=LOW, chip in reset
        time.sleep(0.1)
        self._setDTR(True)  # IO0=LOW
        self._setRTS(False)  # EN=HIGH, chip out of reset
        time.sleep(self.reset_delay)
        self._setDTR(False)  # IO0=HIGH, done


class UnixTightReset(ResetStrategy):
    """
    UNIX-only reset sequence with custom implementation,
    which allows setting DTR and RTS lines at the same time.
    """

    def reset(self):
        self._setDTRandRTS(False, False)
        self._setDTRandRTS(True, True)
        self._setDTRandRTS(False, True)  # IO0=HIGH & EN=LOW, chip in reset
        time.sleep(0.1)
        self._setDTRandRTS(True, False)  # IO0=LOW & EN=HIGH, chip out of reset
        time.sleep(self.reset_delay)
        self._setDTRandRTS(False, False)  # IO0=HIGH, done
        self._setDTR(False)  # Needed in some environments to ensure IO0=HIGH


class USBJTAGSerialReset(ResetStrategy):
    """
    Custom reset sequence, which is required when the device
    is connecting via its USB-JTAG-Serial peripheral.
    """

    def reset(self):
        self._setRTS(False)
        self._setDTR(False)  # Idle
        time.sleep(0.1)
        self._setDTR(True)  # Set IO0
        self._setRTS(False)
        time.sleep(0.1)
        self._setRTS(True)  # Reset. Calls inverted to go through (1,1) instead of (0,0)
        self._setDTR(False)
        self._setRTS(True)  # RTS set as Windows only propagates DTR on RTS setting
        time.sleep(0.1)
        self._setDTR(False)
        self._setRTS(False)  # Chip out of reset


class HardReset(ResetStrategy):
    """
    Reset sequence for hard resetting the chip.
    Can be used to reset out of the bootloader or to restart a running app.
    """

    def __init__(self, port, uses_usb_otg=False):
        super().__init__(port)
        self.uses_usb_otg = uses_usb_otg

    def reset(self):
        self._setRTS(True)  # EN->LOW
        if self.uses_usb_otg:
            # Give the chip some time to come out of reset,
            # to be able to handle further DTR/RTS transitions
            time.sleep(0.2)
            self._setRTS(False)
            time.sleep(0.2)
        else:
            time.sleep(0.1)
            self._setRTS(False)


class CustomReset(ResetStrategy):
    """
    Custom reset strategy defined with a string.

    CustomReset object is created as "rst = CustomReset(port, seq_str)"
    and can be later executed simply with "rst()"

    The seq_str input string consists of individual commands divided by "|".
    Commands (e.g. R0) are defined by a code (R) and an argument (0).

    The commands are:
    D: setDTR - 1=True / 0=False
    R: setRTS - 1=True / 0=False
    U: setDTRandRTS (Unix-only) - 0,0 / 0,1 / 1,0 / or 1,1
    W: Wait (time delay) - positive float number

    e.g.
    "D0|R1|W0.1|D1|R0|W0.05|D0" represents the ClassicReset strategy
    "U1,1|U0,1|W0.1|U1,0|W0.05|U0,0" represents the UnixTightReset strategy
    """

    format_dict = {
        "D": "self.port.setDTR({})",
        "R": "self.port.setRTS({})",
        "W": "time.sleep({})",
        "U": "self._setDTRandRTS({})",
    }

    def reset(self):
        exec(self.constructed_strategy)

    def __init__(self, port, seq_str):
        super().__init__(port)
        self.constructed_strategy = self._parse_string_to_seq(seq_str)

    def _parse_string_to_seq(self, seq_str):
        try:
            cmds = seq_str.split("|")
            fn_calls_list = [self.format_dict[cmd[0]].format(cmd[1:]) for cmd in cmds]
        except Exception as e:
            raise FatalError(f'Invalid "custom_reset_sequence" option format: {e}')
        return "\n".join(fn_calls_list)
