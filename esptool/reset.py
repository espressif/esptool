# SPDX-FileCopyrightText: 2014-2023 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import struct
import time

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
    def __init__(self, port, reset_delay=DEFAULT_RESET_DELAY):
        self.port = port
        self.reset_delay = reset_delay

    def __call__():
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

    def __call__(self):
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

    def __call__(self):
        self._setDTRandRTS(False, False)
        self._setDTRandRTS(True, True)
        self._setDTRandRTS(False, True)  # IO0=HIGH & EN=LOW, chip in reset
        time.sleep(0.1)
        self._setDTRandRTS(True, False)  # IO0=LOW & EN=HIGH, chip out of reset
        time.sleep(self.reset_delay)
        self._setDTRandRTS(False, False)  # IO0=HIGH, done


class USBJTAGSerialReset(ResetStrategy):
    """
    Custom reset sequence, which is required when the device
    is connecting via its USB-JTAG-Serial peripheral.
    """

    def __call__(self):
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

    def __call__(self):
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
