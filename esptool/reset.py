# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import errno
import time

import serial
from esp_pylib.serial_reset import (
    DEFAULT_RESET_DELAY,
    classic_bootloader_reset,
    execute_custom_reset,
    hard_reset,
    parse_custom_reset_sequence,
    set_dtr_rts,
    unix_tight_bootloader_reset,
    usb_jtag_bootloader_reset,
)
from rich.markup import escape

from .logger import log
from .util import FatalError, PrintOnce

__all__ = [
    "DEFAULT_RESET_DELAY",
    "ClassicReset",
    "CustomReset",
    "HardReset",
    "ResetStrategy",
    "USBJTAGSerialReset",
    "UnixTightReset",
]


class ResetStrategy:
    """Common reset-strategy base.

    Wraps the chosen `esp_pylib.serial_reset` sequence with esptool's
    retry-on-disconnect loop. Targets with internal USB peripherals can
    drop and re-enumerate the serial device during a reset; the loop opens
    the port up to three times before giving up. ``ENOTTY`` / ``EINVAL``
    are treated specially because some platforms (RFC2217 ports, certain
    USB ROM-loader interfaces) simply do not honour modem-control writes —
    we surface that with a single one-shot warning and continue.
    """

    print_once = PrintOnce(log.warn)

    def __init__(
        self,
        port: serial.Serial,
        reset_delay: float = DEFAULT_RESET_DELAY,
        flow_control: bool = False,
    ):
        self.port = port
        self.reset_delay = reset_delay
        self.flow_control = flow_control

    def __call__(self) -> None:
        for retry in reversed(range(3)):
            try:
                if not self.port.isOpen():
                    self.port.open()
                self.reset()
                break
            except OSError as e:
                # ENOTTY for TIOCMSET; EINVAL for TIOCMGET
                if e.errno in [errno.ENOTTY, errno.EINVAL]:
                    self.print_once(
                        "Chip was NOT reset. Setting RTS/DTR lines is not "
                        f"supported for port '{escape(str(self.port.name))}'. "
                        "Set --before and "
                        "--after arguments to 'no-reset' and switch to bootloader "
                        "manually to avoid this warning."
                    )
                    break
                elif not retry:
                    raise
                self.port.close()
                time.sleep(0.5)

    def reset(self):
        pass


class ClassicReset(ResetStrategy):
    """Portable bootloader reset (sequential DTR/RTS writes)."""

    def reset(self) -> None:
        classic_bootloader_reset(
            self.port,
            enter_boot_delay=0.1,
            reset_delay=self.reset_delay,
            flow_control=self.flow_control,
        )


class UnixTightReset(ResetStrategy):
    """POSIX-only bootloader reset that toggles DTR/RTS atomically.

    Falls back to `ClassicReset` on Windows because the shared
    `esp_pylib.serial_reset.unix_tight_bootloader_reset` raises
    `NotImplementedError` there (no ``ioctl``).
    """

    def reset(self) -> None:
        unix_tight_bootloader_reset(
            self.port,
            enter_boot_delay=0.1,
            reset_delay=self.reset_delay,
            flow_control=self.flow_control,
        )


class USBJTAGSerialReset(ResetStrategy):
    """Reset sequence for the internal USB-Serial-JTAG peripheral."""

    def reset(self) -> None:
        usb_jtag_bootloader_reset(self.port)


class HardReset(ResetStrategy):
    """Pulse EN to restart the chip."""

    def __init__(
        self,
        port: serial.Serial,
        uses_usb: bool = False,
        flow_control: bool = False,
        usb_jtag_serial: bool = False,
    ):
        super().__init__(port, flow_control=flow_control)
        self.uses_usb = uses_usb
        self.usb_jtag_serial = usb_jtag_serial

    def _release_lines(self) -> None:
        """Deassert DTR and RTS together before pulsing RTS on USB-Serial/JTAG.

        On POSIX, pyserial opens the port with DTR and RTS asserted, and with
        ``--before no-reset`` nothing releases them. USB-Serial/JTAG ignores an
        RTS pulse while DTR is asserted, and dropping DTR first while RTS is
        asserted is its download-mode entry, so both lines have to go idle in
        one write. Windows ports already open with both lines deasserted.
        """
        if not (self.port.dtr or self.port.rts):
            return
        try:
            set_dtr_rts(self.port, dtr=False, rts=False)
        except (NotImplementedError, OSError):
            return
        # Sync pyserial's cached state, set_rts() re-applies the cached DTR value
        self.port.dtr = False
        self.port.rts = False
        time.sleep(0.1)

    def reset(self) -> None:
        if self.usb_jtag_serial:
            self._release_lines()
        if self.uses_usb:
            # Chips talking over their internal USB peripheral disappear from
            # the bus during reset; ``post_release_delay=0.2`` gives the
            # device time to re-enumerate before any follow-up writes.
            hard_reset(
                self.port,
                hold_delay=0.2,
                post_release_delay=0.2,
                flow_control=self.flow_control,
            )
        else:
            hard_reset(
                self.port,
                hold_delay=0.1,
                post_release_delay=0.0,
                flow_control=self.flow_control,
            )


class CustomReset(ResetStrategy):
    """User-defined reset sequence parsed from a ``"D0|R1|W0.1|..."`` string.

    The mini-language is shared with esp-idf-monitor via
    `esp_pylib.serial_reset.parse_custom_reset_sequence`. Parsing
    errors from the shared parser (``ValueError``) are rewrapped into a
    `FatalError` so they flow through esptool's top-level
    error-handling path with the historical message format.
    """

    def __init__(self, port: serial.Serial, seq_str: str):
        super().__init__(port)
        try:
            # Parse eagerly so a typo surfaces at object-construction time,
            # not deep inside `reset` after a serial port is already
            # busy.
            parse_custom_reset_sequence(seq_str)
        except ValueError as e:
            raise FatalError(f"Invalid custom reset sequence option format: {e}")
        self._seq_str = seq_str

    def reset(self) -> None:
        execute_custom_reset(self.port, self._seq_str)
