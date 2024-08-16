# SPDX-FileCopyrightText: 2014-2024 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import threading
from esptool.reset import (
    ClassicReset,
    CustomReset,
    DEFAULT_RESET_DELAY,
    HardReset,
    UnixTightReset,
)
import serial
import serial.rfc2217
from serial.rfc2217 import (
    COM_PORT_OPTION,
    SET_CONTROL,
    SET_CONTROL_DTR_OFF,
    SET_CONTROL_DTR_ON,
    SET_CONTROL_RTS_OFF,
    SET_CONTROL_RTS_ON,
)

from esptool.config import load_config_file

cfg, _ = load_config_file(verbose=True)
cfg = cfg["esptool"]


class EspPortManager(serial.rfc2217.PortManager):
    """
    The beginning of the reset sequence is detected and the proper reset sequence
    is applied in a thread. The rest of the reset sequence received is just ignored
    and not sent to the serial port.
    """

    def __init__(self, serial_port, connection, esp32r0_delay, logger=None):
        self.esp32r0_delay = esp32r0_delay
        self.is_download_mode = False
        super(EspPortManager, self).__init__(serial_port, connection, logger)

    def _telnet_process_subnegotiation(self, suboption):
        if suboption[0:1] == COM_PORT_OPTION and suboption[1:2] == SET_CONTROL:
            if suboption[2:3] == SET_CONTROL_DTR_OFF:
                self.is_download_mode = False
                self.serial.dtr = False
                return
            elif suboption[2:3] == SET_CONTROL_RTS_OFF and not self.is_download_mode:
                reset_thread = threading.Thread(target=self._hard_reset_thread)
                reset_thread.daemon = True
                reset_thread.name = "hard_reset_thread"
                reset_thread.start()
                return
            elif suboption[2:3] == SET_CONTROL_DTR_ON and not self.is_download_mode:
                self.is_download_mode = True
                reset_thread = threading.Thread(target=self._reset_thread)
                reset_thread.daemon = True
                reset_thread.name = "reset_thread"
                reset_thread.start()
                return
            elif suboption[2:3] in [
                SET_CONTROL_DTR_ON,
                SET_CONTROL_RTS_ON,
                SET_CONTROL_RTS_OFF,
            ]:
                return
        # only in cases not handled above do the original implementation in PortManager
        super(EspPortManager, self)._telnet_process_subnegotiation(suboption)

    def _hard_reset_thread(self):
        """
        The reset logic used for hard resetting the chip.
        """
        if self.logger:
            self.logger.info("Activating hard reset in thread")
        HardReset(self.serial)()

    def _reset_thread(self):
        """
        The reset logic is used from esptool.py because the RTS and DTR signals
        cannot be retransmitted through RFC 2217 with proper timing.
        """
        if self.logger:
            self.logger.info("Activating reset in thread")

        delay = DEFAULT_RESET_DELAY
        if self.esp32r0_delay:
            delay += 0.5

        cfg_custom_reset_sequence = cfg.get("custom_reset_sequence")
        if cfg_custom_reset_sequence is not None:
            CustomReset(self.serial, cfg_custom_reset_sequence)()
        elif os.name != "nt":
            UnixTightReset(self.serial, delay)()
        else:
            ClassicReset(self.serial, delay)()
