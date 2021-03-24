#!/usr/bin/env python
#
# ESP8266 & ESP32 family ROM Bootloader Utility
# Copyright (C) 2014-2016 Fredrik Ahlberg, Angus Gratton, Espressif Systems (Shanghai) PTE LTD, other contributors as noted.
# https://github.com/espressif/esptool
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.

from __future__ import division, print_function

import argparse
import base64
import binascii
import copy
import hashlib
import inspect
import io
import itertools
import os
import shlex
import string
import struct
import sys
import time
import zlib

try:
    import serial
except ImportError:
    print("Pyserial is not installed for %s. Check the README for installation instructions." % (sys.executable))
    raise

# check 'serial' is 'pyserial' and not 'serial' https://github.com/espressif/esptool/issues/269
try:
    if "serialization" in serial.__doc__ and "deserialization" in serial.__doc__:
        raise ImportError("""
esptool.py depends on pyserial, but there is a conflict with a currently installed package named 'serial'.

You may be able to work around this by 'pip uninstall serial; pip install pyserial' \
but this may break other installed Python software that depends on 'serial'.

There is no good fix for this right now, apart from configuring virtualenvs. \
See https://github.com/espressif/esptool/issues/269#issuecomment-385298196 for discussion of the underlying issue(s).""")
except TypeError:
    pass  # __doc__ returns None for pyserial

try:
    import serial.tools.list_ports as list_ports
except ImportError:
    print("The installed version (%s) of pyserial appears to be too old for esptool.py (Python interpreter %s). "
          "Check the README for installation instructions." % (sys.VERSION, sys.executable))
    raise
except Exception:
    if sys.platform == "darwin":
        # swallow the exception, this is a known issue in pyserial+macOS Big Sur preview ref https://github.com/espressif/esptool/issues/540
        list_ports = None
    else:
        raise


__version__ = "3.1-dev"

MAX_UINT32 = 0xffffffff
MAX_UINT24 = 0xffffff

DEFAULT_TIMEOUT = 3                   # timeout for most flash operations
START_FLASH_TIMEOUT = 20              # timeout for starting flash (may perform erase)
CHIP_ERASE_TIMEOUT = 120              # timeout for full chip erase
MAX_TIMEOUT = CHIP_ERASE_TIMEOUT * 2  # longest any command can run
SYNC_TIMEOUT = 0.1                    # timeout for syncing with bootloader
MD5_TIMEOUT_PER_MB = 8                # timeout (per megabyte) for calculating md5sum
ERASE_REGION_TIMEOUT_PER_MB = 30      # timeout (per megabyte) for erasing a region
ERASE_WRITE_TIMEOUT_PER_MB = 40       # timeout (per megabyte) for erasing and writing data
MEM_END_ROM_TIMEOUT = 0.05            # special short timeout for ESP_MEM_END, as it may never respond
DEFAULT_SERIAL_WRITE_TIMEOUT = 10     # timeout for serial port write
DEFAULT_CONNECT_ATTEMPTS = 7          # default number of times to try connection


def timeout_per_mb(seconds_per_mb, size_bytes):
    """ Scales timeouts which are size-specific """
    result = seconds_per_mb * (size_bytes / 1e6)
    if result < DEFAULT_TIMEOUT:
        return DEFAULT_TIMEOUT
    return result


def _chip_to_rom_loader(chip):
    return {
        'esp8266': ESP8266ROM,
        'esp32': ESP32ROM,
        'esp32s2': ESP32S2ROM,
        'esp32s3beta2': ESP32S3BETA2ROM,
        'esp32s3beta3': ESP32S3BETA3ROM,
        'esp32c3': ESP32C3ROM,
    }[chip]


def get_default_connected_device(serial_list, port, connect_attempts, initial_baud, chip='auto', trace=False,
                                 before='default_reset'):
    _esp = None
    for each_port in reversed(serial_list):
        print("Serial port %s" % each_port)
        try:
            if chip == 'auto':
                _esp = ESPLoader.detect_chip(each_port, initial_baud, before, trace,
                                             connect_attempts)
            else:
                chip_class = _chip_to_rom_loader(chip)
                _esp = chip_class(each_port, initial_baud, trace)
                _esp.connect(before, connect_attempts)
            break
        except (FatalError, OSError) as err:
            if port is not None:
                raise
            print("%s failed to connect: %s" % (each_port, err))
            _esp = None
    return _esp


DETECTED_FLASH_SIZES = {0x12: '256KB', 0x13: '512KB', 0x14: '1MB',
                        0x15: '2MB', 0x16: '4MB', 0x17: '8MB',
                        0x18: '16MB', 0x19: '32MB', 0x1a: '64MB'}


def check_supported_function(func, check_func):
    """
    Decorator implementation that wraps a check around an ESPLoader
    bootloader function to check if it's supported.

    This is used to capture the multidimensional differences in
    functionality between the ESP8266 & ESP32/32S2/32S3/32C3 ROM loaders, and the
    software stub that runs on both. Not possible to do this cleanly
    via inheritance alone.
    """
    def inner(*args, **kwargs):
        obj = args[0]
        if check_func(obj):
            return func(*args, **kwargs)
        else:
            raise NotImplementedInROMError(obj, func)
    return inner


def stub_function_only(func):
    """ Attribute for a function only supported in the software stub loader """
    return check_supported_function(func, lambda o: o.IS_STUB)


def stub_and_esp32_function_only(func):
    """ Attribute for a function only supported by software stubs or ESP32/32S2/32S3/32C3 ROM """
    return check_supported_function(func, lambda o: o.IS_STUB or isinstance(o, ESP32ROM))


PYTHON2 = sys.version_info[0] < 3  # True if on pre-Python 3

# Function to return nth byte of a bitstring
# Different behaviour on Python 2 vs 3
if PYTHON2:
    def byte(bitstr, index):
        return ord(bitstr[index])
else:
    def byte(bitstr, index):
        return bitstr[index]

# Provide a 'basestring' class on Python 3
try:
    basestring
except NameError:
    basestring = str


def print_overwrite(message, last_line=False):
    """ Print a message, overwriting the currently printed line.

    If last_line is False, don't append a newline at the end (expecting another subsequent call will overwrite this one.)

    After a sequence of calls with last_line=False, call once with last_line=True.

    If output is not a TTY (for example redirected a pipe), no overwriting happens and this function is the same as print().
    """
    if sys.stdout.isatty():
        print("\r%s" % message, end='\n' if last_line else '')
    else:
        print(message)


def _mask_to_shift(mask):
    """ Return the index of the least significant bit in the mask """
    shift = 0
    while mask & 0x1 == 0:
        shift += 1
        mask >>= 1
    return shift


def esp8266_function_only(func):
    """ Attribute for a function only supported on ESP8266 """
    return check_supported_function(func, lambda o: o.CHIP_NAME == "ESP8266")


class ESPLoader(object):
    """ Base class providing access to ESP ROM & software stub bootloaders.
    Subclasses provide ESP8266 & ESP32 specific functionality.

    Don't instantiate this base class directly, either instantiate a subclass or
    call ESPLoader.detect_chip() which will interrogate the chip and return the
    appropriate subclass instance.

    """
    CHIP_NAME = "Espressif device"
    IS_STUB = False

    DEFAULT_PORT = "/dev/ttyUSB0"

    # Commands supported by ESP8266 ROM bootloader
    ESP_FLASH_BEGIN = 0x02
    ESP_FLASH_DATA  = 0x03
    ESP_FLASH_END   = 0x04
    ESP_MEM_BEGIN   = 0x05
    ESP_MEM_END     = 0x06
    ESP_MEM_DATA    = 0x07
    ESP_SYNC        = 0x08
    ESP_WRITE_REG   = 0x09
    ESP_READ_REG    = 0x0a

    # Some comands supported by ESP32 ROM bootloader (or -8266 w/ stub)
    ESP_SPI_SET_PARAMS = 0x0B
    ESP_SPI_ATTACH     = 0x0D
    ESP_READ_FLASH_SLOW  = 0x0e  # ROM only, much slower than the stub flash read
    ESP_CHANGE_BAUDRATE = 0x0F
    ESP_FLASH_DEFL_BEGIN = 0x10
    ESP_FLASH_DEFL_DATA  = 0x11
    ESP_FLASH_DEFL_END   = 0x12
    ESP_SPI_FLASH_MD5    = 0x13

    # Commands supported by ESP32-S2/S3/C3 ROM bootloader only
    ESP_GET_SECURITY_INFO = 0x14

    # Some commands supported by stub only
    ESP_ERASE_FLASH = 0xD0
    ESP_ERASE_REGION = 0xD1
    ESP_READ_FLASH = 0xD2
    ESP_RUN_USER_CODE = 0xD3

    # Flash encryption encrypted data command
    ESP_FLASH_ENCRYPT_DATA = 0xD4

    # Response code(s) sent by ROM
    ROM_INVALID_RECV_MSG = 0x05   # response if an invalid message is received

    # Maximum block sized for RAM and Flash writes, respectively.
    ESP_RAM_BLOCK   = 0x1800

    FLASH_WRITE_SIZE = 0x400

    # Default baudrate. The ROM auto-bauds, so we can use more or less whatever we want.
    ESP_ROM_BAUD    = 115200

    # First byte of the application image
    ESP_IMAGE_MAGIC = 0xe9

    # Initial state for the checksum routine
    ESP_CHECKSUM_MAGIC = 0xef

    # Flash sector size, minimum unit of erase.
    FLASH_SECTOR_SIZE = 0x1000

    UART_DATE_REG_ADDR = 0x60000078

    CHIP_DETECT_MAGIC_REG_ADDR = 0x40001000  # This ROM address has a different value on each chip model

    UART_CLKDIV_MASK = 0xFFFFF

    # Memory addresses
    IROM_MAP_START = 0x40200000
    IROM_MAP_END = 0x40300000

    # The number of bytes in the UART response that signify command status
    STATUS_BYTES_LENGTH = 2

    def __init__(self, port=DEFAULT_PORT, baud=ESP_ROM_BAUD, trace_enabled=False):
        """Base constructor for ESPLoader bootloader interaction

        Don't call this constructor, either instantiate ESP8266ROM
        or ESP32ROM, or use ESPLoader.detect_chip().

        This base class has all of the instance methods for bootloader
        functionality supported across various chips & stub
        loaders. Subclasses replace the functions they don't support
        with ones which throw NotImplementedInROMError().

        """
        self.secure_download_mode = False  # flag is set to True if esptool detects the ROM is in Secure Download Mode

        if isinstance(port, basestring):
            self._port = serial.serial_for_url(port)
        else:
            self._port = port
        self._slip_reader = slip_reader(self._port, self.trace)
        # setting baud rate in a separate step is a workaround for
        # CH341 driver on some Linux versions (this opens at 9600 then
        # sets), shouldn't matter for other platforms/drivers. See
        # https://github.com/espressif/esptool/issues/44#issuecomment-107094446
        self._set_port_baudrate(baud)
        self._trace_enabled = trace_enabled
        # set write timeout, to prevent esptool blocked at write forever.
        try:
            self._port.write_timeout = DEFAULT_SERIAL_WRITE_TIMEOUT
        except NotImplementedError:
            # no write timeout for RFC2217 ports
            # need to set the property back to None or it will continue to fail
            self._port.write_timeout = None

    @property
    def serial_port(self):
        return self._port.port

    def _set_port_baudrate(self, baud):
        try:
            self._port.baudrate = baud
        except IOError:
            raise FatalError("Failed to set baud rate %d. The driver may not support this rate." % baud)

    @staticmethod
    def detect_chip(port=DEFAULT_PORT, baud=ESP_ROM_BAUD, connect_mode='default_reset', trace_enabled=False,
                    connect_attempts=DEFAULT_CONNECT_ATTEMPTS):
        """ Use serial access to detect the chip type.

        We use the UART's datecode register for this, it's mapped at
        the same address on ESP8266 & ESP32 so we can use one
        memory read and compare to the datecode register for each chip
        type.

        This routine automatically performs ESPLoader.connect() (passing
        connect_mode parameter) as part of querying the chip.
        """
        detect_port = ESPLoader(port, baud, trace_enabled=trace_enabled)
        detect_port.connect(connect_mode, connect_attempts, detecting=True)
        try:
            print('Detecting chip type...', end='')
            sys.stdout.flush()
            chip_magic_value = detect_port.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR)

            for cls in [ESP8266ROM, ESP32ROM, ESP32S2ROM, ESP32S3BETA2ROM, ESP32S3BETA3ROM, ESP32C3ROM]:
                if chip_magic_value in cls.CHIP_DETECT_MAGIC_VALUE:
                    # don't connect a second time
                    inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                    inst._post_connect()
                    print(' %s' % inst.CHIP_NAME, end='')
                    return inst
        except UnsupportedCommandError:
            raise FatalError("Unsupported Command Error received. Probably this means Secure Download Mode is enabled, "
                             "autodetection will not work. Need to manually specify the chip.")
        finally:
            print('')  # end line
        raise FatalError("Unexpected CHIP magic value 0x%08x. Failed to autodetect chip type." % (chip_magic_value))

    """ Read a SLIP packet from the serial port """
    def read(self):
        return next(self._slip_reader)

    """ Write bytes to the serial port while performing SLIP escaping """
    def write(self, packet):
        buf = b'\xc0' \
              + (packet.replace(b'\xdb', b'\xdb\xdd').replace(b'\xc0', b'\xdb\xdc')) \
              + b'\xc0'
        self.trace("Write %d bytes: %s", len(buf), HexFormatter(buf))
        self._port.write(buf)

    def trace(self, message, *format_args):
        if self._trace_enabled:
            now = time.time()
            try:

                delta = now - self._last_trace
            except AttributeError:
                delta = 0.0
            self._last_trace = now
            prefix = "TRACE +%.3f " % delta
            print(prefix + (message % format_args))

    """ Calculate checksum of a blob, as it is defined by the ROM """
    @staticmethod
    def checksum(data, state=ESP_CHECKSUM_MAGIC):
        for b in data:
            if type(b) is int:  # python 2/3 compat
                state ^= b
            else:
                state ^= ord(b)

        return state

    """ Send a request and read the response """
    def command(self, op=None, data=b"", chk=0, wait_response=True, timeout=DEFAULT_TIMEOUT):
        saved_timeout = self._port.timeout
        new_timeout = min(timeout, MAX_TIMEOUT)
        if new_timeout != saved_timeout:
            self._port.timeout = new_timeout

        try:
            if op is not None:
                self.trace("command op=0x%02x data len=%s wait_response=%d timeout=%.3f data=%s",
                           op, len(data), 1 if wait_response else 0, timeout, HexFormatter(data))
                pkt = struct.pack(b'<BBHI', 0x00, op, len(data), chk) + data
                self.write(pkt)

            if not wait_response:
                return

            self._port.flush()

            # tries to get a response until that response has the
            # same operation as the request or a retries limit has
            # exceeded. This is needed for some esp8266s that
            # reply with more sync responses than expected.
            for retry in range(100):
                p = self.read()
                if len(p) < 8:
                    continue
                (resp, op_ret, len_ret, val) = struct.unpack('<BBHI', p[:8])
                if resp != 1:
                    continue
                data = p[8:]

                if op is None or op_ret == op:
                    return val, data
                if byte(data, 0) != 0 and byte(data, 1) == self.ROM_INVALID_RECV_MSG:
                    self.flush_input()  # Unsupported read_reg can result in more than one error response for some reason
                    raise UnsupportedCommandError(self, op)

        finally:
            if new_timeout != saved_timeout:
                self._port.timeout = saved_timeout

        raise FatalError("Response doesn't match request")

    def check_command(self, op_description, op=None, data=b'', chk=0, timeout=DEFAULT_TIMEOUT):
        """
        Execute a command with 'command', check the result code and throw an appropriate
        FatalError if it fails.

        Returns the "result" of a successful command.
        """
        val, data = self.command(op, data, chk, timeout=timeout)

        # things are a bit weird here, bear with us

        # the status bytes are the last 2/4 bytes in the data (depending on chip)
        if len(data) < self.STATUS_BYTES_LENGTH:
            raise FatalError("Failed to %s. Only got %d byte status response." % (op_description, len(data)))
        status_bytes = data[-self.STATUS_BYTES_LENGTH:]
        # we only care if the first one is non-zero. If it is, the second byte is a reason.
        if byte(status_bytes, 0) != 0:
            raise FatalError.WithResult('Failed to %s' % op_description, status_bytes)

        # if we had more data than just the status bytes, return it as the result
        # (this is used by the md5sum command, maybe other commands?)
        if len(data) > self.STATUS_BYTES_LENGTH:
            return data[:-self.STATUS_BYTES_LENGTH]
        else:  # otherwise, just return the 'val' field which comes from the reply header (this is used by read_reg)
            return val

    def flush_input(self):
        self._port.flushInput()
        self._slip_reader = slip_reader(self._port, self.trace)

    def sync(self):
        self.command(self.ESP_SYNC, b'\x07\x07\x12\x20' + 32 * b'\x55',
                     timeout=SYNC_TIMEOUT)
        for i in range(7):
            self.command()

    def _setDTR(self, state):
        self._port.setDTR(state)

    def _setRTS(self, state):
        self._port.setRTS(state)
        # Work-around for adapters on Windows using the usbser.sys driver:
        # generate a dummy change to DTR so that the set-control-line-state
        # request is sent with the updated RTS state and the same DTR state
        self._port.setDTR(self._port.dtr)

    def _connect_attempt(self, mode='default_reset', esp32r0_delay=False):
        """ A single connection attempt, with esp32r0 workaround options """
        # esp32r0_delay is a workaround for bugs with the most common auto reset
        # circuit and Windows, if the EN pin on the dev board does not have
        # enough capacitance.
        #
        # Newer dev boards shouldn't have this problem (higher value capacitor
        # on the EN pin), and ESP32 revision 1 can't use this workaround as it
        # relies on a silicon bug.
        #
        # Details: https://github.com/espressif/esptool/issues/136
        last_error = None

        # If we're doing no_sync, we're likely communicating as a pass through
        # with an intermediate device to the ESP32
        if mode == "no_reset_no_sync":
            return last_error

        # issue reset-to-bootloader:
        # RTS = either CH_PD/EN or nRESET (both active low = chip in reset
        # DTR = GPIO0 (active low = boot to flasher)
        #
        # DTR & RTS are active low signals,
        # ie True = pin @ 0V, False = pin @ VCC.
        if mode != 'no_reset':
            self._setDTR(False)  # IO0=HIGH
            self._setRTS(True)   # EN=LOW, chip in reset
            time.sleep(0.1)
            if esp32r0_delay:
                # Some chips are more likely to trigger the esp32r0
                # watchdog reset silicon bug if they're held with EN=LOW
                # for a longer period
                time.sleep(1.2)
            self._setDTR(True)   # IO0=LOW
            self._setRTS(False)  # EN=HIGH, chip out of reset
            if esp32r0_delay:
                # Sleep longer after reset.
                # This workaround only works on revision 0 ESP32 chips,
                # it exploits a silicon bug spurious watchdog reset.
                time.sleep(0.4)  # allow watchdog reset to occur
            time.sleep(0.05)
            self._setDTR(False)  # IO0=HIGH, done

        for _ in range(5):
            try:
                self.flush_input()
                self._port.flushOutput()
                self.sync()
                return None
            except FatalError as e:
                if esp32r0_delay:
                    print('_', end='')
                else:
                    print('.', end='')
                sys.stdout.flush()
                time.sleep(0.05)
                last_error = e
        return last_error

    def get_memory_region(self, name):
        """ Returns a tuple of (start, end) for the memory map entry with the given name, or None if it doesn't exist
        """
        try:
            return [(start, end) for (start, end, n) in self.MEMORY_MAP if n == name][0]
        except IndexError:
            return None

    def connect(self, mode='default_reset', attempts=DEFAULT_CONNECT_ATTEMPTS, detecting=False):
        """ Try connecting repeatedly until successful, or giving up """
        print('Connecting...', end='')
        sys.stdout.flush()
        last_error = None

        try:
            for _ in range(attempts) if attempts > 0 else itertools.count():
                last_error = self._connect_attempt(mode=mode, esp32r0_delay=False)
                if last_error is None:
                    break
                last_error = self._connect_attempt(mode=mode, esp32r0_delay=True)
                if last_error is None:
                    break
        finally:
            print('')  # end 'Connecting...' line

        if last_error is not None:
            raise FatalError('Failed to connect to %s: %s' % (self.CHIP_NAME, last_error))

        if not detecting:
            try:
                # check the date code registers match what we expect to see
                chip_magic_value = self.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR)
                if chip_magic_value not in self.CHIP_DETECT_MAGIC_VALUE:
                    actually = None
                    for cls in [ESP8266ROM, ESP32ROM, ESP32S2ROM, ESP32S3BETA2ROM, ESP32S3BETA3ROM, ESP32C3ROM]:
                        if chip_magic_value in cls.CHIP_DETECT_MAGIC_VALUE:
                            actually = cls
                            break
                    if actually is None:
                        print(("WARNING: This chip doesn't appear to be a %s (chip magic value 0x%08x). "
                               "Probably it is unsupported by this version of esptool.") % (self.CHIP_NAME, chip_magic_value))
                    else:
                        raise FatalError("This chip is %s not %s. Wrong --chip argument?" % (actually.CHIP_NAME, self.CHIP_NAME))
            except UnsupportedCommandError:
                self.secure_download_mode = True
            self._post_connect()

    def _post_connect(self):
        """
        Additional initialization hook, may be overridden by the chip-specific class.
        Gets called after connect, and after auto-detection.
        """
        pass

    def read_reg(self, addr, timeout=DEFAULT_TIMEOUT):
        """ Read memory address in target """
        # we don't call check_command here because read_reg() function is called
        # when detecting chip type, and the way we check for success (STATUS_BYTES_LENGTH) is different
        # for different chip types (!)
        val, data = self.command(self.ESP_READ_REG, struct.pack('<I', addr), timeout=timeout)
        if byte(data, 0) != 0:
            raise FatalError.WithResult("Failed to read register address %08x" % addr, data)
        return val

    """ Write to memory address in target """
    def write_reg(self, addr, value, mask=0xFFFFFFFF, delay_us=0, delay_after_us=0):
        command = struct.pack('<IIII', addr, value, mask, delay_us)
        if delay_after_us > 0:
            # add a dummy write to a date register as an excuse to have a delay
            command += struct.pack('<IIII', self.UART_DATE_REG_ADDR, 0, 0, delay_after_us)

        return self.check_command("write target memory", self.ESP_WRITE_REG, command)

    def update_reg(self, addr, mask, new_val):
        """ Update register at 'addr', replace the bits masked out by 'mask'
        with new_val. new_val is shifted left to match the LSB of 'mask'

        Returns just-written value of register.
        """
        shift = _mask_to_shift(mask)
        val = self.read_reg(addr)
        val &= ~mask
        val |= (new_val << shift) & mask
        self.write_reg(addr, val)

        return val

    """ Start downloading an application image to RAM """
    def mem_begin(self, size, blocks, blocksize, offset):
        if self.IS_STUB:  # check we're not going to overwrite a running stub with this data
            stub = self.STUB_CODE
            load_start = offset
            load_end = offset + size
            for (start, end) in [(stub["data_start"], stub["data_start"] + len(stub["data"])),
                                 (stub["text_start"], stub["text_start"] + len(stub["text"]))]:
                if load_start < end and load_end > start:
                    raise FatalError(("Software loader is resident at 0x%08x-0x%08x. "
                                      "Can't load binary at overlapping address range 0x%08x-0x%08x. "
                                      "Either change binary loading address, or use the --no-stub "
                                      "option to disable the software loader.") % (start, end, load_start, load_end))

        return self.check_command("enter RAM download mode", self.ESP_MEM_BEGIN,
                                  struct.pack('<IIII', size, blocks, blocksize, offset))

    """ Send a block of an image to RAM """
    def mem_block(self, data, seq):
        return self.check_command("write to target RAM", self.ESP_MEM_DATA,
                                  struct.pack('<IIII', len(data), seq, 0, 0) + data,
                                  self.checksum(data))

    """ Leave download mode and run the application """
    def mem_finish(self, entrypoint=0):
        # Sending ESP_MEM_END usually sends a correct response back, however sometimes
        # (with ROM loader) the executed code may reset the UART or change the baud rate
        # before the transmit FIFO is empty. So in these cases we set a short timeout and
        # ignore errors.
        timeout = DEFAULT_TIMEOUT if self.IS_STUB else MEM_END_ROM_TIMEOUT
        data = struct.pack('<II', int(entrypoint == 0), entrypoint)
        try:
            return self.check_command("leave RAM download mode", self.ESP_MEM_END,
                                      data=data, timeout=timeout)
        except FatalError:
            if self.IS_STUB:
                raise
            pass

    """ Start downloading to Flash (performs an erase)

    Returns number of blocks (of size self.FLASH_WRITE_SIZE) to write.
    """
    def flash_begin(self, size, offset, begin_rom_encrypted=False):
        num_blocks = (size + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE
        erase_size = self.get_erase_size(offset, size)

        t = time.time()
        if self.IS_STUB:
            timeout = DEFAULT_TIMEOUT
        else:
            timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, size)  # ROM performs the erase up front

        params = struct.pack('<IIII', erase_size, num_blocks, self.FLASH_WRITE_SIZE, offset)
        if isinstance(self, (ESP32S2ROM, ESP32S3BETA2ROM, ESP32S3BETA3ROM, ESP32C3ROM)) and not self.IS_STUB:
            params += struct.pack('<I', 1 if begin_rom_encrypted else 0)
        self.check_command("enter Flash download mode", self.ESP_FLASH_BEGIN,
                           params, timeout=timeout)
        if size != 0 and not self.IS_STUB:
            print("Took %.2fs to erase flash block" % (time.time() - t))
        return num_blocks

    """ Write block to flash """
    def flash_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        self.check_command("write to target Flash after seq %d" % seq,
                           self.ESP_FLASH_DATA,
                           struct.pack('<IIII', len(data), seq, 0, 0) + data,
                           self.checksum(data),
                           timeout=timeout)

    """ Encrypt before writing to flash """
    def flash_encrypt_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        if isinstance(self, (ESP32S2ROM, ESP32C3ROM)) and not self.IS_STUB:
            # ROM support performs the encrypted writes via the normal write command,
            # triggered by flash_begin(begin_rom_encrypted=True)
            return self.flash_block(data, seq, timeout)

        self.check_command("Write encrypted to target Flash after seq %d" % seq,
                           self.ESP_FLASH_ENCRYPT_DATA,
                           struct.pack('<IIII', len(data), seq, 0, 0) + data,
                           self.checksum(data),
                           timeout=timeout)

    """ Leave flash mode and run/reboot """
    def flash_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        # stub sends a reply to this command
        self.check_command("leave Flash mode", self.ESP_FLASH_END, pkt)

    """ Run application code in flash """
    def run(self, reboot=False):
        # Fake flash begin immediately followed by flash end
        self.flash_begin(0, 0)
        self.flash_finish(reboot)

    """ Read SPI flash manufacturer and device id """
    def flash_id(self):
        SPIFLASH_RDID = 0x9F
        return self.run_spiflash_command(SPIFLASH_RDID, b"", 24)

    def get_security_info(self):
        # TODO: this only works on the ESP32S2 ROM code loader and needs to work in stub loader also
        res = self.check_command('get security info', self.ESP_GET_SECURITY_INFO, b'')
        res = struct.unpack("<IBBBBBBBB", res)
        flags, flash_crypt_cnt, key_purposes = res[0], res[1], res[2:]
        # TODO: pack this as some kind of better data type
        return (flags, flash_crypt_cnt, key_purposes)

    @classmethod
    def parse_flash_size_arg(cls, arg):
        try:
            return cls.FLASH_SIZES[arg]
        except KeyError:
            raise FatalError("Flash size '%s' is not supported by this chip type. Supported sizes: %s"
                             % (arg, ", ".join(cls.FLASH_SIZES.keys())))

    def run_stub(self, stub=None):
        if stub is None:
            if self.IS_STUB:
                raise FatalError("Not possible for a stub to load another stub (memory likely to overlap.)")
            stub = self.STUB_CODE

        # Upload
        print("Uploading stub...")
        for field in ['text', 'data']:
            if field in stub:
                offs = stub[field + "_start"]
                length = len(stub[field])
                blocks = (length + self.ESP_RAM_BLOCK - 1) // self.ESP_RAM_BLOCK
                self.mem_begin(length, blocks, self.ESP_RAM_BLOCK, offs)
                for seq in range(blocks):
                    from_offs = seq * self.ESP_RAM_BLOCK
                    to_offs = from_offs + self.ESP_RAM_BLOCK
                    self.mem_block(stub[field][from_offs:to_offs], seq)
        print("Running stub...")
        self.mem_finish(stub['entry'])

        p = self.read()
        if p != b'OHAI':
            raise FatalError("Failed to start stub. Unexpected response: %s" % p)
        print("Stub running...")
        return self.STUB_CLASS(self)

    @stub_and_esp32_function_only
    def flash_defl_begin(self, size, compsize, offset):
        """ Start downloading compressed data to Flash (performs an erase)

        Returns number of blocks (size self.FLASH_WRITE_SIZE) to write.
        """
        num_blocks = (compsize + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE
        erase_blocks = (size + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE

        t = time.time()
        if self.IS_STUB:
            write_size = size  # stub expects number of bytes here, manages erasing internally
            timeout = DEFAULT_TIMEOUT
        else:
            write_size = erase_blocks * self.FLASH_WRITE_SIZE  # ROM expects rounded up to erase block size
            timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, write_size)  # ROM performs the erase up front
        print("Compressed %d bytes to %d..." % (size, compsize))
        params = struct.pack('<IIII', write_size, num_blocks, self.FLASH_WRITE_SIZE, offset)
        if isinstance(self, (ESP32S2ROM, ESP32S3BETA2ROM, ESP32S3BETA3ROM, ESP32C3ROM)) and not self.IS_STUB:
            params += struct.pack('<I', 0)  # extra param is to enter encrypted flash mode via ROM (not supported currently)
        self.check_command("enter compressed flash mode", self.ESP_FLASH_DEFL_BEGIN, params, timeout=timeout)
        if size != 0 and not self.IS_STUB:
            # (stub erases as it writes, but ROM loaders erase on begin)
            print("Took %.2fs to erase flash block" % (time.time() - t))
        return num_blocks

    """ Write block to flash, send compressed """
    @stub_and_esp32_function_only
    def flash_defl_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        self.check_command("write compressed data to flash after seq %d" % seq,
                           self.ESP_FLASH_DEFL_DATA, struct.pack('<IIII', len(data), seq, 0, 0) + data, self.checksum(data), timeout=timeout)

    """ Leave compressed flash mode and run/reboot """
    @stub_and_esp32_function_only
    def flash_defl_finish(self, reboot=False):
        if not reboot and not self.IS_STUB:
            # skip sending flash_finish to ROM loader, as this
            # exits the bootloader. Stub doesn't do this.
            return
        pkt = struct.pack('<I', int(not reboot))
        self.check_command("leave compressed flash mode", self.ESP_FLASH_DEFL_END, pkt)
        self.in_bootloader = False

    @stub_and_esp32_function_only
    def flash_md5sum(self, addr, size):
        # the MD5 command returns additional bytes in the standard
        # command reply slot
        timeout = timeout_per_mb(MD5_TIMEOUT_PER_MB, size)
        res = self.check_command('calculate md5sum', self.ESP_SPI_FLASH_MD5, struct.pack('<IIII', addr, size, 0, 0),
                                 timeout=timeout)

        if len(res) == 32:
            return res.decode("utf-8")  # already hex formatted
        elif len(res) == 16:
            return hexify(res).lower()
        else:
            raise FatalError("MD5Sum command returned unexpected result: %r" % res)

    @stub_and_esp32_function_only
    def change_baud(self, baud):
        print("Changing baud rate to %d" % baud)
        # stub takes the new baud rate and the old one
        second_arg = self._port.baudrate if self.IS_STUB else 0
        self.command(self.ESP_CHANGE_BAUDRATE, struct.pack('<II', baud, second_arg))
        print("Changed.")
        self._set_port_baudrate(baud)
        time.sleep(0.05)  # get rid of crap sent during baud rate change
        self.flush_input()

    @stub_function_only
    def erase_flash(self):
        # depending on flash chip model the erase may take this long (maybe longer!)
        self.check_command("erase flash", self.ESP_ERASE_FLASH,
                           timeout=CHIP_ERASE_TIMEOUT)

    @stub_function_only
    def erase_region(self, offset, size):
        if offset % self.FLASH_SECTOR_SIZE != 0:
            raise FatalError("Offset to erase from must be a multiple of 4096")
        if size % self.FLASH_SECTOR_SIZE != 0:
            raise FatalError("Size of data to erase must be a multiple of 4096")
        timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, size)
        self.check_command("erase region", self.ESP_ERASE_REGION, struct.pack('<II', offset, size), timeout=timeout)

    def read_flash_slow(self, offset, length, progress_fn):
        raise NotImplementedInROMError(self, self.read_flash_slow)

    def read_flash(self, offset, length, progress_fn=None):
        if not self.IS_STUB:
            return self.read_flash_slow(offset, length, progress_fn)  # ROM-only routine

        # issue a standard bootloader command to trigger the read
        self.check_command("read flash", self.ESP_READ_FLASH,
                           struct.pack('<IIII',
                                       offset,
                                       length,
                                       self.FLASH_SECTOR_SIZE,
                                       64))
        # now we expect (length // block_size) SLIP frames with the data
        data = b''
        while len(data) < length:
            p = self.read()
            data += p
            if len(data) < length and len(p) < self.FLASH_SECTOR_SIZE:
                raise FatalError('Corrupt data, expected 0x%x bytes but received 0x%x bytes' % (self.FLASH_SECTOR_SIZE, len(p)))
            self.write(struct.pack('<I', len(data)))
            if progress_fn and (len(data) % 1024 == 0 or len(data) == length):
                progress_fn(len(data), length)
        if progress_fn:
            progress_fn(len(data), length)
        if len(data) > length:
            raise FatalError('Read more than expected')

        digest_frame = self.read()
        if len(digest_frame) != 16:
            raise FatalError('Expected digest, got: %s' % hexify(digest_frame))
        expected_digest = hexify(digest_frame).upper()
        digest = hashlib.md5(data).hexdigest().upper()
        if digest != expected_digest:
            raise FatalError('Digest mismatch: expected %s, got %s' % (expected_digest, digest))
        return data

    def flash_spi_attach(self, hspi_arg):
        """Send SPI attach command to enable the SPI flash pins

        ESP8266 ROM does this when you send flash_begin, ESP32 ROM
        has it as a SPI command.
        """
        # last 3 bytes in ESP_SPI_ATTACH argument are reserved values
        arg = struct.pack('<I', hspi_arg)
        if not self.IS_STUB:
            # ESP32 ROM loader takes additional 'is legacy' arg, which is not
            # currently supported in the stub loader or esptool.py (as it's not usually needed.)
            is_legacy = 0
            arg += struct.pack('BBBB', is_legacy, 0, 0, 0)
        self.check_command("configure SPI flash pins", ESP32ROM.ESP_SPI_ATTACH, arg)

    def flash_set_parameters(self, size):
        """Tell the ESP bootloader the parameters of the chip

        Corresponds to the "flashchip" data structure that the ROM
        has in RAM.

        'size' is in bytes.

        All other flash parameters are currently hardcoded (on ESP8266
        these are mostly ignored by ROM code, on ESP32 I'm not sure.)
        """
        fl_id = 0
        total_size = size
        block_size = 64 * 1024
        sector_size = 4 * 1024
        page_size = 256
        status_mask = 0xffff
        self.check_command("set SPI params", ESP32ROM.ESP_SPI_SET_PARAMS,
                           struct.pack('<IIIIII', fl_id, total_size, block_size, sector_size, page_size, status_mask))

    def run_spiflash_command(self, spiflash_command, data=b"", read_bits=0):
        """Run an arbitrary SPI flash command.

        This function uses the "USR_COMMAND" functionality in the ESP
        SPI hardware, rather than the precanned commands supported by
        hardware. So the value of spiflash_command is an actual command
        byte, sent over the wire.

        After writing command byte, writes 'data' to MOSI and then
        reads back 'read_bits' of reply on MISO. Result is a number.
        """

        # SPI_USR register flags
        SPI_USR_COMMAND = (1 << 31)
        SPI_USR_MISO    = (1 << 28)
        SPI_USR_MOSI    = (1 << 27)

        # SPI registers, base address differs ESP32* vs 8266
        base = self.SPI_REG_BASE
        SPI_CMD_REG       = base + 0x00
        SPI_USR_REG       = base + self.SPI_USR_OFFS
        SPI_USR1_REG      = base + self.SPI_USR1_OFFS
        SPI_USR2_REG      = base + self.SPI_USR2_OFFS
        SPI_W0_REG        = base + self.SPI_W0_OFFS

        # following two registers are ESP32 & 32S2/32C3 only
        if self.SPI_MOSI_DLEN_OFFS is not None:
            # ESP32/32S2/32C3 has a more sophisticated way to set up "user" commands
            def set_data_lengths(mosi_bits, miso_bits):
                SPI_MOSI_DLEN_REG = base + self.SPI_MOSI_DLEN_OFFS
                SPI_MISO_DLEN_REG = base + self.SPI_MISO_DLEN_OFFS
                if mosi_bits > 0:
                    self.write_reg(SPI_MOSI_DLEN_REG, mosi_bits - 1)
                if miso_bits > 0:
                    self.write_reg(SPI_MISO_DLEN_REG, miso_bits - 1)
        else:

            def set_data_lengths(mosi_bits, miso_bits):
                SPI_DATA_LEN_REG = SPI_USR1_REG
                SPI_MOSI_BITLEN_S = 17
                SPI_MISO_BITLEN_S = 8
                mosi_mask = 0 if (mosi_bits == 0) else (mosi_bits - 1)
                miso_mask = 0 if (miso_bits == 0) else (miso_bits - 1)
                self.write_reg(SPI_DATA_LEN_REG,
                               (miso_mask << SPI_MISO_BITLEN_S) | (
                                   mosi_mask << SPI_MOSI_BITLEN_S))

        # SPI peripheral "command" bitmasks for SPI_CMD_REG
        SPI_CMD_USR  = (1 << 18)

        # shift values
        SPI_USR2_COMMAND_LEN_SHIFT = 28

        if read_bits > 32:
            raise FatalError("Reading more than 32 bits back from a SPI flash operation is unsupported")
        if len(data) > 64:
            raise FatalError("Writing more than 64 bytes of data with one SPI command is unsupported")

        data_bits = len(data) * 8
        old_spi_usr = self.read_reg(SPI_USR_REG)
        old_spi_usr2 = self.read_reg(SPI_USR2_REG)
        flags = SPI_USR_COMMAND
        if read_bits > 0:
            flags |= SPI_USR_MISO
        if data_bits > 0:
            flags |= SPI_USR_MOSI
        set_data_lengths(data_bits, read_bits)
        self.write_reg(SPI_USR_REG, flags)
        self.write_reg(SPI_USR2_REG,
                       (7 << SPI_USR2_COMMAND_LEN_SHIFT) | spiflash_command)
        if data_bits == 0:
            self.write_reg(SPI_W0_REG, 0)  # clear data register before we read it
        else:
            data = pad_to(data, 4, b'\00')  # pad to 32-bit multiple
            words = struct.unpack("I" * (len(data) // 4), data)
            next_reg = SPI_W0_REG
            for word in words:
                self.write_reg(next_reg, word)
                next_reg += 4
        self.write_reg(SPI_CMD_REG, SPI_CMD_USR)

        def wait_done():
            for _ in range(10):
                if (self.read_reg(SPI_CMD_REG) & SPI_CMD_USR) == 0:
                    return
            raise FatalError("SPI command did not complete in time")
        wait_done()

        status = self.read_reg(SPI_W0_REG)
        # restore some SPI controller registers
        self.write_reg(SPI_USR_REG, old_spi_usr)
        self.write_reg(SPI_USR2_REG, old_spi_usr2)
        return status

    def read_status(self, num_bytes=2):
        """Read up to 24 bits (num_bytes) of SPI flash status register contents
        via RDSR, RDSR2, RDSR3 commands

        Not all SPI flash supports all three commands. The upper 1 or 2
        bytes may be 0xFF.
        """
        SPIFLASH_RDSR  = 0x05
        SPIFLASH_RDSR2 = 0x35
        SPIFLASH_RDSR3 = 0x15

        status = 0
        shift = 0
        for cmd in [SPIFLASH_RDSR, SPIFLASH_RDSR2, SPIFLASH_RDSR3][0:num_bytes]:
            status += self.run_spiflash_command(cmd, read_bits=8) << shift
            shift += 8
        return status

    def write_status(self, new_status, num_bytes=2, set_non_volatile=False):
        """Write up to 24 bits (num_bytes) of new status register

        num_bytes can be 1, 2 or 3.

        Not all flash supports the additional commands to write the
        second and third byte of the status register. When writing 2
        bytes, esptool also sends a 16-byte WRSR command (as some
        flash types use this instead of WRSR2.)

        If the set_non_volatile flag is set, non-volatile bits will
        be set as well as volatile ones (WREN used instead of WEVSR).

        """
        SPIFLASH_WRSR = 0x01
        SPIFLASH_WRSR2 = 0x31
        SPIFLASH_WRSR3 = 0x11
        SPIFLASH_WEVSR = 0x50
        SPIFLASH_WREN = 0x06
        SPIFLASH_WRDI = 0x04

        enable_cmd = SPIFLASH_WREN if set_non_volatile else SPIFLASH_WEVSR

        # try using a 16-bit WRSR (not supported by all chips)
        # this may be redundant, but shouldn't hurt
        if num_bytes == 2:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(SPIFLASH_WRSR, struct.pack("<H", new_status))

        # also try using individual commands (also not supported by all chips for num_bytes 2 & 3)
        for cmd in [SPIFLASH_WRSR, SPIFLASH_WRSR2, SPIFLASH_WRSR3][0:num_bytes]:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(cmd, struct.pack("B", new_status & 0xFF))
            new_status >>= 8

        self.run_spiflash_command(SPIFLASH_WRDI)

    def get_crystal_freq(self):
        # Figure out the crystal frequency from the UART clock divider
        # Returns a normalized value in integer MHz (40 or 26 are the only supported values)
        #
        # The logic here is:
        # - We know that our baud rate and the ESP UART baud rate are roughly the same, or we couldn't communicate
        # - We can read the UART clock divider register to know how the ESP derives this from the APB bus frequency
        # - Multiplying these two together gives us the bus frequency which is either the crystal frequency (ESP32)
        #   or double the crystal frequency (ESP8266). See the self.XTAL_CLK_DIVIDER parameter for this factor.
        uart_div = self.read_reg(self.UART_CLKDIV_REG) & self.UART_CLKDIV_MASK
        est_xtal = (self._port.baudrate * uart_div) / 1e6 / self.XTAL_CLK_DIVIDER
        norm_xtal = 40 if est_xtal > 33 else 26
        if abs(norm_xtal - est_xtal) > 1:
            print("WARNING: Detected crystal freq %.2fMHz is quite different to normalized freq %dMHz. Unsupported crystal in use?" % (est_xtal, norm_xtal))
        return norm_xtal

    def hard_reset(self):
        self._setRTS(True)  # EN->LOW
        time.sleep(0.1)
        self._setRTS(False)

    def soft_reset(self, stay_in_bootloader):
        if not self.IS_STUB:
            if stay_in_bootloader:
                return  # ROM bootloader is already in bootloader!
            else:
                # 'run user code' is as close to a soft reset as we can do
                self.flash_begin(0, 0)
                self.flash_finish(False)
        else:
            if stay_in_bootloader:
                # soft resetting from the stub loader
                # will re-load the ROM bootloader
                self.flash_begin(0, 0)
                self.flash_finish(True)
            elif self.CHIP_NAME != "ESP8266":
                raise FatalError("Soft resetting is currently only supported on ESP8266")
            else:
                # running user code from stub loader requires some hacks
                # in the stub loader
                self.command(self.ESP_RUN_USER_CODE, wait_response=False)


class ESP8266ROM(ESPLoader):
    """ Access class for ESP8266 ROM bootloader
    """
    CHIP_NAME = "ESP8266"
    IS_STUB = False

    CHIP_DETECT_MAGIC_VALUE = [0xfff0c101]

    # OTP ROM addresses
    ESP_OTP_MAC0    = 0x3ff00050
    ESP_OTP_MAC1    = 0x3ff00054
    ESP_OTP_MAC3    = 0x3ff0005c

    SPI_REG_BASE    = 0x60000200
    SPI_USR_OFFS    = 0x1c
    SPI_USR1_OFFS   = 0x20
    SPI_USR2_OFFS   = 0x24
    SPI_MOSI_DLEN_OFFS = None
    SPI_MISO_DLEN_OFFS = None
    SPI_W0_OFFS     = 0x40

    UART_CLKDIV_REG = 0x60000014

    XTAL_CLK_DIVIDER = 2

    FLASH_SIZES = {
        '512KB': 0x00,
        '256KB': 0x10,
        '1MB': 0x20,
        '2MB': 0x30,
        '4MB': 0x40,
        '2MB-c1': 0x50,
        '4MB-c1': 0x60,
        '8MB': 0x80,
        '16MB': 0x90,
    }

    BOOTLOADER_FLASH_OFFSET = 0

    MEMORY_MAP = [[0x3FF00000, 0x3FF00010, "DPORT"],
                  [0x3FFE8000, 0x40000000, "DRAM"],
                  [0x40100000, 0x40108000, "IRAM"],
                  [0x40201010, 0x402E1010, "IROM"]]

    def get_efuses(self):
        # Return the 128 bits of ESP8266 efuse as a single Python integer
        result = self.read_reg(0x3ff0005c) << 96
        result |= self.read_reg(0x3ff00058) << 64
        result |= self.read_reg(0x3ff00054) << 32
        result |= self.read_reg(0x3ff00050)
        return result

    def _get_flash_size(self, efuses):
        # rX_Y = EFUSE_DATA_OUTX[Y]
        r0_4 = (efuses & (1 << 4)) != 0
        r3_25 = (efuses & (1 << 121)) != 0
        r3_26 = (efuses & (1 << 122)) != 0
        r3_27 = (efuses & (1 << 123)) != 0

        if r0_4 and not r3_25:
            if not r3_27 and not r3_26:
                return 1
            elif not r3_27 and r3_26:
                return 2
        if not r0_4 and r3_25:
            if not r3_27 and not r3_26:
                return 2
            elif not r3_27 and r3_26:
                return 4
        return -1

    def get_chip_description(self):
        efuses = self.get_efuses()
        is_8285 = (efuses & ((1 << 4) | 1 << 80)) != 0  # One or the other efuse bit is set for ESP8285
        if is_8285:
            flash_size = self._get_flash_size(efuses)
            max_temp = (efuses & (1 << 5)) != 0  # This efuse bit identifies the max flash temperature
            chip_name = {
                1: "ESP8285H08" if max_temp else "ESP8285N08",
                2: "ESP8285H16" if max_temp else "ESP8285N16"
            }.get(flash_size, "ESP8285")
            return chip_name
        return "ESP8266EX"

    def get_chip_features(self):
        features = ["WiFi"]
        if "ESP8285" in self.get_chip_description():
            features += ["Embedded Flash"]
        return features

    def flash_spi_attach(self, hspi_arg):
        if self.IS_STUB:
            super(ESP8266ROM, self).flash_spi_attach(hspi_arg)
        else:
            # ESP8266 ROM has no flash_spi_attach command in serial protocol,
            # but flash_begin will do it
            self.flash_begin(0, 0)

    def flash_set_parameters(self, size):
        # not implemented in ROM, but OK to silently skip for ROM
        if self.IS_STUB:
            super(ESP8266ROM, self).flash_set_parameters(size)

    def chip_id(self):
        """ Read Chip ID from efuse - the equivalent of the SDK system_get_chip_id() function """
        id0 = self.read_reg(self.ESP_OTP_MAC0)
        id1 = self.read_reg(self.ESP_OTP_MAC1)
        return (id0 >> 24) | ((id1 & MAX_UINT24) << 8)

    def read_mac(self):
        """ Read MAC from OTP ROM """
        mac0 = self.read_reg(self.ESP_OTP_MAC0)
        mac1 = self.read_reg(self.ESP_OTP_MAC1)
        mac3 = self.read_reg(self.ESP_OTP_MAC3)
        if (mac3 != 0):
            oui = ((mac3 >> 16) & 0xff, (mac3 >> 8) & 0xff, mac3 & 0xff)
        elif ((mac1 >> 16) & 0xff) == 0:
            oui = (0x18, 0xfe, 0x34)
        elif ((mac1 >> 16) & 0xff) == 1:
            oui = (0xac, 0xd0, 0x74)
        else:
            raise FatalError("Unknown OUI")
        return oui + ((mac1 >> 8) & 0xff, mac1 & 0xff, (mac0 >> 24) & 0xff)

    def get_erase_size(self, offset, size):
        """ Calculate an erase size given a specific size in bytes.

        Provides a workaround for the bootloader erase bug."""

        sectors_per_block = 16
        sector_size = self.FLASH_SECTOR_SIZE
        num_sectors = (size + sector_size - 1) // sector_size
        start_sector = offset // sector_size

        head_sectors = sectors_per_block - (start_sector % sectors_per_block)
        if num_sectors < head_sectors:
            head_sectors = num_sectors

        if num_sectors < 2 * head_sectors:
            return (num_sectors + 1) // 2 * sector_size
        else:
            return (num_sectors - head_sectors) * sector_size

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError("Overriding VDDSDIO setting only applies to ESP32")


class ESP8266StubLoader(ESP8266ROM):
    """ Access class for ESP8266 stub loader, runs on top of ROM.
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader

    def get_erase_size(self, offset, size):
        return size  # stub doesn't have same size bug as ROM loader


ESP8266ROM.STUB_CLASS = ESP8266StubLoader


class ESP32ROM(ESPLoader):
    """Access class for ESP32 ROM bootloader

    """
    CHIP_NAME = "ESP32"
    IMAGE_CHIP_ID = 0
    IS_STUB = False

    CHIP_DETECT_MAGIC_VALUE = [0x00f01d83]

    IROM_MAP_START = 0x400d0000
    IROM_MAP_END   = 0x40400000

    DROM_MAP_START = 0x3F400000
    DROM_MAP_END   = 0x3F800000

    # ESP32 uses a 4 byte status reply
    STATUS_BYTES_LENGTH = 4

    SPI_REG_BASE   = 0x3ff42000
    SPI_USR_OFFS    = 0x1c
    SPI_USR1_OFFS   = 0x20
    SPI_USR2_OFFS   = 0x24
    SPI_MOSI_DLEN_OFFS = 0x28
    SPI_MISO_DLEN_OFFS = 0x2c
    EFUSE_RD_REG_BASE = 0x3ff5a000

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE + 0x18
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = (1 << 7)  # EFUSE_RD_DISABLE_DL_ENCRYPT

    DR_REG_SYSCON_BASE = 0x3ff66000

    SPI_W0_OFFS = 0x80

    UART_CLKDIV_REG = 0x3ff40014

    XTAL_CLK_DIVIDER = 1

    FLASH_SIZES = {
        '1MB': 0x00,
        '2MB': 0x10,
        '4MB': 0x20,
        '8MB': 0x30,
        '16MB': 0x40
    }

    BOOTLOADER_FLASH_OFFSET = 0x1000

    OVERRIDE_VDDSDIO_CHOICES = ["1.8V", "1.9V", "OFF"]

    MEMORY_MAP = [[0x00000000, 0x00010000, "PADDING"],
                  [0x3F400000, 0x3F800000, "DROM"],
                  [0x3F800000, 0x3FC00000, "EXTRAM_DATA"],
                  [0x3FF80000, 0x3FF82000, "RTC_DRAM"],
                  [0x3FF90000, 0x40000000, "BYTE_ACCESSIBLE"],
                  [0x3FFAE000, 0x40000000, "DRAM"],
                  [0x3FFE0000, 0x3FFFFFFC, "DIRAM_DRAM"],
                  [0x40000000, 0x40070000, "IROM"],
                  [0x40070000, 0x40078000, "CACHE_PRO"],
                  [0x40078000, 0x40080000, "CACHE_APP"],
                  [0x40080000, 0x400A0000, "IRAM"],
                  [0x400A0000, 0x400BFFFC, "DIRAM_IRAM"],
                  [0x400C0000, 0x400C2000, "RTC_IRAM"],
                  [0x400D0000, 0x40400000, "IROM"],
                  [0x50000000, 0x50002000, "RTC_DATA"]]

    FLASH_ENCRYPTED_WRITE_ALIGN = 32

    """ Try to read the BLOCK1 (encryption key) and check if it is valid """

    def is_flash_encryption_key_valid(self):

        """ Bit 0 of efuse_rd_disable[3:0] is mapped to BLOCK1
        this bit is at position 16 in EFUSE_BLK0_RDATA0_REG """
        word0 = self.read_efuse(0)
        rd_disable = (word0 >> 16) & 0x1

        # reading of BLOCK1 is NOT ALLOWED so we assume valid key is programmed
        if rd_disable:
            return True
        else:
            # reading of BLOCK1 is ALLOWED so we will read and verify for non-zero.
            # When ESP32 has not generated AES/encryption key in BLOCK1, the contents will be readable and 0.
            # If the flash encryption is enabled it is expected to have a valid non-zero key. We break out on
            # first occurance of non-zero value
            key_word = [0] * 7
            for i in range(len(key_word)):
                key_word[i] = self.read_efuse(14 + i)
                # key is non-zero so break & return
                if key_word[i] != 0:
                    return True
            return False

    def get_flash_crypt_config(self):
        """ For flash encryption related commands we need to make sure
        user has programmed all the relevant efuse correctly so before
        writing encrypted write_flash_encrypt esptool will verify the values
        of flash_crypt_config to be non zero if they are not read
        protected. If the values are zero a warning will be printed

        bit 3 in efuse_rd_disable[3:0] is mapped to flash_crypt_config
        this bit is at position 19 in EFUSE_BLK0_RDATA0_REG """
        word0 = self.read_efuse(0)
        rd_disable = (word0 >> 19) & 0x1

        if rd_disable == 0:
            """ we can read the flash_crypt_config efuse value
            so go & read it (EFUSE_BLK0_RDATA5_REG[31:28]) """
            word5 = self.read_efuse(5)
            word5 = (word5 >> 28) & 0xF
            return word5
        else:
            # if read of the efuse is disabled we assume it is set correctly
            return 0xF

    def get_encrypted_download_disabled(self):
        if self.read_reg(self.EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG) & self.EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT:
            return True
        else:
            return False

    def get_pkg_version(self):
        word3 = self.read_efuse(3)
        pkg_version = (word3 >> 9) & 0x07
        pkg_version += ((word3 >> 2) & 0x1) << 3
        return pkg_version

    def get_chip_revision(self):
        word3 = self.read_efuse(3)
        word5 = self.read_efuse(5)
        apb_ctl_date = self.read_reg(self.DR_REG_SYSCON_BASE + 0x7C)

        rev_bit0 = (word3 >> 15) & 0x1
        rev_bit1 = (word5 >> 20) & 0x1
        rev_bit2 = (apb_ctl_date >> 31) & 0x1
        if rev_bit0:
            if rev_bit1:
                if rev_bit2:
                    return 3
                else:
                    return 2
            else:
                return 1
        return 0

    def get_chip_description(self):
        pkg_version = self.get_pkg_version()
        chip_revision = self.get_chip_revision()
        rev3 = (chip_revision == 3)
        single_core = self.read_efuse(3) & (1 << 0)  # CHIP_VER DIS_APP_CPU

        chip_name = {
            0: "ESP32-S0WDQ6" if single_core else "ESP32-D0WDQ6",
            1: "ESP32-S0WD" if single_core else "ESP32-D0WD",
            2: "ESP32-D2WD",
            4: "ESP32-U4WDH",
            5: "ESP32-PICO-V3" if rev3 else "ESP32-PICO-D4",
            6: "ESP32-PICO-V3-02",
        }.get(pkg_version, "unknown ESP32")

        # ESP32-D0WD-V3, ESP32-D0WDQ6-V3
        if chip_name.startswith("ESP32-D0WD") and rev3:
            chip_name += "-V3"

        return "%s (revision %d)" % (chip_name, chip_revision)

    def get_chip_features(self):
        features = ["WiFi"]
        word3 = self.read_efuse(3)

        # names of variables in this section are lowercase
        #  versions of EFUSE names as documented in TRM and
        # ESP-IDF efuse_reg.h

        chip_ver_dis_bt = word3 & (1 << 1)
        if chip_ver_dis_bt == 0:
            features += ["BT"]

        chip_ver_dis_app_cpu = word3 & (1 << 0)
        if chip_ver_dis_app_cpu:
            features += ["Single Core"]
        else:
            features += ["Dual Core"]

        chip_cpu_freq_rated = word3 & (1 << 13)
        if chip_cpu_freq_rated:
            chip_cpu_freq_low = word3 & (1 << 12)
            if chip_cpu_freq_low:
                features += ["160MHz"]
            else:
                features += ["240MHz"]

        pkg_version = self.get_pkg_version()
        if pkg_version in [2, 4, 5, 6]:
            features += ["Embedded Flash"]

        if pkg_version == 6:
            features += ["Embedded PSRAM"]

        word4 = self.read_efuse(4)
        adc_vref = (word4 >> 8) & 0x1F
        if adc_vref:
            features += ["VRef calibration in efuse"]

        blk3_part_res = word3 >> 14 & 0x1
        if blk3_part_res:
            features += ["BLK3 partially reserved"]

        word6 = self.read_efuse(6)
        coding_scheme = word6 & 0x3
        features += ["Coding Scheme %s" % {
            0: "None",
            1: "3/4",
            2: "Repeat (UNSUPPORTED)",
            3: "Invalid"}[coding_scheme]]

        return features

    def read_efuse(self, n):
        """ Read the nth word of the ESP3x EFUSE region. """
        return self.read_reg(self.EFUSE_RD_REG_BASE + (4 * n))

    def chip_id(self):
        raise NotSupportedError(self, "chip_id")

    def read_mac(self):
        """ Read MAC from EFUSE region """
        words = [self.read_efuse(2), self.read_efuse(1)]
        bitstring = struct.pack(">II", *words)
        bitstring = bitstring[2:8]  # trim the 2 byte CRC
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:  # Python 3, bitstring elements are already bytes
            return tuple(bitstring)

    def get_erase_size(self, offset, size):
        return size

    def override_vddsdio(self, new_voltage):
        new_voltage = new_voltage.upper()
        if new_voltage not in self.OVERRIDE_VDDSDIO_CHOICES:
            raise FatalError("The only accepted VDDSDIO overrides are '1.8V', '1.9V' and 'OFF'")
        RTC_CNTL_SDIO_CONF_REG = 0x3ff48074
        RTC_CNTL_XPD_SDIO_REG = (1 << 31)
        RTC_CNTL_DREFH_SDIO_M = (3 << 29)
        RTC_CNTL_DREFM_SDIO_M = (3 << 27)
        RTC_CNTL_DREFL_SDIO_M = (3 << 25)
        # RTC_CNTL_SDIO_TIEH = (1 << 23)  # not used here, setting TIEH=1 would set 3.3V output, not safe for esptool.py to do
        RTC_CNTL_SDIO_FORCE = (1 << 22)
        RTC_CNTL_SDIO_PD_EN = (1 << 21)

        reg_val = RTC_CNTL_SDIO_FORCE  # override efuse setting
        reg_val |= RTC_CNTL_SDIO_PD_EN
        if new_voltage != "OFF":
            reg_val |= RTC_CNTL_XPD_SDIO_REG  # enable internal LDO
        if new_voltage == "1.9V":
            reg_val |= (RTC_CNTL_DREFH_SDIO_M | RTC_CNTL_DREFM_SDIO_M | RTC_CNTL_DREFL_SDIO_M)  # boost voltage
        self.write_reg(RTC_CNTL_SDIO_CONF_REG, reg_val)
        print("VDDSDIO regulator set to %s" % new_voltage)

    def read_flash_slow(self, offset, length, progress_fn):
        BLOCK_LEN = 64  # ROM read limit per command (this limit is why it's so slow)

        data = b''
        while len(data) < length:
            block_len = min(BLOCK_LEN, length - len(data))
            r = self.check_command("read flash block", self.ESP_READ_FLASH_SLOW,
                                   struct.pack('<II', offset + len(data), block_len))
            if len(r) < block_len:
                raise FatalError("Expected %d byte block, got %d bytes. Serial errors?" % (block_len, len(r)))
            data += r[:block_len]  # command always returns 64 byte buffer, regardless of how many bytes were actually read from flash
            if progress_fn and (len(data) % 1024 == 0 or len(data) == length):
                progress_fn(len(data), length)
        return data


class ESP32S2ROM(ESP32ROM):
    CHIP_NAME = "ESP32-S2"
    IMAGE_CHIP_ID = 2

    IROM_MAP_START = 0x40080000
    IROM_MAP_END   = 0x40b80000
    DROM_MAP_START = 0x3F000000
    DROM_MAP_END   = 0x3F3F0000

    CHIP_DETECT_MAGIC_VALUE = [0x000007c6]

    SPI_REG_BASE = 0x3f402000
    SPI_USR_OFFS    = 0x18
    SPI_USR1_OFFS   = 0x1c
    SPI_USR2_OFFS   = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    MAC_EFUSE_REG = 0x3f41A044  # ESP32-S2 has special block for MAC efuses

    UART_CLKDIV_REG = 0x3f400014

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    # todo: use espefuse APIs to get this info
    EFUSE_BASE = 0x3f41A000
    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 19

    PURPOSE_VAL_XTS_AES256_KEY_1 = 2
    PURPOSE_VAL_XTS_AES256_KEY_2 = 3
    PURPOSE_VAL_XTS_AES128_KEY = 4

    UARTDEV_BUF_NO = 0x3ffffd14  # Variable in ROM .bss which indicates the port in use
    UARTDEV_BUF_NO_USB = 2  # Value of the above variable indicating that USB is in use

    USB_RAM_BLOCK = 0x800  # Max block size USB CDC is used

    GPIO_STRAP_REG = 0x3f404038
    GPIO_STRAP_SPI_BOOT_MASK = 0x8   # Not download mode
    RTC_CNTL_OPTION1_REG = 0x3f408128
    RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK = 0x1  # Is download mode forced over USB?

    MEMORY_MAP = [[0x00000000, 0x00010000, "PADDING"],
                  [0x3F000000, 0x3FF80000, "DROM"],
                  [0x3F500000, 0x3FF80000, "EXTRAM_DATA"],
                  [0x3FF9E000, 0x3FFA0000, "RTC_DRAM"],
                  [0x3FF9E000, 0x40000000, "BYTE_ACCESSIBLE"],
                  [0x3FF9E000, 0x40072000, "MEM_INTERNAL"],
                  [0x3FFB0000, 0x40000000, "DRAM"],
                  [0x40000000, 0x4001A100, "IROM_MASK"],
                  [0x40020000, 0x40070000, "IRAM"],
                  [0x40070000, 0x40072000, "RTC_IRAM"],
                  [0x40080000, 0x40800000, "IROM"],
                  [0x50000000, 0x50002000, "RTC_DATA"]]

    def get_pkg_version(self):
        num_word = 3
        block1_addr = self.EFUSE_BASE + 0x044
        word3 = self.read_reg(block1_addr + (4 * num_word))
        pkg_version = (word3 >> 21) & 0x0F
        return pkg_version

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-S2",
            1: "ESP32-S2FH16",
            2: "ESP32-S2FH32",
        }.get(self.get_pkg_version(), "unknown ESP32-S2")

        return "%s" % (chip_name)

    def get_chip_features(self):
        features = ["WiFi"]

        if self.secure_download_mode:
            features += ["Secure Download Mode Enabled"]

        pkg_version = self.get_pkg_version()

        if pkg_version in [1, 2]:
            if pkg_version == 1:
                features += ["Embedded 2MB Flash"]
            elif pkg_version == 2:
                features += ["Embedded 4MB Flash"]
            features += ["105C temp rating"]

        num_word = 4
        block2_addr = self.EFUSE_BASE + 0x05C
        word4 = self.read_reg(block2_addr + (4 * num_word))
        block2_version = (word4 >> 4) & 0x07

        if block2_version == 1:
            features += ["ADC and temperature sensor calibration in BLK2 of efuse"]
        return features

    def get_crystal_freq(self):
        # ESP32-S2 XTAL is fixed to 40MHz
        return 40

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError("VDD_SDIO overrides are not supported for ESP32-S2")

    def read_mac(self):
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:  # Python 3, bitstring elements are already bytes
            return tuple(bitstring)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-S2

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > 5:
            raise FatalError("Valid key block numbers must be in range 0-5")

        reg, shift = [(self.EFUSE_PURPOSE_KEY0_REG, self.EFUSE_PURPOSE_KEY0_SHIFT),
                      (self.EFUSE_PURPOSE_KEY1_REG, self.EFUSE_PURPOSE_KEY1_SHIFT),
                      (self.EFUSE_PURPOSE_KEY2_REG, self.EFUSE_PURPOSE_KEY2_SHIFT),
                      (self.EFUSE_PURPOSE_KEY3_REG, self.EFUSE_PURPOSE_KEY3_SHIFT),
                      (self.EFUSE_PURPOSE_KEY4_REG, self.EFUSE_PURPOSE_KEY4_SHIFT),
                      (self.EFUSE_PURPOSE_KEY5_REG, self.EFUSE_PURPOSE_KEY5_SHIFT)][key_block]
        return (self.read_reg(reg) >> shift) & 0xF

    def is_flash_encryption_key_valid(self):
        # Need to see either an AES-128 key or two AES-256 keys
        purposes = [self.get_key_block_purpose(b) for b in range(6)]

        if any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes):
            return True

        return any(p == self.PURPOSE_VAL_XTS_AES256_KEY_1 for p in purposes) \
            and any(p == self.PURPOSE_VAL_XTS_AES256_KEY_2 for p in purposes)

    def uses_usb(self, _cache=[]):
        if self.secure_download_mode:
            return False  # can't detect native USB in secure download mode
        if not _cache:
            buf_no = self.read_reg(self.UARTDEV_BUF_NO) & 0xff
            _cache.append(buf_no == self.UARTDEV_BUF_NO_USB)
        return _cache[0]

    def _post_connect(self):
        if self.uses_usb():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK

    def _check_if_can_reset(self):
        """
        Check the strapping register to see if we can reset out of download mode.
        """
        if os.getenv("ESPTOOL_TESTING") is not None:
            print("ESPTOOL_TESTING is set, ignoring strapping mode check")
            # Esptool tests over USB CDC run with GPIO0 strapped low, don't complain in this case.
            return
        strap_reg = self.read_reg(self.GPIO_STRAP_REG)
        force_dl_reg = self.read_reg(self.RTC_CNTL_OPTION1_REG)
        if strap_reg & self.GPIO_STRAP_SPI_BOOT_MASK == 0 and force_dl_reg & self.RTC_CNTL_FORCE_DOWNLOAD_BOOT_MASK == 0:
            print("ERROR: {} chip was placed into download mode using GPIO0.\n"
                  "esptool.py can not exit the download mode over USB. "
                  "To run the app, reset the chip manually.\n"
                  "To suppress this error, set --after option to 'no_reset'.".format(self.get_chip_description()))
            raise SystemExit(1)

    def hard_reset(self):
        if self.uses_usb():
            self._check_if_can_reset()

        self._setRTS(True)  # EN->LOW
        if self.uses_usb():
            # Give the chip some time to come out of reset, to be able to handle further DTR/RTS transitions
            time.sleep(0.2)
            self._setRTS(False)
            time.sleep(0.2)
        else:
            self._setRTS(False)


class ESP32S3BETA2ROM(ESP32ROM):
    CHIP_NAME = "ESP32-S3(beta2)"
    IMAGE_CHIP_ID = 4

    IROM_MAP_START = 0x42000000
    IROM_MAP_END   = 0x44000000
    DROM_MAP_START = 0x3c000000
    DROM_MAP_END   = 0x3e000000

    UART_DATE_REG_ADDR = 0x60000080

    CHIP_DETECT_MAGIC_VALUE = [0xeb004136]

    SPI_REG_BASE = 0x60002000
    SPI_USR_OFFS    = 0x18
    SPI_USR1_OFFS   = 0x1c
    SPI_USR2_OFFS   = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    EFUSE_REG_BASE = 0x6001A030  # BLOCK0 read base address

    MAC_EFUSE_REG = 0x6001A000  # ESP32S3 has special block for MAC efuses

    UART_CLKDIV_REG = 0x60000014

    GPIO_STRAP_REG = 0x60004038

    MEMORY_MAP = [[0x00000000, 0x00010000, "PADDING"],
                  [0x3C000000, 0x3D000000, "DROM"],
                  [0x3D000000, 0x3E000000, "EXTRAM_DATA"],
                  [0x600FE000, 0x60100000, "RTC_DRAM"],
                  [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
                  [0x3FC88000, 0x403E2000, "MEM_INTERNAL"],
                  [0x3FC88000, 0x3FD00000, "DRAM"],
                  [0x40000000, 0x4001A100, "IROM_MASK"],
                  [0x40370000, 0x403E0000, "IRAM"],
                  [0x600FE000, 0x60100000, "RTC_IRAM"],
                  [0x42000000, 0x42800000, "IROM"],
                  [0x50000000, 0x50002000, "RTC_DATA"]]

    def get_chip_description(self):
        return "ESP32-S3(beta2)"

    def get_chip_features(self):
        return ["WiFi", "BLE"]

    def get_crystal_freq(self):
        # ESP32S3 XTAL is fixed to 40MHz
        return 40

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError("VDD_SDIO overrides are not supported for ESP32-S3")

    def read_mac(self):
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:  # Python 3, bitstring elements are already bytes
            return tuple(bitstring)


class ESP32S3BETA3ROM(ESP32ROM):
    CHIP_NAME = "ESP32-S3(beta3)"
    IMAGE_CHIP_ID = 6

    IROM_MAP_START = 0x42000000
    IROM_MAP_END   = 0x44000000
    DROM_MAP_START = 0x3c000000
    DROM_MAP_END   = 0x3e000000

    UART_DATE_REG_ADDR = 0x60000080

    CHIP_DETECT_MAGIC_VALUE = [0x9]

    SPI_REG_BASE = 0x60002000
    SPI_USR_OFFS    = 0x18
    SPI_USR1_OFFS   = 0x1c
    SPI_USR2_OFFS   = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    EFUSE_BASE = 0x6001A000  # BLOCK0 read base address

    MAC_EFUSE_REG  = EFUSE_BASE + 0x044  # ESP32S3 has special block for MAC efuses

    UART_CLKDIV_REG = 0x60000014

    GPIO_STRAP_REG = 0x60004038

    MEMORY_MAP = [[0x00000000, 0x00010000, "PADDING"],
                  [0x3C000000, 0x3D000000, "DROM"],
                  [0x3D000000, 0x3E000000, "EXTRAM_DATA"],
                  [0x600FE000, 0x60100000, "RTC_DRAM"],
                  [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
                  [0x3FC88000, 0x403E2000, "MEM_INTERNAL"],
                  [0x3FC88000, 0x3FD00000, "DRAM"],
                  [0x40000000, 0x4001A100, "IROM_MASK"],
                  [0x40370000, 0x403E0000, "IRAM"],
                  [0x600FE000, 0x60100000, "RTC_IRAM"],
                  [0x42000000, 0x42800000, "IROM"],
                  [0x50000000, 0x50002000, "RTC_DATA"]]

    def get_chip_description(self):
        return "ESP32-S3(beta3)"

    def get_chip_features(self):
        return ["WiFi", "BLE"]

    def get_crystal_freq(self):
        # ESP32S3 XTAL is fixed to 40MHz
        return 40

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError("VDD_SDIO overrides are not supported for ESP32-S3")

    def read_mac(self):
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:  # Python 3, bitstring elements are already bytes
            return tuple(bitstring)


class ESP32C3ROM(ESP32ROM):
    CHIP_NAME = "ESP32-C3"
    IMAGE_CHIP_ID = 5

    IROM_MAP_START = 0x42000000
    IROM_MAP_END   = 0x42800000
    DROM_MAP_START = 0x3c000000
    DROM_MAP_END   = 0x3c800000

    SPI_REG_BASE = 0x60002000
    SPI_USR_OFFS    = 0x18
    SPI_USR1_OFFS   = 0x1C
    SPI_USR2_OFFS   = 0x20
    SPI_MOSI_DLEN_OFFS = 0x24
    SPI_MISO_DLEN_OFFS = 0x28
    SPI_W0_OFFS = 0x58

    BOOTLOADER_FLASH_OFFSET = 0x0

    # Magic value for ESP32C3 eco 1+2 and ESP32C3 eco3 respectivly
    CHIP_DETECT_MAGIC_VALUE = [0x6921506f, 0x1b31506f]

    UART_DATE_REG_ADDR = 0x60000000 + 0x7c

    EFUSE_BASE = 0x60008800
    MAC_EFUSE_REG  = EFUSE_BASE + 0x044

    EFUSE_RD_REG_BASE = EFUSE_BASE + 0x030  # BLOCK0 read base address

    EFUSE_PURPOSE_KEY0_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY0_SHIFT = 24
    EFUSE_PURPOSE_KEY1_REG = EFUSE_BASE + 0x34
    EFUSE_PURPOSE_KEY1_SHIFT = 28
    EFUSE_PURPOSE_KEY2_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY2_SHIFT = 0
    EFUSE_PURPOSE_KEY3_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY3_SHIFT = 4
    EFUSE_PURPOSE_KEY4_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY4_SHIFT = 8
    EFUSE_PURPOSE_KEY5_REG = EFUSE_BASE + 0x38
    EFUSE_PURPOSE_KEY5_SHIFT = 12

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 20

    PURPOSE_VAL_XTS_AES128_KEY = 4

    GPIO_STRAP_REG = 0x3f404038

    FLASH_ENCRYPTED_WRITE_ALIGN = 16

    MEMORY_MAP = [[0x00000000, 0x00010000, "PADDING"],
                  [0x3C000000, 0x3C800000, "DROM"],
                  [0x3FC80000, 0x3FCE0000, "DRAM"],
                  [0x3FC88000, 0x3FD00000, "BYTE_ACCESSIBLE"],
                  [0x3FF00000, 0x3FF20000, "DROM_MASK"],
                  [0x40000000, 0x40060000, "IROM_MASK"],
                  [0x42000000, 0x42800000, "IROM"],
                  [0x4037C000, 0x403E0000, "IRAM"],
                  [0x50000000, 0x50002000, "RTC_IRAM"],
                  [0x50000000, 0x50002000, "RTC_DRAM"],
                  [0x600FE000, 0x60100000, "MEM_INTERNAL2"]]

    def get_pkg_version(self):
        num_word = 3
        block1_addr = self.EFUSE_BASE + 0x044
        word3 = self.read_reg(block1_addr + (4 * num_word))
        pkg_version = (word3 >> 21) & 0x0F
        return pkg_version

    def get_chip_revision(self):
        # reads WAFER_VERSION field from EFUSE_RD_MAC_SPI_SYS_3_REG
        block1_addr = self.EFUSE_BASE + 0x044
        num_word = 3
        pos = 18
        return (self.read_reg(block1_addr + (4 * num_word)) & (0x7 << pos)) >> pos

    def get_chip_description(self):
        chip_name = {
            0: "ESP32-C3",
        }.get(self.get_pkg_version(), "unknown ESP32-C3")
        chip_revision = self.get_chip_revision()

        return "%s (revision %d)" % (chip_name, chip_revision)

    def get_chip_features(self):
        return ["Wi-Fi"]

    def get_crystal_freq(self):
        # ESP32C3 XTAL is fixed to 40MHz
        return 40

    def override_vddsdio(self, new_voltage):
        raise NotImplementedInROMError("VDD_SDIO overrides are not supported for ESP32-C3")

    def read_mac(self):
        mac0 = self.read_reg(self.MAC_EFUSE_REG)
        mac1 = self.read_reg(self.MAC_EFUSE_REG + 4)  # only bottom 16 bits are MAC
        bitstring = struct.pack(">II", mac1, mac0)[2:]
        try:
            return tuple(ord(b) for b in bitstring)
        except TypeError:  # Python 3, bitstring elements are already bytes
            return tuple(bitstring)

    def get_flash_crypt_config(self):
        return None  # doesn't exist on ESP32-C3

    def get_key_block_purpose(self, key_block):
        if key_block < 0 or key_block > 5:
            raise FatalError("Valid key block numbers must be in range 0-5")

        reg, shift = [(self.EFUSE_PURPOSE_KEY0_REG, self.EFUSE_PURPOSE_KEY0_SHIFT),
                      (self.EFUSE_PURPOSE_KEY1_REG, self.EFUSE_PURPOSE_KEY1_SHIFT),
                      (self.EFUSE_PURPOSE_KEY2_REG, self.EFUSE_PURPOSE_KEY2_SHIFT),
                      (self.EFUSE_PURPOSE_KEY3_REG, self.EFUSE_PURPOSE_KEY3_SHIFT),
                      (self.EFUSE_PURPOSE_KEY4_REG, self.EFUSE_PURPOSE_KEY4_SHIFT),
                      (self.EFUSE_PURPOSE_KEY5_REG, self.EFUSE_PURPOSE_KEY5_SHIFT)][key_block]
        return (self.read_reg(reg) >> shift) & 0xF

    def is_flash_encryption_key_valid(self):
        # Need to see an AES-128 key
        purposes = [self.get_key_block_purpose(b) for b in range(6)]

        return any(p == self.PURPOSE_VAL_XTS_AES128_KEY for p in purposes)


class ESP32StubLoader(ESP32ROM):
    """ Access class for ESP32 stub loader, runs on top of ROM.
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32ROM.STUB_CLASS = ESP32StubLoader


class ESP32S2StubLoader(ESP32S2ROM):
    """ Access class for ESP32-S2 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader

        if rom_loader.uses_usb():
            self.ESP_RAM_BLOCK = self.USB_RAM_BLOCK
            self.FLASH_WRITE_SIZE = self.USB_RAM_BLOCK


ESP32S2ROM.STUB_CLASS = ESP32S2StubLoader


class ESP32S3BETA2StubLoader(ESP32S3BETA2ROM):
    """ Access class for ESP32S3 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32S3BETA2ROM.STUB_CLASS = ESP32S3BETA2StubLoader


class ESP32S3BETA3StubLoader(ESP32S3BETA3ROM):
    """ Access class for ESP32S3 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32S3BETA3ROM.STUB_CLASS = ESP32S3BETA3StubLoader


class ESP32C3StubLoader(ESP32C3ROM):
    """ Access class for ESP32C3 stub loader, runs on top of ROM.

    (Basically the same as ESP32StubLoader, but different base class.
    Can possibly be made into a mixin.)
    """
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.flush_input()  # resets _slip_reader


ESP32C3ROM.STUB_CLASS = ESP32C3StubLoader


class ESPBOOTLOADER(object):
    """ These are constants related to software ESP8266 bootloader, working with 'v2' image files """

    # First byte of the "v2" application image
    IMAGE_V2_MAGIC = 0xea

    # First 'segment' value in a "v2" application image, appears to be a constant version value?
    IMAGE_V2_SEGMENT = 4


def LoadFirmwareImage(chip, filename):
    """ Load a firmware image. Can be for any supported SoC.

        ESP8266 images will be examined to determine if they are original ROM firmware images (ESP8266ROMFirmwareImage)
        or "v2" OTA bootloader images.

        Returns a BaseFirmwareImage subclass, either ESP8266ROMFirmwareImage (v1) or ESP8266V2FirmwareImage (v2).
    """
    chip = chip.lower().replace("-", "")
    with open(filename, 'rb') as f:
        if chip == 'esp32':
            return ESP32FirmwareImage(f)
        elif chip == "esp32s2":
            return ESP32S2FirmwareImage(f)
        elif chip == "esp32s3beta2":
            return ESP32S3BETA2FirmwareImage(f)
        elif chip == "esp32s3beta3":
            return ESP32S3BETA3FirmwareImage(f)
        elif chip == 'esp32c3':
            return ESP32C3FirmwareImage(f)
        else:  # Otherwise, ESP8266 so look at magic to determine the image type
            magic = ord(f.read(1))
            f.seek(0)
            if magic == ESPLoader.ESP_IMAGE_MAGIC:
                return ESP8266ROMFirmwareImage(f)
            elif magic == ESPBOOTLOADER.IMAGE_V2_MAGIC:
                return ESP8266V2FirmwareImage(f)
            else:
                raise FatalError("Invalid image magic number: %d" % magic)


class ImageSegment(object):
    """ Wrapper class for a segment in an ESP image
    (very similar to a section in an ELFImage also) """
    def __init__(self, addr, data, file_offs=None):
        self.addr = addr
        self.data = data
        self.file_offs = file_offs
        self.include_in_checksum = True
        if self.addr != 0:
            self.pad_to_alignment(4)  # pad all "real" ImageSegments 4 byte aligned length

    def copy_with_new_addr(self, new_addr):
        """ Return a new ImageSegment with same data, but mapped at
        a new address. """
        return ImageSegment(new_addr, self.data, 0)

    def split_image(self, split_len):
        """ Return a new ImageSegment which splits "split_len" bytes
        from the beginning of the data. Remaining bytes are kept in
        this segment object (and the start address is adjusted to match.) """
        result = copy.copy(self)
        result.data = self.data[:split_len]
        self.data = self.data[split_len:]
        self.addr += split_len
        self.file_offs = None
        result.file_offs = None
        return result

    def __repr__(self):
        r = "len 0x%05x load 0x%08x" % (len(self.data), self.addr)
        if self.file_offs is not None:
            r += " file_offs 0x%08x" % (self.file_offs)
        return r

    def get_memory_type(self, image):
        """
        Return a list describing the memory type(s) that is covered by this
        segment's start address.
        """
        return [map_range[2] for map_range in image.ROM_LOADER.MEMORY_MAP if map_range[0] <= self.addr < map_range[1]]

    def pad_to_alignment(self, alignment):
        self.data = pad_to(self.data, alignment, b'\x00')


class ELFSection(ImageSegment):
    """ Wrapper class for a section in an ELF image, has a section
    name as well as the common properties of an ImageSegment. """
    def __init__(self, name, addr, data):
        super(ELFSection, self).__init__(addr, data)
        self.name = name.decode("utf-8")

    def __repr__(self):
        return "%s %s" % (self.name, super(ELFSection, self).__repr__())


class BaseFirmwareImage(object):
    SEG_HEADER_LEN = 8
    SHA256_DIGEST_LEN = 32

    """ Base class with common firmware image functions """
    def __init__(self):
        self.segments = []
        self.entrypoint = 0
        self.elf_sha256 = None
        self.elf_sha256_offset = 0

    def load_common_header(self, load_file, expected_magic):
        (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', load_file.read(8))

        if magic != expected_magic:
            raise FatalError('Invalid firmware image magic=0x%x' % (magic))
        return segments

    def verify(self):
        if len(self.segments) > 16:
            raise FatalError('Invalid segment count %d (max 16). Usually this indicates a linker script problem.' % len(self.segments))

    def load_segment(self, f, is_irom_segment=False):
        """ Load the next segment from the image file """
        file_offs = f.tell()
        (offset, size) = struct.unpack('<II', f.read(8))
        self.warn_if_unusual_segment(offset, size, is_irom_segment)
        segment_data = f.read(size)
        if len(segment_data) < size:
            raise FatalError('End of file reading segment 0x%x, length %d (actual length %d)' % (offset, size, len(segment_data)))
        segment = ImageSegment(offset, segment_data, file_offs)
        self.segments.append(segment)
        return segment

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        if not is_irom_segment:
            if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                print('WARNING: Suspicious segment 0x%x, length %d' % (offset, size))

    def maybe_patch_segment_data(self, f, segment_data):
        """If SHA256 digest of the ELF file needs to be inserted into this segment, do so. Returns segment data."""
        segment_len = len(segment_data)
        file_pos = f.tell()  # file_pos is position in the .bin file
        if self.elf_sha256_offset >= file_pos and self.elf_sha256_offset < file_pos + segment_len:
            # SHA256 digest needs to be patched into this binary segment,
            # calculate offset of the digest inside the binary segment.
            patch_offset = self.elf_sha256_offset - file_pos
            # Sanity checks
            if patch_offset < self.SEG_HEADER_LEN or patch_offset + self.SHA256_DIGEST_LEN > segment_len:
                raise FatalError('Cannot place SHA256 digest on segment boundary'
                                 '(elf_sha256_offset=%d, file_pos=%d, segment_size=%d)' %
                                 (self.elf_sha256_offset, file_pos, segment_len))
            # offset relative to the data part
            patch_offset -= self.SEG_HEADER_LEN
            if segment_data[patch_offset:patch_offset + self.SHA256_DIGEST_LEN] != b'\x00' * self.SHA256_DIGEST_LEN:
                raise FatalError('Contents of segment at SHA256 digest offset 0x%x are not all zero. Refusing to overwrite.' %
                                 self.elf_sha256_offset)
            assert(len(self.elf_sha256) == self.SHA256_DIGEST_LEN)
            segment_data = segment_data[0:patch_offset] + self.elf_sha256 + \
                segment_data[patch_offset + self.SHA256_DIGEST_LEN:]
        return segment_data

    def save_segment(self, f, segment, checksum=None):
        """ Save the next segment to the image file, return next checksum value if provided """
        segment_data = self.maybe_patch_segment_data(f, segment.data)
        f.write(struct.pack('<II', segment.addr, len(segment_data)))
        f.write(segment_data)
        if checksum is not None:
            return ESPLoader.checksum(segment_data, checksum)

    def read_checksum(self, f):
        """ Return ESPLoader checksum from end of just-read image """
        # Skip the padding. The checksum is stored in the last byte so that the
        # file is a multiple of 16 bytes.
        align_file_position(f, 16)
        return ord(f.read(1))

    def calculate_checksum(self):
        """ Calculate checksum of loaded image, based on segments in
        segment array.
        """
        checksum = ESPLoader.ESP_CHECKSUM_MAGIC
        for seg in self.segments:
            if seg.include_in_checksum:
                checksum = ESPLoader.checksum(seg.data, checksum)
        return checksum

    def append_checksum(self, f, checksum):
        """ Append ESPLoader checksum to the just-written image """
        align_file_position(f, 16)
        f.write(struct.pack(b'B', checksum))

    def write_common_header(self, f, segments):
        f.write(struct.pack('<BBBBI', ESPLoader.ESP_IMAGE_MAGIC, len(segments),
                            self.flash_mode, self.flash_size_freq, self.entrypoint))

    def is_irom_addr(self, addr):
        """ Returns True if an address starts in the irom region.
        Valid for ESP8266 only.
        """
        return ESP8266ROM.IROM_MAP_START <= addr < ESP8266ROM.IROM_MAP_END

    def get_irom_segment(self):
        irom_segments = [s for s in self.segments if self.is_irom_addr(s.addr)]
        if len(irom_segments) > 0:
            if len(irom_segments) != 1:
                raise FatalError('Found %d segments that could be irom0. Bad ELF file?' % len(irom_segments))
            return irom_segments[0]
        return None

    def get_non_irom_segments(self):
        irom_segment = self.get_irom_segment()
        return [s for s in self.segments if s != irom_segment]

    def merge_adjacent_segments(self):
        if not self.segments:
            return  # nothing to merge

        segments = []
        # The easiest way to merge the sections is the browse them backward.
        for i in range(len(self.segments) - 1, 0, -1):
            # elem is the previous section, the one `next_elem` may need to be
            # merged in
            elem = self.segments[i - 1]
            next_elem = self.segments[i]
            if all((elem.get_memory_type(self) == next_elem.get_memory_type(self),
                    elem.include_in_checksum == next_elem.include_in_checksum,
                    next_elem.addr == elem.addr + len(elem.data))):
                # Merge any segment that ends where the next one starts, without spanning memory types
                #
                # (don't 'pad' any gaps here as they may be excluded from the image due to 'noinit'
                # or other reasons.)
                elem.data += next_elem.data
            else:
                # The section next_elem cannot be merged into the previous one,
                # which means it needs to be part of the final segments.
                # As we are browsing the list backward, the elements need to be
                # inserted at the beginning of the final list.
                segments.insert(0, next_elem)

        # The first segment will always be here as it cannot be merged into any
        # "previous" section.
        segments.insert(0, self.segments[0])

        # note: we could sort segments here as well, but the ordering of segments is sometimes
        # important for other reasons (like embedded ELF SHA-256), so we assume that the linker
        # script will have produced any adjacent sections in linear order in the ELF, anyhow.
        self.segments = segments


class ESP8266ROMFirmwareImage(BaseFirmwareImage):
    """ 'Version 1' firmware image, segments loaded directly by the ROM bootloader. """

    ROM_LOADER = ESP8266ROM

    def __init__(self, load_file=None):
        super(ESP8266ROMFirmwareImage, self).__init__()
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1

        if load_file is not None:
            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            self.verify()

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        return input_file + '-'

    def save(self, basename):
        """ Save a set of V1 images for flashing. Parameter is a base filename. """
        # IROM data goes in its own plain binary file
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            with open("%s0x%05x.bin" % (basename, irom_segment.addr - ESP8266ROM.IROM_MAP_START), "wb") as f:
                f.write(irom_segment.data)

        # everything but IROM goes at 0x00000 in an image file
        normal_segments = self.get_non_irom_segments()
        with open("%s0x00000.bin" % basename, 'wb') as f:
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


ESP8266ROM.BOOTLOADER_IMAGE = ESP8266ROMFirmwareImage


class ESP8266V2FirmwareImage(BaseFirmwareImage):
    """ 'Version 2' firmware image, segments loaded by software bootloader stub
        (ie Espressif bootloader or rboot)
    """

    ROM_LOADER = ESP8266ROM

    def __init__(self, load_file=None):
        super(ESP8266V2FirmwareImage, self).__init__()
        self.version = 2
        if load_file is not None:
            segments = self.load_common_header(load_file, ESPBOOTLOADER.IMAGE_V2_MAGIC)
            if segments != ESPBOOTLOADER.IMAGE_V2_SEGMENT:
                # segment count is not really segment count here, but we expect to see '4'
                print('Warning: V2 header has unexpected "segment" count %d (usually 4)' % segments)

            # irom segment comes before the second header
            #
            # the file is saved in the image with a zero load address
            # in the header, so we need to calculate a load address
            irom_segment = self.load_segment(load_file, True)
            irom_segment.addr = 0  # for actual mapped addr, add ESP8266ROM.IROM_MAP_START + flashing_addr + 8
            irom_segment.include_in_checksum = False

            first_flash_mode = self.flash_mode
            first_flash_size_freq = self.flash_size_freq
            first_entrypoint = self.entrypoint
            # load the second header

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

            if first_flash_mode != self.flash_mode:
                print('WARNING: Flash mode value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_mode, self.flash_mode))
            if first_flash_size_freq != self.flash_size_freq:
                print('WARNING: Flash size/freq value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_size_freq, self.flash_size_freq))
            if first_entrypoint != self.entrypoint:
                print('WARNING: Entrypoint address in first header (0x%08x) disagrees with second header (0x%08x). Using second value.'
                      % (first_entrypoint, self.entrypoint))

            # load all the usual segments
            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            self.verify()

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            irom_offs = irom_segment.addr - ESP8266ROM.IROM_MAP_START
        else:
            irom_offs = 0
        return "%s-0x%05x.bin" % (os.path.splitext(input_file)[0],
                                  irom_offs & ~(ESPLoader.FLASH_SECTOR_SIZE - 1))

    def save(self, filename):
        with open(filename, 'wb') as f:
            # Save first header for irom0 segment
            f.write(struct.pack(b'<BBBBI', ESPBOOTLOADER.IMAGE_V2_MAGIC, ESPBOOTLOADER.IMAGE_V2_SEGMENT,
                                self.flash_mode, self.flash_size_freq, self.entrypoint))

            irom_segment = self.get_irom_segment()
            if irom_segment is not None:
                # save irom0 segment, make sure it has load addr 0 in the file
                irom_segment = irom_segment.copy_with_new_addr(0)
                irom_segment.pad_to_alignment(16)  # irom_segment must end on a 16 byte boundary
                self.save_segment(f, irom_segment)

            # second header, matches V1 header and contains loadable segments
            normal_segments = self.get_non_irom_segments()
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)

        # calculate a crc32 of entire file and append
        # (algorithm used by recent 8266 SDK bootloaders)
        with open(filename, 'rb') as f:
            crc = esp8266_crc32(f.read())
        with open(filename, 'ab') as f:
            f.write(struct.pack(b'<I', crc))


# Backwards compatibility for previous API, remove in esptool.py V3
ESPFirmwareImage = ESP8266ROMFirmwareImage
OTAFirmwareImage = ESP8266V2FirmwareImage


def esp8266_crc32(data):
    """
    CRC32 algorithm used by 8266 SDK bootloader (and gen_appbin.py).
    """
    crc = binascii.crc32(data, 0) & 0xFFFFFFFF
    if crc & 0x80000000:
        return crc ^ 0xFFFFFFFF
    else:
        return crc + 1


class ESP32FirmwareImage(BaseFirmwareImage):
    """ ESP32 firmware image is very similar to V1 ESP8266 image,
    except with an additional 16 byte reserved header at top of image,
    and because of new flash mapping capabilities the flash-mapped regions
    can be placed in the normal image (just @ 64kB padded offsets).
    """

    ROM_LOADER = ESP32ROM

    # ROM bootloader will read the wp_pin field if SPI flash
    # pins are remapped via flash. IDF actually enables QIO only
    # from software bootloader, so this can be ignored. But needs
    # to be set to this value so ROM bootloader will skip it.
    WP_PIN_DISABLED = 0xEE

    EXTENDED_HEADER_STRUCT_FMT = "<BBBBHB" + ("B" * 8) + "B"

    IROM_ALIGN = 65536

    def __init__(self, load_file=None):
        super(ESP32FirmwareImage, self).__init__()
        self.secure_pad = None
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1
        self.wp_pin = self.WP_PIN_DISABLED
        # SPI pin drive levels
        self.clk_drv = 0
        self.q_drv = 0
        self.d_drv = 0
        self.cs_drv = 0
        self.hd_drv = 0
        self.wp_drv = 0
        self.min_rev = 0

        self.append_digest = True

        if load_file is not None:
            start = load_file.tell()

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)
            self.load_extended_header(load_file)

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            if self.append_digest:
                end = load_file.tell()
                self.stored_digest = load_file.read(32)
                load_file.seek(start)
                calc_digest = hashlib.sha256()
                calc_digest.update(load_file.read(end - start))
                self.calc_digest = calc_digest.digest()  # TODO: decide what to do here?

            self.verify()

    def is_flash_addr(self, addr):
        return (self.ROM_LOADER.IROM_MAP_START <= addr < self.ROM_LOADER.IROM_MAP_END) \
            or (self.ROM_LOADER.DROM_MAP_START <= addr < self.ROM_LOADER.DROM_MAP_END)

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        return "%s.bin" % (os.path.splitext(input_file)[0])

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        pass  # TODO: add warnings for ESP32 segment offset/size combinations that are wrong

    def save(self, filename):
        total_segments = 0
        with io.BytesIO() as f:  # write file to memory first
            self.write_common_header(f, self.segments)

            # first 4 bytes of header are read by ROM bootloader for SPI
            # config, but currently unused
            self.save_extended_header(f)

            checksum = ESPLoader.ESP_CHECKSUM_MAGIC

            # split segments into flash-mapped vs ram-loaded, and take copies so we can mutate them
            flash_segments = [copy.deepcopy(s) for s in sorted(self.segments, key=lambda s:s.addr) if self.is_flash_addr(s.addr)]
            ram_segments = [copy.deepcopy(s) for s in sorted(self.segments, key=lambda s:s.addr) if not self.is_flash_addr(s.addr)]

            # check for multiple ELF sections that are mapped in the same flash mapping region.
            # this is usually a sign of a broken linker script, but if you have a legitimate
            # use case then let us know
            if len(flash_segments) > 0:
                last_addr = flash_segments[0].addr
                for segment in flash_segments[1:]:
                    if segment.addr // self.IROM_ALIGN == last_addr // self.IROM_ALIGN:
                        raise FatalError(("Segment loaded at 0x%08x lands in same 64KB flash mapping as segment loaded at 0x%08x. "
                                          "Can't generate binary. Suggest changing linker script or ELF to merge sections.") %
                                         (segment.addr, last_addr))
                    last_addr = segment.addr

            def get_alignment_data_needed(segment):
                # Actual alignment (in data bytes) required for a segment header: positioned so that
                # after we write the next 8 byte header, file_offs % IROM_ALIGN == segment.addr % IROM_ALIGN
                #
                # (this is because the segment's vaddr may not be IROM_ALIGNed, more likely is aligned
                # IROM_ALIGN+0x18 to account for the binary file header
                align_past = (segment.addr % self.IROM_ALIGN) - self.SEG_HEADER_LEN
                pad_len = (self.IROM_ALIGN - (f.tell() % self.IROM_ALIGN)) + align_past
                if pad_len == 0 or pad_len == self.IROM_ALIGN:
                    return 0  # already aligned

                # subtract SEG_HEADER_LEN a second time, as the padding block has a header as well
                pad_len -= self.SEG_HEADER_LEN
                if pad_len < 0:
                    pad_len += self.IROM_ALIGN
                return pad_len

            # try to fit each flash segment on a 64kB aligned boundary
            # by padding with parts of the non-flash segments...
            while len(flash_segments) > 0:
                segment = flash_segments[0]
                pad_len = get_alignment_data_needed(segment)
                if pad_len > 0:  # need to pad
                    if len(ram_segments) > 0 and pad_len > self.SEG_HEADER_LEN:
                        pad_segment = ram_segments[0].split_image(pad_len)
                        if len(ram_segments[0].data) == 0:
                            ram_segments.pop(0)
                    else:
                        pad_segment = ImageSegment(0, b'\x00' * pad_len, f.tell())
                    checksum = self.save_segment(f, pad_segment, checksum)
                    total_segments += 1
                else:
                    # write the flash segment
                    assert (f.tell() + 8) % self.IROM_ALIGN == segment.addr % self.IROM_ALIGN
                    checksum = self.save_flash_segment(f, segment, checksum)
                    flash_segments.pop(0)
                    total_segments += 1

            # flash segments all written, so write any remaining RAM segments
            for segment in ram_segments:
                checksum = self.save_segment(f, segment, checksum)
                total_segments += 1

            if self.secure_pad:
                # pad the image so that after signing it will end on a a 64KB boundary.
                # This ensures all mapped flash content will be verified.
                if not self.append_digest:
                    raise FatalError("secure_pad only applies if a SHA-256 digest is also appended to the image")
                align_past = (f.tell() + self.SEG_HEADER_LEN) % self.IROM_ALIGN
                # 16 byte aligned checksum (force the alignment to simplify calculations)
                checksum_space = 16
                if self.secure_pad == '1':
                    # after checksum: SHA-256 digest + (to be added by signing process) version, signature + 12 trailing bytes due to alignment
                    space_after_checksum = 32 + 4 + 64 + 12
                elif self.secure_pad == '2':  # Secure Boot V2
                    # after checksum: SHA-256 digest + signature sector, but we place signature sector after the 64KB boundary
                    space_after_checksum = 32
                pad_len = (self.IROM_ALIGN - align_past - checksum_space - space_after_checksum) % self.IROM_ALIGN
                pad_segment = ImageSegment(0, b'\x00' * pad_len, f.tell())

                checksum = self.save_segment(f, pad_segment, checksum)
                total_segments += 1

            # done writing segments
            self.append_checksum(f, checksum)
            image_length = f.tell()

            if self.secure_pad:
                assert ((image_length + space_after_checksum) % self.IROM_ALIGN) == 0

            # kinda hacky: go back to the initial header and write the new segment count
            # that includes padding segments. This header is not checksummed
            f.seek(1)
            try:
                f.write(chr(total_segments))
            except TypeError:  # Python 3
                f.write(bytes([total_segments]))

            if self.append_digest:
                # calculate the SHA256 of the whole file and append it
                f.seek(0)
                digest = hashlib.sha256()
                digest.update(f.read(image_length))
                f.write(digest.digest())

            with open(filename, 'wb') as real_file:
                real_file.write(f.getvalue())

    def save_flash_segment(self, f, segment, checksum=None):
        """ Save the next segment to the image file, return next checksum value if provided """
        segment_end_pos = f.tell() + len(segment.data) + self.SEG_HEADER_LEN
        segment_len_remainder = segment_end_pos % self.IROM_ALIGN
        if segment_len_remainder < 0x24:
            # Work around a bug in ESP-IDF 2nd stage bootloader, that it didn't map the
            # last MMU page, if an IROM/DROM segment was < 0x24 bytes over the page boundary.
            segment.data += b'\x00' * (0x24 - segment_len_remainder)
        return self.save_segment(f, segment, checksum)

    def load_extended_header(self, load_file):
        def split_byte(n):
            return (n & 0x0F, (n >> 4) & 0x0F)

        fields = list(struct.unpack(self.EXTENDED_HEADER_STRUCT_FMT, load_file.read(16)))

        self.wp_pin = fields[0]

        # SPI pin drive stengths are two per byte
        self.clk_drv, self.q_drv = split_byte(fields[1])
        self.d_drv, self.cs_drv = split_byte(fields[2])
        self.hd_drv, self.wp_drv = split_byte(fields[3])

        chip_id = fields[4]
        if chip_id != self.ROM_LOADER.IMAGE_CHIP_ID:
            print(("Unexpected chip id in image. Expected %d but value was %d. "
                   "Is this image for a different chip model?") % (self.ROM_LOADER.IMAGE_CHIP_ID, chip_id))

        # reserved fields in the middle should all be zero
        if any(f for f in fields[6:-1] if f != 0):
            print("Warning: some reserved header fields have non-zero values. This image may be from a newer esptool.py?")

        append_digest = fields[-1]  # last byte is append_digest
        if append_digest in [0, 1]:
            self.append_digest = (append_digest == 1)
        else:
            raise RuntimeError("Invalid value for append_digest field (0x%02x). Should be 0 or 1.", append_digest)

    def save_extended_header(self, save_file):
        def join_byte(ln, hn):
            return (ln & 0x0F) + ((hn & 0x0F) << 4)

        append_digest = 1 if self.append_digest else 0

        fields = [self.wp_pin,
                  join_byte(self.clk_drv, self.q_drv),
                  join_byte(self.d_drv, self.cs_drv),
                  join_byte(self.hd_drv, self.wp_drv),
                  self.ROM_LOADER.IMAGE_CHIP_ID,
                  self.min_rev]
        fields += [0] * 8  # padding
        fields += [append_digest]

        packed = struct.pack(self.EXTENDED_HEADER_STRUCT_FMT, *fields)
        save_file.write(packed)


ESP32ROM.BOOTLOADER_IMAGE = ESP32FirmwareImage


class ESP32S2FirmwareImage(ESP32FirmwareImage):
    """ ESP32S2 Firmware Image almost exactly the same as ESP32FirmwareImage """
    ROM_LOADER = ESP32S2ROM


ESP32S2ROM.BOOTLOADER_IMAGE = ESP32S2FirmwareImage


class ESP32S3BETA2FirmwareImage(ESP32FirmwareImage):
    """ ESP32S3 Firmware Image almost exactly the same as ESP32FirmwareImage """
    ROM_LOADER = ESP32S3BETA2ROM


ESP32S3BETA2ROM.BOOTLOADER_IMAGE = ESP32S3BETA2FirmwareImage


class ESP32S3BETA3FirmwareImage(ESP32FirmwareImage):
    """ ESP32S3 Firmware Image almost exactly the same as ESP32FirmwareImage """
    ROM_LOADER = ESP32S3BETA3ROM


ESP32S3BETA3ROM.BOOTLOADER_IMAGE = ESP32S3BETA3FirmwareImage


class ESP32C3FirmwareImage(ESP32FirmwareImage):
    """ ESP32C3 Firmware Image almost exactly the same as ESP32FirmwareImage """
    ROM_LOADER = ESP32C3ROM


ESP32C3ROM.BOOTLOADER_IMAGE = ESP32C3FirmwareImage


class ELFFile(object):
    SEC_TYPE_PROGBITS = 0x01
    SEC_TYPE_STRTAB = 0x03

    LEN_SEC_HEADER = 0x28

    SEG_TYPE_LOAD = 0x01
    LEN_SEG_HEADER = 0x20

    def __init__(self, name):
        # Load sections from the ELF file
        self.name = name
        with open(self.name, 'rb') as f:
            self._read_elf_file(f)

    def get_section(self, section_name):
        for s in self.sections:
            if s.name == section_name:
                return s
        raise ValueError("No section %s in ELF file" % section_name)

    def _read_elf_file(self, f):
        # read the ELF file header
        LEN_FILE_HEADER = 0x34
        try:
            (ident, _type, machine, _version,
             self.entrypoint, _phoff, shoff, _flags,
             _ehsize, _phentsize, _phnum, shentsize,
             shnum, shstrndx) = struct.unpack("<16sHHLLLLLHHHHHH", f.read(LEN_FILE_HEADER))
        except struct.error as e:
            raise FatalError("Failed to read a valid ELF header from %s: %s" % (self.name, e))

        if byte(ident, 0) != 0x7f or ident[1:4] != b'ELF':
            raise FatalError("%s has invalid ELF magic header" % self.name)
        if machine not in [0x5e, 0xf3]:
            raise FatalError("%s does not appear to be an Xtensa or an RISCV ELF file. e_machine=%04x" % (self.name, machine))
        if shentsize != self.LEN_SEC_HEADER:
            raise FatalError("%s has unexpected section header entry size 0x%x (not 0x%x)" % (self.name, shentsize, self.LEN_SEC_HEADER))
        if shnum == 0:
            raise FatalError("%s has 0 section headers" % (self.name))
        self._read_sections(f, shoff, shnum, shstrndx)
        self._read_segments(f, _phoff, _phnum, shstrndx)

    def _read_sections(self, f, section_header_offs, section_header_count, shstrndx):
        f.seek(section_header_offs)
        len_bytes = section_header_count * self.LEN_SEC_HEADER
        section_header = f.read(len_bytes)
        if len(section_header) == 0:
            raise FatalError("No section header found at offset %04x in ELF file." % section_header_offs)
        if len(section_header) != (len_bytes):
            raise FatalError("Only read 0x%x bytes from section header (expected 0x%x.) Truncated ELF file?" % (len(section_header), len_bytes))

        # walk through the section header and extract all sections
        section_header_offsets = range(0, len(section_header), self.LEN_SEC_HEADER)

        def read_section_header(offs):
            name_offs, sec_type, _flags, lma, sec_offs, size = struct.unpack_from("<LLLLLL", section_header[offs:])
            return (name_offs, sec_type, lma, size, sec_offs)
        all_sections = [read_section_header(offs) for offs in section_header_offsets]
        prog_sections = [s for s in all_sections if s[1] == ELFFile.SEC_TYPE_PROGBITS]

        # search for the string table section
        if not (shstrndx * self.LEN_SEC_HEADER) in section_header_offsets:
            raise FatalError("ELF file has no STRTAB section at shstrndx %d" % shstrndx)
        _, sec_type, _, sec_size, sec_offs = read_section_header(shstrndx * self.LEN_SEC_HEADER)
        if sec_type != ELFFile.SEC_TYPE_STRTAB:
            print('WARNING: ELF file has incorrect STRTAB section type 0x%02x' % sec_type)
        f.seek(sec_offs)
        string_table = f.read(sec_size)

        # build the real list of ELFSections by reading the actual section names from the
        # string table section, and actual data for each section from the ELF file itself
        def lookup_string(offs):
            raw = string_table[offs:]
            return raw[:raw.index(b'\x00')]

        def read_data(offs, size):
            f.seek(offs)
            return f.read(size)

        prog_sections = [ELFSection(lookup_string(n_offs), lma, read_data(offs, size)) for (n_offs, _type, lma, size, offs) in prog_sections
                         if lma != 0 and size > 0]
        self.sections = prog_sections

    def _read_segments(self, f, segment_header_offs, segment_header_count, shstrndx):
        f.seek(segment_header_offs)
        len_bytes = segment_header_count * self.LEN_SEG_HEADER
        segment_header = f.read(len_bytes)
        if len(segment_header) == 0:
            raise FatalError("No segment header found at offset %04x in ELF file." % segment_header_offs)
        if len(segment_header) != (len_bytes):
            raise FatalError("Only read 0x%x bytes from segment header (expected 0x%x.) Truncated ELF file?" % (len(segment_header), len_bytes))

        # walk through the segment header and extract all segments
        segment_header_offsets = range(0, len(segment_header), self.LEN_SEG_HEADER)

        def read_segment_header(offs):
            seg_type, seg_offs, _vaddr, lma, size, _memsize, _flags, _align = struct.unpack_from("<LLLLLLLL", segment_header[offs:])
            return (seg_type, lma, size, seg_offs)
        all_segments = [read_segment_header(offs) for offs in segment_header_offsets]
        prog_segments = [s for s in all_segments if s[0] == ELFFile.SEG_TYPE_LOAD]

        def read_data(offs, size):
            f.seek(offs)
            return f.read(size)

        prog_segments = [ELFSection(b'PHDR', lma, read_data(offs, size)) for (_type, lma, size, offs) in prog_segments
                         if lma != 0 and size > 0]
        self.segments = prog_segments

    def sha256(self):
        # return SHA256 hash of the input ELF file
        sha256 = hashlib.sha256()
        with open(self.name, 'rb') as f:
            sha256.update(f.read())
        return sha256.digest()


def slip_reader(port, trace_function):
    """Generator to read SLIP packets from a serial port.
    Yields one full SLIP packet at a time, raises exception on timeout or invalid data.

    Designed to avoid too many calls to serial.read(1), which can bog
    down on slow systems.
    """
    partial_packet = None
    in_escape = False
    while True:
        waiting = port.inWaiting()
        read_bytes = port.read(1 if waiting == 0 else waiting)
        if read_bytes == b'':
            waiting_for = "header" if partial_packet is None else "content"
            trace_function("Timed out waiting for packet %s", waiting_for)
            raise FatalError("Timed out waiting for packet %s" % waiting_for)
        trace_function("Read %d bytes: %s", len(read_bytes), HexFormatter(read_bytes))
        for b in read_bytes:
            if type(b) is int:
                b = bytes([b])  # python 2/3 compat

            if partial_packet is None:  # waiting for packet header
                if b == b'\xc0':
                    partial_packet = b""
                else:
                    trace_function("Read invalid data: %s", HexFormatter(read_bytes))
                    trace_function("Remaining data in serial buffer: %s", HexFormatter(port.read(port.inWaiting())))
                    raise FatalError('Invalid head of packet (0x%s)' % hexify(b))
            elif in_escape:  # part-way through escape sequence
                in_escape = False
                if b == b'\xdc':
                    partial_packet += b'\xc0'
                elif b == b'\xdd':
                    partial_packet += b'\xdb'
                else:
                    trace_function("Read invalid data: %s", HexFormatter(read_bytes))
                    trace_function("Remaining data in serial buffer: %s", HexFormatter(port.read(port.inWaiting())))
                    raise FatalError('Invalid SLIP escape (0xdb, 0x%s)' % (hexify(b)))
            elif b == b'\xdb':  # start of escape sequence
                in_escape = True
            elif b == b'\xc0':  # end of packet
                trace_function("Received full packet: %s", HexFormatter(partial_packet))
                yield partial_packet
                partial_packet = None
            else:  # normal byte in packet
                partial_packet += b


def arg_auto_int(x):
    return int(x, 0)


def div_roundup(a, b):
    """ Return a/b rounded up to nearest integer,
    equivalent result to int(math.ceil(float(int(a)) / float(int(b))), only
    without possible floating point accuracy errors.
    """
    return (int(a) + int(b) - 1) // int(b)


def align_file_position(f, size):
    """ Align the position in the file to the next block of specified size """
    align = (size - 1) - (f.tell() % size)
    f.seek(align, 1)


def flash_size_bytes(size):
    """ Given a flash size of the type passed in args.flash_size
    (ie 512KB or 1MB) then return the size in bytes.
    """
    if "MB" in size:
        return int(size[:size.index("MB")]) * 1024 * 1024
    elif "KB" in size:
        return int(size[:size.index("KB")]) * 1024
    else:
        raise FatalError("Unknown size %s" % size)


def hexify(s, uppercase=True):
    format_str = '%02X' if uppercase else '%02x'
    if not PYTHON2:
        return ''.join(format_str % c for c in s)
    else:
        return ''.join(format_str % ord(c) for c in s)


class HexFormatter(object):
    """
    Wrapper class which takes binary data in its constructor
    and returns a hex string as it's __str__ method.

    This is intended for "lazy formatting" of trace() output
    in hex format. Avoids overhead (significant on slow computers)
    of generating long hex strings even if tracing is disabled.

    Note that this doesn't save any overhead if passed as an
    argument to "%", only when passed to trace()

    If auto_split is set (default), any long line (> 16 bytes) will be
    printed as separately indented lines, with ASCII decoding at the end
    of each line.
    """
    def __init__(self, binary_string, auto_split=True):
        self._s = binary_string
        self._auto_split = auto_split

    def __str__(self):
        if self._auto_split and len(self._s) > 16:
            result = ""
            s = self._s
            while len(s) > 0:
                line = s[:16]
                ascii_line = "".join(c if (c == ' ' or (c in string.printable and c not in string.whitespace))
                                     else '.' for c in line.decode('ascii', 'replace'))
                s = s[16:]
                result += "\n    %-16s %-16s | %s" % (hexify(line[:8], False), hexify(line[8:], False), ascii_line)
            return result
        else:
            return hexify(self._s, False)


def pad_to(data, alignment, pad_character=b'\xFF'):
    """ Pad to the next alignment boundary """
    pad_mod = len(data) % alignment
    if pad_mod != 0:
        data += pad_character * (alignment - pad_mod)
    return data


class FatalError(RuntimeError):
    """
    Wrapper class for runtime errors that aren't caused by internal bugs, but by
    ESP8266 responses or input content.
    """
    def __init__(self, message):
        RuntimeError.__init__(self, message)

    @staticmethod
    def WithResult(message, result):
        """
        Return a fatal error object that appends the hex values of
        'result' as a string formatted argument.
        """
        message += " (result was %s)" % hexify(result)
        return FatalError(message)


class NotImplementedInROMError(FatalError):
    """
    Wrapper class for the error thrown when a particular ESP bootloader function
    is not implemented in the ROM bootloader.
    """
    def __init__(self, bootloader, func):
        FatalError.__init__(self, "%s ROM does not support function %s." % (bootloader.CHIP_NAME, func.__name__))


class NotSupportedError(FatalError):
    def __init__(self, esp, function_name):
        FatalError.__init__(self, "Function %s is not supported for %s." % (function_name, esp.CHIP_NAME))

# "Operation" commands, executable at command line. One function each
#
# Each function takes either two args (<ESPLoader instance>, <args>) or a single <args>
# argument.


class UnsupportedCommandError(RuntimeError):
    """
    Wrapper class for when ROM loader returns an invalid command response.

    Usually this indicates the loader is running in Secure Download Mode.
    """
    def __init__(self, esp, op):
        if esp.secure_download_mode:
            msg = "This command (0x%x) is not supported in Secure Download Mode" % op
        else:
            msg = "Invalid (unsupported) command 0x%x" % op
        RuntimeError.__init__(self, msg)


def load_ram(esp, args):
    image = LoadFirmwareImage(esp.CHIP_NAME, args.filename)

    print('RAM boot...')
    for seg in image.segments:
        size = len(seg.data)
        print('Downloading %d bytes at %08x...' % (size, seg.addr), end=' ')
        sys.stdout.flush()
        esp.mem_begin(size, div_roundup(size, esp.ESP_RAM_BLOCK), esp.ESP_RAM_BLOCK, seg.addr)

        seq = 0
        while len(seg.data) > 0:
            esp.mem_block(seg.data[0:esp.ESP_RAM_BLOCK], seq)
            seg.data = seg.data[esp.ESP_RAM_BLOCK:]
            seq += 1
        print('done!')

    print('All segments done, executing at %08x' % image.entrypoint)
    esp.mem_finish(image.entrypoint)


def read_mem(esp, args):
    print('0x%08x = 0x%08x' % (args.address, esp.read_reg(args.address)))


def write_mem(esp, args):
    esp.write_reg(args.address, args.value, args.mask, 0)
    print('Wrote %08x, mask %08x to %08x' % (args.value, args.mask, args.address))


def dump_mem(esp, args):
    with open(args.filename, 'wb') as f:
        for i in range(args.size // 4):
            d = esp.read_reg(args.address + (i * 4))
            f.write(struct.pack(b'<I', d))
            if f.tell() % 1024 == 0:
                print_overwrite('%d bytes read... (%d %%)' % (f.tell(),
                                                              f.tell() * 100 // args.size))
            sys.stdout.flush()
        print_overwrite("Read %d bytes" % f.tell(), last_line=True)
    print('Done!')


def detect_flash_size(esp, args):
    if args.flash_size == 'detect':
        if esp.secure_download_mode:
            raise FatalError("Detecting flash size is not supported in secure download mode. Need to manually specify flash size.")
        flash_id = esp.flash_id()
        size_id = flash_id >> 16
        args.flash_size = DETECTED_FLASH_SIZES.get(size_id)
        if args.flash_size is None:
            print('Warning: Could not auto-detect Flash size (FlashID=0x%x, SizeID=0x%x), defaulting to 4MB' % (flash_id, size_id))
            args.flash_size = '4MB'
        else:
            print('Auto-detected Flash size:', args.flash_size)


def _update_image_flash_params(esp, address, args, image):
    """ Modify the flash mode & size bytes if this looks like an executable bootloader image  """
    if len(image) < 8:
        return image  # not long enough to be a bootloader image

    # unpack the (potential) image header
    magic, _, flash_mode, flash_size_freq = struct.unpack("BBBB", image[:4])
    if address != esp.BOOTLOADER_FLASH_OFFSET:
        return image  # not flashing bootloader offset, so don't modify this

    if (args.flash_mode, args.flash_freq, args.flash_size) == ('keep',) * 3:
        return image  # all settings are 'keep', not modifying anything

    # easy check if this is an image: does it start with a magic byte?
    if magic != esp.ESP_IMAGE_MAGIC:
        print("Warning: Image file at 0x%x doesn't look like an image file, so not changing any flash settings." % address)
        return image

    # make sure this really is an image, and not just data that
    # starts with esp.ESP_IMAGE_MAGIC (mostly a problem for encrypted
    # images that happen to start with a magic byte
    try:
        test_image = esp.BOOTLOADER_IMAGE(io.BytesIO(image))
        test_image.verify()
    except Exception:
        print("Warning: Image file at 0x%x is not a valid %s image, so not changing any flash settings." % (address, esp.CHIP_NAME))
        return image

    if args.flash_mode != 'keep':
        flash_mode = {'qio': 0, 'qout': 1, 'dio': 2, 'dout': 3}[args.flash_mode]

    flash_freq = flash_size_freq & 0x0F
    if args.flash_freq != 'keep':
        flash_freq = {'40m': 0, '26m': 1, '20m': 2, '80m': 0xf}[args.flash_freq]

    flash_size = flash_size_freq & 0xF0
    if args.flash_size != 'keep':
        flash_size = esp.parse_flash_size_arg(args.flash_size)

    flash_params = struct.pack(b'BB', flash_mode, flash_size + flash_freq)
    if flash_params != image[2:4]:
        print('Flash params set to 0x%04x' % struct.unpack(">H", flash_params))
        image = image[0:2] + flash_params + image[4:]
    return image


def write_flash(esp, args):
    # set args.compress based on default behaviour:
    # -> if either --compress or --no-compress is set, honour that
    # -> otherwise, set --compress unless --no-stub is set
    if args.compress is None and not args.no_compress:
        args.compress = not args.no_stub

    # In case we have encrypted files to write, we first do few sanity checks before actual flash
    if args.encrypt or args.encrypt_files is not None:
        do_write = True

        if not esp.secure_download_mode:
            if esp.get_encrypted_download_disabled():
                raise FatalError("This chip has encrypt functionality in UART download mode disabled. "
                                 "This is the Flash Encryption configuration for Production mode instead of Development mode.")

            crypt_cfg_efuse = esp.get_flash_crypt_config()

            if crypt_cfg_efuse is not None and crypt_cfg_efuse != 0xF:
                print('Unexpected FLASH_CRYPT_CONFIG value: 0x%x' % (crypt_cfg_efuse))
                do_write = False

            enc_key_valid = esp.is_flash_encryption_key_valid()

            if not enc_key_valid:
                print('Flash encryption key is not programmed')
                do_write = False

        # Determine which files list contain the ones to encrypt
        files_to_encrypt = args.addr_filename if args.encrypt else args.encrypt_files

        for address, argfile in files_to_encrypt:
            if address % esp.FLASH_ENCRYPTED_WRITE_ALIGN:
                print("File %s address 0x%x is not %d byte aligned, can't flash encrypted" %
                      (argfile.name, address, esp.FLASH_ENCRYPTED_WRITE_ALIGN))
                do_write = False

        if not do_write and not args.ignore_flash_encryption_efuse_setting:
            raise FatalError("Can't perform encrypted flash write, consult Flash Encryption documentation for more information")

    # verify file sizes fit in flash
    if args.flash_size != 'keep':  # TODO: check this even with 'keep'
        flash_end = flash_size_bytes(args.flash_size)
        for address, argfile in args.addr_filename:
            argfile.seek(0, os.SEEK_END)
            if address + argfile.tell() > flash_end:
                raise FatalError(("File %s (length %d) at offset %d will not fit in %d bytes of flash. "
                                  "Use --flash-size argument, or change flashing address.")
                                 % (argfile.name, argfile.tell(), address, flash_end))
            argfile.seek(0)

    if args.erase_all:
        erase_flash(esp, args)
    else:
        for address, argfile in args.addr_filename:
            argfile.seek(0, os.SEEK_END)
            write_end = address + argfile.tell()
            argfile.seek(0)
            bytes_over = address % esp.FLASH_SECTOR_SIZE
            if bytes_over != 0:
                print("WARNING: Flash address {:#010x} is not aligned to a {:#x} byte flash sector. "
                      "{:#x} bytes before this address will be erased."
                      .format(address, esp.FLASH_SECTOR_SIZE, bytes_over))
            # Print the address range of to-be-erased flash memory region
            print("Flash will be erased from {:#010x} to {:#010x}..."
                  .format(address - bytes_over, div_roundup(write_end, esp.FLASH_SECTOR_SIZE) * esp.FLASH_SECTOR_SIZE - 1))

    """ Create a list describing all the files we have to flash. Each entry holds an "encrypt" flag
    marking whether the file needs encryption or not. This list needs to be sorted.

    First, append to each entry of our addr_filename list the flag args.encrypt
    For example, if addr_filename is [(0x1000, "partition.bin"), (0x8000, "bootloader")],
    all_files will be [(0x1000, "partition.bin", args.encrypt), (0x8000, "bootloader", args.encrypt)],
    where, of course, args.encrypt is either True or False
    """
    all_files = [(offs, filename, args.encrypt) for (offs, filename) in args.addr_filename]

    """Now do the same with encrypt_files list, if defined.
    In this case, the flag is True
    """
    if args.encrypt_files is not None:
        encrypted_files_flag = [(offs, filename, True) for (offs, filename) in args.encrypt_files]

        # Concatenate both lists and sort them.
        # As both list are already sorted, we could simply do a merge instead,
        # but for the sake of simplicity and because the lists are very small,
        # let's use sorted.
        all_files = sorted(all_files + encrypted_files_flag, key=lambda x: x[0])

    for address, argfile, encrypted in all_files:
        compress = args.compress

        # Check whether we can compress the current file before flashing
        if compress and encrypted:
            print('\nWARNING: - compress and encrypt options are mutually exclusive ')
            print('Will flash %s uncompressed' % argfile.name)
            compress = False

        if args.no_stub:
            print('Erasing flash...')
        image = pad_to(argfile.read(), esp.FLASH_ENCRYPTED_WRITE_ALIGN if encrypted else 4)
        if len(image) == 0:
            print('WARNING: File %s is empty' % argfile.name)
            continue
        image = _update_image_flash_params(esp, address, args, image)
        calcmd5 = hashlib.md5(image).hexdigest()
        uncsize = len(image)
        if compress:
            uncimage = image
            image = zlib.compress(uncimage, 9)
            # Decompress the compressed binary a block at a time, to dynamically calculate the
            # timeout based on the real write size
            decompress = zlib.decompressobj()
            blocks = esp.flash_defl_begin(uncsize, len(image), address)
        else:
            blocks = esp.flash_begin(uncsize, address, begin_rom_encrypted=encrypted)
        argfile.seek(0)  # in case we need it again
        seq = 0
        bytes_sent = 0  # bytes sent on wire
        bytes_written = 0  # bytes written to flash
        t = time.time()

        timeout = DEFAULT_TIMEOUT

        while len(image) > 0:
            print_overwrite('Writing at 0x%08x... (%d %%)' % (address + bytes_written, 100 * (seq + 1) // blocks))
            sys.stdout.flush()
            block = image[0:esp.FLASH_WRITE_SIZE]
            if compress:
                # feeding each compressed block into the decompressor lets us see block-by-block how much will be written
                block_uncompressed = len(decompress.decompress(block))
                bytes_written += block_uncompressed
                block_timeout = max(DEFAULT_TIMEOUT, timeout_per_mb(ERASE_WRITE_TIMEOUT_PER_MB, block_uncompressed))
                if not esp.IS_STUB:
                    timeout = block_timeout  # ROM code writes block to flash before ACKing
                esp.flash_defl_block(block, seq, timeout=timeout)
                if esp.IS_STUB:
                    timeout = block_timeout  # Stub ACKs when block is received, then writes to flash while receiving the block after it
            else:
                # Pad the last block
                block = block + b'\xff' * (esp.FLASH_WRITE_SIZE - len(block))
                if encrypted:
                    esp.flash_encrypt_block(block, seq)
                else:
                    esp.flash_block(block, seq)
                bytes_written += len(block)
            bytes_sent += len(block)
            image = image[esp.FLASH_WRITE_SIZE:]
            seq += 1

        if esp.IS_STUB:
            # Stub only writes each block to flash after 'ack'ing the receive, so do a final dummy operation which will
            # not be 'ack'ed until the last block has actually been written out to flash
            esp.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR, timeout=timeout)

        t = time.time() - t
        speed_msg = ""
        if compress:
            if t > 0.0:
                speed_msg = " (effective %.1f kbit/s)" % (uncsize / t * 8 / 1000)
            print_overwrite('Wrote %d bytes (%d compressed) at 0x%08x in %.1f seconds%s...' % (uncsize,
                                                                                               bytes_sent,
                                                                                               address, t, speed_msg), last_line=True)
        else:
            if t > 0.0:
                speed_msg = " (%.1f kbit/s)" % (bytes_written / t * 8 / 1000)
            print_overwrite('Wrote %d bytes at 0x%08x in %.1f seconds%s...' % (bytes_written, address, t, speed_msg), last_line=True)

        if not encrypted and not esp.secure_download_mode:
            try:
                res = esp.flash_md5sum(address, uncsize)
                if res != calcmd5:
                    print('File  md5: %s' % calcmd5)
                    print('Flash md5: %s' % res)
                    print('MD5 of 0xFF is %s' % (hashlib.md5(b'\xFF' * uncsize).hexdigest()))
                    raise FatalError("MD5 of file does not match data in flash!")
                else:
                    print('Hash of data verified.')
            except NotImplementedInROMError:
                pass

    print('\nLeaving...')

    if esp.IS_STUB:
        # skip sending flash_finish to ROM loader here,
        # as it causes the loader to exit and run user code
        esp.flash_begin(0, 0)

        # Get the "encrypted" flag for the last file flashed
        # Note: all_files list contains triplets like:
        # (address: Integer, filename: String, encrypted: Boolean)
        last_file_encrypted = all_files[-1][2]

        # Check whether the last file flashed was compressed or not
        if args.compress and not last_file_encrypted:
            esp.flash_defl_finish(False)
        else:
            esp.flash_finish(False)

    if args.verify:
        print('Verifying just-written flash...')
        print('(This option is deprecated, flash contents are now always read back after flashing.)')
        # If some encrypted files have been flashed print a warning saying that we won't check them
        if args.encrypt or args.encrypt_files is not None:
            print('WARNING: - cannot verify encrypted files, they will be ignored')
        # Call verify_flash function only if there at least one non-encrypted file flashed
        if not args.encrypt:
            verify_flash(esp, args)


def image_info(args):
    image = LoadFirmwareImage(args.chip, args.filename)
    print('Image version: %d' % image.version)
    print('Entry point: %08x' % image.entrypoint if image.entrypoint != 0 else 'Entry point not set')
    print('%d segments' % len(image.segments))
    print()
    idx = 0
    for seg in image.segments:
        idx += 1
        segs = seg.get_memory_type(image)
        seg_name = ",".join(segs)
        print('Segment %d: %r [%s]' % (idx, seg, seg_name))
    calc_checksum = image.calculate_checksum()
    print('Checksum: %02x (%s)' % (image.checksum,
                                   'valid' if image.checksum == calc_checksum else 'invalid - calculated %02x' % calc_checksum))
    try:
        digest_msg = 'Not appended'
        if image.append_digest:
            is_valid = image.stored_digest == image.calc_digest
            digest_msg = "%s (%s)" % (hexify(image.calc_digest).lower(),
                                      "valid" if is_valid else "invalid")
            print('Validation Hash: %s' % digest_msg)
    except AttributeError:
        pass  # ESP8266 image has no append_digest field


def make_image(args):
    image = ESP8266ROMFirmwareImage()
    if len(args.segfile) == 0:
        raise FatalError('No segments specified')
    if len(args.segfile) != len(args.segaddr):
        raise FatalError('Number of specified files does not match number of specified addresses')
    for (seg, addr) in zip(args.segfile, args.segaddr):
        with open(seg, 'rb') as f:
            data = f.read()
            image.segments.append(ImageSegment(addr, data))
    image.entrypoint = args.entrypoint
    image.save(args.output)


def elf2image(args):
    e = ELFFile(args.input)
    if args.chip == 'auto':  # Default to ESP8266 for backwards compatibility
        print("Creating image for ESP8266...")
        args.chip = 'esp8266'

    if args.chip == 'esp32':
        image = ESP32FirmwareImage()
        if args.secure_pad:
            image.secure_pad = '1'
        elif args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32s2':
        image = ESP32S2FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32s3beta2':
        image = ESP32S3BETA2FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32s3beta3':
        image = ESP32S3BETA3FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.chip == 'esp32c3':
        image = ESP32C3FirmwareImage()
        if args.secure_pad_v2:
            image.secure_pad = '2'
    elif args.version == '1':  # ESP8266
        image = ESP8266ROMFirmwareImage()
    else:
        image = ESP8266V2FirmwareImage()
    image.entrypoint = e.entrypoint
    image.flash_mode = {'qio': 0, 'qout': 1, 'dio': 2, 'dout': 3}[args.flash_mode]

    if args.chip != 'esp8266':
        image.min_rev = int(args.min_rev)

    # ELFSection is a subclass of ImageSegment, so can use interchangeably
    image.segments = e.segments if args.use_segments else e.sections

    image.flash_size_freq = image.ROM_LOADER.FLASH_SIZES[args.flash_size]
    image.flash_size_freq += {'40m': 0, '26m': 1, '20m': 2, '80m': 0xf}[args.flash_freq]

    if args.elf_sha256_offset:
        image.elf_sha256 = e.sha256()
        image.elf_sha256_offset = args.elf_sha256_offset

    before = len(image.segments)
    image.merge_adjacent_segments()
    if len(image.segments) != before:
        delta = before - len(image.segments)
        print("Merged %d ELF section%s" % (delta, "s" if delta > 1 else ""))

    image.verify()

    if args.output is None:
        args.output = image.default_output_name(args.input)
    image.save(args.output)


def read_mac(esp, args):
    mac = esp.read_mac()

    def print_mac(label, mac):
        print('%s: %s' % (label, ':'.join(map(lambda x: '%02x' % x, mac))))
    print_mac("MAC", mac)


def chip_id(esp, args):
    try:
        chipid = esp.chip_id()
        print('Chip ID: 0x%08x' % chipid)
    except NotSupportedError:
        print('Warning: %s has no Chip ID. Reading MAC instead.' % esp.CHIP_NAME)
        read_mac(esp, args)


def erase_flash(esp, args):
    print('Erasing flash (this may take a while)...')
    t = time.time()
    esp.erase_flash()
    print('Chip erase completed successfully in %.1fs' % (time.time() - t))


def erase_region(esp, args):
    print('Erasing region (may be slow depending on size)...')
    t = time.time()
    esp.erase_region(args.address, args.size)
    print('Erase completed successfully in %.1f seconds.' % (time.time() - t))


def run(esp, args):
    esp.run()


def flash_id(esp, args):
    flash_id = esp.flash_id()
    print('Manufacturer: %02x' % (flash_id & 0xff))
    flid_lowbyte = (flash_id >> 16) & 0xFF
    print('Device: %02x%02x' % ((flash_id >> 8) & 0xff, flid_lowbyte))
    print('Detected flash size: %s' % (DETECTED_FLASH_SIZES.get(flid_lowbyte, "Unknown")))


def read_flash(esp, args):
    if args.no_progress:
        flash_progress = None
    else:
        def flash_progress(progress, length):
            msg = '%d (%d %%)' % (progress, progress * 100.0 / length)
            padding = '\b' * len(msg)
            if progress == length:
                padding = '\n'
            sys.stdout.write(msg + padding)
            sys.stdout.flush()
    t = time.time()
    data = esp.read_flash(args.address, args.size, flash_progress)
    t = time.time() - t
    print_overwrite('Read %d bytes at 0x%x in %.1f seconds (%.1f kbit/s)...'
                    % (len(data), args.address, t, len(data) / t * 8 / 1000), last_line=True)
    with open(args.filename, 'wb') as f:
        f.write(data)


def verify_flash(esp, args):
    differences = False

    for address, argfile in args.addr_filename:
        image = pad_to(argfile.read(), 4)
        argfile.seek(0)  # rewind in case we need it again

        image = _update_image_flash_params(esp, address, args, image)

        image_size = len(image)
        print('Verifying 0x%x (%d) bytes @ 0x%08x in flash against %s...' % (image_size, image_size, address, argfile.name))
        # Try digest first, only read if there are differences.
        digest = esp.flash_md5sum(address, image_size)
        expected_digest = hashlib.md5(image).hexdigest()
        if digest == expected_digest:
            print('-- verify OK (digest matched)')
            continue
        else:
            differences = True
            if getattr(args, 'diff', 'no') != 'yes':
                print('-- verify FAILED (digest mismatch)')
                continue

        flash = esp.read_flash(address, image_size)
        assert flash != image
        diff = [i for i in range(image_size) if flash[i] != image[i]]
        print('-- verify FAILED: %d differences, first @ 0x%08x' % (len(diff), address + diff[0]))
        for d in diff:
            flash_byte = flash[d]
            image_byte = image[d]
            if PYTHON2:
                flash_byte = ord(flash_byte)
                image_byte = ord(image_byte)
            print('   %08x %02x %02x' % (address + d, flash_byte, image_byte))
    if differences:
        raise FatalError("Verify failed.")


def read_flash_status(esp, args):
    print('Status value: 0x%04x' % esp.read_status(args.bytes))


def write_flash_status(esp, args):
    fmt = "0x%%0%dx" % (args.bytes * 2)
    args.value = args.value & ((1 << (args.bytes * 8)) - 1)
    print(('Initial flash status: ' + fmt) % esp.read_status(args.bytes))
    print(('Setting flash status: ' + fmt) % args.value)
    esp.write_status(args.value, args.bytes, args.non_volatile)
    print(('After flash status:   ' + fmt) % esp.read_status(args.bytes))


def get_security_info(esp, args):
    (flags, flash_crypt_cnt, key_purposes) = esp.get_security_info()
    # TODO: better display
    print('Flags: 0x%08x (%s)' % (flags, bin(flags)))
    print('Flash_Crypt_Cnt: 0x%x' % flash_crypt_cnt)
    print('Key_Purposes: %s' % (key_purposes,))


def merge_bin(args):
    chip_class = _chip_to_rom_loader(args.chip)

    # sort the files by offset. The AddrFilenamePairAction has already checked for overlap
    input_files = sorted(args.addr_filename, key=lambda x: x[0])
    if not input_files:
        raise FatalError("No input files specified")
    first_addr = input_files[0][0]
    if first_addr < args.target_offset:
        raise FatalError("Output file target offset is 0x%x. Input file offset 0x%x is before this." % (args.target_offset, first_addr))

    if args.format != 'raw':
        raise FatalError("This version of esptool only supports the 'raw' output format")

    with open(args.output, 'wb') as of:
        def pad_to(flash_offs):
            # account for output file offset if there is any
            of.write(b'\xFF' * (flash_offs - args.target_offset - of.tell()))
        for addr, argfile in input_files:
            pad_to(addr)
            image = argfile.read()
            image = _update_image_flash_params(chip_class, addr, args, image)
            of.write(image)
        if args.fill_flash_size:
            pad_to(flash_size_bytes(args.fill_flash_size))
        print("Wrote 0x%x bytes to file %s, ready to flash to offset 0x%x" % (of.tell(), args.output, args.target_offset))


def version(args):
    print(__version__)

#
# End of operations functions
#


def main(argv=None, esp=None):
    """
    Main function for esptool

    argv - Optional override for default arguments parsing (that uses sys.argv), can be a list of custom arguments
    as strings. Arguments and their values need to be added as individual items to the list e.g. "-b 115200" thus
    becomes ['-b', '115200'].

    esp - Optional override of the connected device previously returned by get_default_connected_device()
    """

    external_esp = esp is not None

    parser = argparse.ArgumentParser(description='esptool.py v%s - ESP8266 ROM Bootloader Utility' % __version__, prog='esptool')

    parser.add_argument('--chip', '-c',
                        help='Target chip type',
                        type=lambda c: c.lower().replace('-', ''),  # support ESP32-S2, etc.
                        choices=['auto', 'esp8266', 'esp32', 'esp32s2', 'esp32s3beta2', 'esp32s3beta3', 'esp32c3'],
                        default=os.environ.get('ESPTOOL_CHIP', 'auto'))

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default=os.environ.get('ESPTOOL_PORT', None))

    parser.add_argument(
        '--baud', '-b',
        help='Serial port baud rate used when flashing/reading',
        type=arg_auto_int,
        default=os.environ.get('ESPTOOL_BAUD', ESPLoader.ESP_ROM_BAUD))

    parser.add_argument(
        '--before',
        help='What to do before connecting to the chip',
        choices=['default_reset', 'no_reset', 'no_reset_no_sync'],
        default=os.environ.get('ESPTOOL_BEFORE', 'default_reset'))

    parser.add_argument(
        '--after', '-a',
        help='What to do after esptool.py is finished',
        choices=['hard_reset', 'soft_reset', 'no_reset'],
        default=os.environ.get('ESPTOOL_AFTER', 'hard_reset'))

    parser.add_argument(
        '--no-stub',
        help="Disable launching the flasher stub, only talk to ROM bootloader. Some features will not be available.",
        action='store_true')

    parser.add_argument(
        '--trace', '-t',
        help="Enable trace-level output of esptool.py interactions.",
        action='store_true')

    parser.add_argument(
        '--override-vddsdio',
        help="Override ESP32 VDDSDIO internal voltage regulator (use with care)",
        choices=ESP32ROM.OVERRIDE_VDDSDIO_CHOICES,
        nargs='?')

    parser.add_argument(
        '--connect-attempts',
        help=('Number of attempts to connect, negative or 0 for infinite. '
              'Default: %d.' % DEFAULT_CONNECT_ATTEMPTS),
        type=int,
        default=os.environ.get('ESPTOOL_CONNECT_ATTEMPTS', DEFAULT_CONNECT_ATTEMPTS))

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run esptool {command} -h for additional help')

    def add_spi_connection_arg(parent):
        parent.add_argument('--spi-connection', '-sc', help='ESP32-only argument. Override default SPI Flash connection. '
                            'Value can be SPI, HSPI or a comma-separated list of 5 I/O numbers to use for SPI flash (CLK,Q,D,HD,CS).',
                            action=SpiConnectionAction)

    parser_load_ram = subparsers.add_parser(
        'load_ram',
        help='Download an image to RAM and execute')
    parser_load_ram.add_argument('filename', help='Firmware image')

    parser_dump_mem = subparsers.add_parser(
        'dump_mem',
        help='Dump arbitrary memory to disk')
    parser_dump_mem.add_argument('address', help='Base address', type=arg_auto_int)
    parser_dump_mem.add_argument('size', help='Size of region to dump', type=arg_auto_int)
    parser_dump_mem.add_argument('filename', help='Name of binary dump')

    parser_read_mem = subparsers.add_parser(
        'read_mem',
        help='Read arbitrary memory location')
    parser_read_mem.add_argument('address', help='Address to read', type=arg_auto_int)

    parser_write_mem = subparsers.add_parser(
        'write_mem',
        help='Read-modify-write to arbitrary memory location')
    parser_write_mem.add_argument('address', help='Address to write', type=arg_auto_int)
    parser_write_mem.add_argument('value', help='Value', type=arg_auto_int)
    parser_write_mem.add_argument('mask', help='Mask of bits to write', type=arg_auto_int, nargs='?', default='0xFFFFFFFF')

    def add_spi_flash_subparsers(parent, allow_keep, auto_detect):
        """ Add common parser arguments for SPI flash properties """
        extra_keep_args = ['keep'] if allow_keep else []

        if auto_detect and allow_keep:
            extra_fs_message = ", detect, or keep"
        elif auto_detect:
            extra_fs_message = ", or detect"
        elif allow_keep:
            extra_fs_message = ", or keep"
        else:
            extra_fs_message = ""

        parent.add_argument('--flash_freq', '-ff', help='SPI Flash frequency',
                            choices=extra_keep_args + ['40m', '26m', '20m', '80m'],
                            default=os.environ.get('ESPTOOL_FF', 'keep' if allow_keep else '40m'))
        parent.add_argument('--flash_mode', '-fm', help='SPI Flash mode',
                            choices=extra_keep_args + ['qio', 'qout', 'dio', 'dout'],
                            default=os.environ.get('ESPTOOL_FM', 'keep' if allow_keep else 'qio'))
        parent.add_argument('--flash_size', '-fs', help='SPI Flash size in MegaBytes (1MB, 2MB, 4MB, 8MB, 16M)'
                            ' plus ESP8266-only (256KB, 512KB, 2MB-c1, 4MB-c1)' + extra_fs_message,
                            action=FlashSizeAction, auto_detect=auto_detect,
                            default=os.environ.get('ESPTOOL_FS', 'keep' if allow_keep else '1MB'))
        add_spi_connection_arg(parent)

    parser_write_flash = subparsers.add_parser(
        'write_flash',
        help='Write a binary blob to flash')

    parser_write_flash.add_argument('addr_filename', metavar='<address> <filename>', help='Address followed by binary filename, separated by space',
                                    action=AddrFilenamePairAction)
    parser_write_flash.add_argument('--erase-all', '-e',
                                    help='Erase all regions of flash (not just write areas) before programming',
                                    action="store_true")

    add_spi_flash_subparsers(parser_write_flash, allow_keep=True, auto_detect=True)
    parser_write_flash.add_argument('--no-progress', '-p', help='Suppress progress output', action="store_true")
    parser_write_flash.add_argument('--verify', help='Verify just-written data on flash '
                                    '(mostly superfluous, data is read back during flashing)', action='store_true')
    parser_write_flash.add_argument('--encrypt', help='Apply flash encryption when writing data (required correct efuse settings)',
                                    action='store_true')
    # In order to not break backward compatibility, our list of encrypted files to flash is a new parameter
    parser_write_flash.add_argument('--encrypt-files', metavar='<address> <filename>',
                                    help='Files to be encrypted on the flash. Address followed by binary filename, separated by space.',
                                    action=AddrFilenamePairAction)
    parser_write_flash.add_argument('--ignore-flash-encryption-efuse-setting', help='Ignore flash encryption efuse settings ',
                                    action='store_true')

    compress_args = parser_write_flash.add_mutually_exclusive_group(required=False)
    compress_args.add_argument('--compress', '-z', help='Compress data in transfer (default unless --no-stub is specified)',
                               action="store_true", default=None)
    compress_args.add_argument('--no-compress', '-u', help='Disable data compression during transfer (default if --no-stub is specified)',
                               action="store_true")

    subparsers.add_parser(
        'run',
        help='Run application code in flash')

    parser_image_info = subparsers.add_parser(
        'image_info',
        help='Dump headers from an application image')
    parser_image_info.add_argument('filename', help='Image file to parse')

    parser_make_image = subparsers.add_parser(
        'make_image',
        help='Create an application image from binary files')
    parser_make_image.add_argument('output', help='Output image file')
    parser_make_image.add_argument('--segfile', '-f', action='append', help='Segment input file')
    parser_make_image.add_argument('--segaddr', '-a', action='append', help='Segment base address', type=arg_auto_int)
    parser_make_image.add_argument('--entrypoint', '-e', help='Address of entry point', type=arg_auto_int, default=0)

    parser_elf2image = subparsers.add_parser(
        'elf2image',
        help='Create an application image from ELF file')
    parser_elf2image.add_argument('input', help='Input ELF file')
    parser_elf2image.add_argument('--output', '-o', help='Output filename prefix (for version 1 image), or filename (for version 2 single image)', type=str)
    parser_elf2image.add_argument('--version', '-e', help='Output image version', choices=['1', '2'], default='1')
    parser_elf2image.add_argument('--min-rev', '-r', help='Minimum chip revision', choices=['0', '1', '2', '3'], default='0')
    parser_elf2image.add_argument('--secure-pad', action='store_true',
                                  help='Pad image so once signed it will end on a 64KB boundary. For Secure Boot v1 images only.')
    parser_elf2image.add_argument('--secure-pad-v2', action='store_true',
                                  help='Pad image to 64KB, so once signed its signature sector will start at the next 64K block. '
                                  'For Secure Boot v2 images only.')
    parser_elf2image.add_argument('--elf-sha256-offset', help='If set, insert SHA256 hash (32 bytes) of the input ELF file at specified offset in the binary.',
                                  type=arg_auto_int, default=None)
    parser_elf2image.add_argument('--use_segments', help='If set, ELF segments will be used instead of ELF sections to genereate the image.',
                                  action='store_true')

    add_spi_flash_subparsers(parser_elf2image, allow_keep=False, auto_detect=False)

    subparsers.add_parser(
        'read_mac',
        help='Read MAC address from OTP ROM')

    subparsers.add_parser(
        'chip_id',
        help='Read Chip ID from OTP ROM')

    parser_flash_id = subparsers.add_parser(
        'flash_id',
        help='Read SPI flash manufacturer and device ID')
    add_spi_connection_arg(parser_flash_id)

    parser_read_status = subparsers.add_parser(
        'read_flash_status',
        help='Read SPI flash status register')

    add_spi_connection_arg(parser_read_status)
    parser_read_status.add_argument('--bytes', help='Number of bytes to read (1-3)', type=int, choices=[1, 2, 3], default=2)

    parser_write_status = subparsers.add_parser(
        'write_flash_status',
        help='Write SPI flash status register')

    add_spi_connection_arg(parser_write_status)
    parser_write_status.add_argument('--non-volatile', help='Write non-volatile bits (use with caution)', action='store_true')
    parser_write_status.add_argument('--bytes', help='Number of status bytes to write (1-3)', type=int, choices=[1, 2, 3], default=2)
    parser_write_status.add_argument('value', help='New value', type=arg_auto_int)

    parser_read_flash = subparsers.add_parser(
        'read_flash',
        help='Read SPI flash content')
    add_spi_connection_arg(parser_read_flash)
    parser_read_flash.add_argument('address', help='Start address', type=arg_auto_int)
    parser_read_flash.add_argument('size', help='Size of region to dump', type=arg_auto_int)
    parser_read_flash.add_argument('filename', help='Name of binary dump')
    parser_read_flash.add_argument('--no-progress', '-p', help='Suppress progress output', action="store_true")

    parser_verify_flash = subparsers.add_parser(
        'verify_flash',
        help='Verify a binary blob against flash')
    parser_verify_flash.add_argument('addr_filename', help='Address and binary file to verify there, separated by space',
                                     action=AddrFilenamePairAction)
    parser_verify_flash.add_argument('--diff', '-d', help='Show differences',
                                     choices=['no', 'yes'], default='no')
    add_spi_flash_subparsers(parser_verify_flash, allow_keep=True, auto_detect=True)

    parser_erase_flash = subparsers.add_parser(
        'erase_flash',
        help='Perform Chip Erase on SPI flash')
    add_spi_connection_arg(parser_erase_flash)

    parser_erase_region = subparsers.add_parser(
        'erase_region',
        help='Erase a region of the flash')
    add_spi_connection_arg(parser_erase_region)
    parser_erase_region.add_argument('address', help='Start address (must be multiple of 4096)', type=arg_auto_int)
    parser_erase_region.add_argument('size', help='Size of region to erase (must be multiple of 4096)', type=arg_auto_int)

    parser_merge_bin = subparsers.add_parser(
        'merge_bin',
        help='Merge multiple raw binary files into a single file for later flashing')

    parser_merge_bin.add_argument('--output', '-o', help='Output filename', type=str, required=True)
    parser_merge_bin.add_argument('--format', '-f', help='Format of the output file', choices='raw', default='raw')  # for future expansion
    add_spi_flash_subparsers(parser_merge_bin, allow_keep=True, auto_detect=False)

    parser_merge_bin.add_argument('--target-offset', '-t', help='Target offset where the output file will be flashed',
                                  type=arg_auto_int, default=0)
    parser_merge_bin.add_argument('--fill-flash-size', help='If set, the final binary file will be padded with FF '
                                  'bytes up to this flash size.', action=FlashSizeAction)
    parser_merge_bin.add_argument('addr_filename', metavar='<address> <filename>',
                                  help='Address followed by binary filename, separated by space',
                                  action=AddrFilenamePairAction)

    subparsers.add_parser(
        'version', help='Print esptool version')

    subparsers.add_parser('get_security_info', help='Get some security-related data')

    # internal sanity check - every operation matches a module function of the same name
    for operation in subparsers.choices.keys():
        assert operation in globals(), "%s should be a module function" % operation

    argv = expand_file_arguments(argv or sys.argv[1:])

    args = parser.parse_args(argv)
    print('esptool.py v%s' % __version__)

    # operation function can take 1 arg (args), 2 args (esp, arg)
    # or be a member function of the ESPLoader class.

    if args.operation is None:
        parser.print_help()
        sys.exit(1)

    # Forbid the usage of both --encrypt, which means encrypt all the given files,
    # and --encrypt-files, which represents the list of files to encrypt.
    # The reason is that allowing both at the same time increases the chances of
    # having contradictory lists (e.g. one file not available in one of list).
    if args.operation == "write_flash" and args.encrypt and args.encrypt_files is not None:
        raise FatalError("Options --encrypt and --encrypt-files must not be specified at the same time.")

    operation_func = globals()[args.operation]

    if PYTHON2:
        # This function is depreciated in Python3
        operation_args = inspect.getargspec(operation_func).args
    else:
        operation_args = inspect.getfullargspec(operation_func).args

    if operation_args[0] == 'esp':  # operation function takes an ESPLoader connection object
        if args.before != "no_reset_no_sync":
            initial_baud = min(ESPLoader.ESP_ROM_BAUD, args.baud)  # don't sync faster than the default baud rate
        else:
            initial_baud = args.baud

        if args.port is None:
            ser_list = get_port_list()
            print("Found %d serial ports" % len(ser_list))
        else:
            ser_list = [args.port]
        esp = esp or get_default_connected_device(ser_list, port=args.port, connect_attempts=args.connect_attempts,
                                                  initial_baud=initial_baud, chip=args.chip, trace=args.trace,
                                                  before=args.before)
        if esp is None:
            raise FatalError("Could not connect to an Espressif device on any of the %d available serial ports." % len(ser_list))

        if esp.secure_download_mode:
            print("Chip is %s in Secure Download Mode" % esp.CHIP_NAME)
        else:
            print("Chip is %s" % (esp.get_chip_description()))
            print("Features: %s" % ", ".join(esp.get_chip_features()))
            print("Crystal is %dMHz" % esp.get_crystal_freq())
            read_mac(esp, args)

        if not args.no_stub:
            if esp.secure_download_mode:
                print("WARNING: Stub loader is not supported in Secure Download Mode, setting --no-stub")
                args.no_stub = True
            else:
                esp = esp.run_stub()

        if args.override_vddsdio:
            esp.override_vddsdio(args.override_vddsdio)

        if args.baud > initial_baud:
            try:
                esp.change_baud(args.baud)
            except NotImplementedInROMError:
                print("WARNING: ROM doesn't support changing baud rate. Keeping initial baud rate %d" % initial_baud)

        # override common SPI flash parameter stuff if configured to do so
        if hasattr(args, "spi_connection") and args.spi_connection is not None:
            if esp.CHIP_NAME != "ESP32":
                raise FatalError("Chip %s does not support --spi-connection option." % esp.CHIP_NAME)
            print("Configuring SPI flash mode...")
            esp.flash_spi_attach(args.spi_connection)
        elif args.no_stub:
            print("Enabling default SPI flash mode...")
            # ROM loader doesn't enable flash unless we explicitly do it
            esp.flash_spi_attach(0)

        if hasattr(args, "flash_size"):
            print("Configuring flash size...")
            detect_flash_size(esp, args)
            if args.flash_size != 'keep':  # TODO: should set this even with 'keep'
                esp.flash_set_parameters(flash_size_bytes(args.flash_size))

        try:
            operation_func(esp, args)
        finally:
            try:  # Clean up AddrFilenamePairAction files
                for address, argfile in args.addr_filename:
                    argfile.close()
            except AttributeError:
                pass

        # Handle post-operation behaviour (reset or other)
        if operation_func == load_ram:
            # the ESP is now running the loaded image, so let it run
            print('Exiting immediately.')
        elif args.after == 'hard_reset':
            print('Hard resetting via RTS pin...')
            esp.hard_reset()
        elif args.after == 'soft_reset':
            print('Soft resetting...')
            # flash_finish will trigger a soft reset
            esp.soft_reset(False)
        else:
            print('Staying in bootloader.')
            if esp.IS_STUB:
                esp.soft_reset(True)  # exit stub back to ROM loader

        if not external_esp:
            esp._port.close()

    else:
        operation_func(args)


def get_port_list():
    if list_ports is None:
        raise FatalError("Listing all serial ports is currently not available. Please try to specify the port when "
                         "running esptool.py or update the pyserial package to the latest version")
    return sorted(ports.device for ports in list_ports.comports())


def expand_file_arguments(argv):
    """ Any argument starting with "@" gets replaced with all values read from a text file.
    Text file arguments can be split by newline or by space.
    Values are added "as-is", as if they were specified in this order on the command line.
    """
    new_args = []
    expanded = False
    for arg in argv:
        if arg.startswith("@"):
            expanded = True
            with open(arg[1:], "r") as f:
                for line in f.readlines():
                    new_args += shlex.split(line)
        else:
            new_args.append(arg)
    if expanded:
        print("esptool.py %s" % (" ".join(new_args[1:])))
        return new_args
    return argv


class FlashSizeAction(argparse.Action):
    """ Custom flash size parser class to support backwards compatibility with megabit size arguments.

    (At next major relase, remove deprecated sizes and this can become a 'normal' choices= argument again.)
    """
    def __init__(self, option_strings, dest, nargs=1, auto_detect=False, **kwargs):
        super(FlashSizeAction, self).__init__(option_strings, dest, nargs, **kwargs)
        self._auto_detect = auto_detect

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            value = {
                '2m': '256KB',
                '4m': '512KB',
                '8m': '1MB',
                '16m': '2MB',
                '32m': '4MB',
                '16m-c1': '2MB-c1',
                '32m-c1': '4MB-c1',
            }[values[0]]
            print("WARNING: Flash size arguments in megabits like '%s' are deprecated." % (values[0]))
            print("Please use the equivalent size '%s'." % (value))
            print("Megabit arguments may be removed in a future release.")
        except KeyError:
            value = values[0]

        known_sizes = dict(ESP8266ROM.FLASH_SIZES)
        known_sizes.update(ESP32ROM.FLASH_SIZES)
        if self._auto_detect:
            known_sizes['detect'] = 'detect'
            known_sizes['keep'] = 'keep'
        if value not in known_sizes:
            raise argparse.ArgumentError(self, '%s is not a known flash size. Known sizes: %s' % (value, ", ".join(known_sizes.keys())))
        setattr(namespace, self.dest, value)


class SpiConnectionAction(argparse.Action):
    """ Custom action to parse 'spi connection' override. Values are SPI, HSPI, or a sequence of 5 pin numbers separated by commas.
    """
    def __call__(self, parser, namespace, value, option_string=None):
        if value.upper() == "SPI":
            value = 0
        elif value.upper() == "HSPI":
            value = 1
        elif "," in value:
            values = value.split(",")
            if len(values) != 5:
                raise argparse.ArgumentError(self, '%s is not a valid list of comma-separate pin numbers. Must be 5 numbers - CLK,Q,D,HD,CS.' % value)
            try:
                values = tuple(int(v, 0) for v in values)
            except ValueError:
                raise argparse.ArgumentError(self, '%s is not a valid argument. All pins must be numeric values' % values)
            if any([v for v in values if v > 33 or v < 0]):
                raise argparse.ArgumentError(self, 'Pin numbers must be in the range 0-33.')
            # encode the pin numbers as a 32-bit integer with packed 6-bit values, the same way ESP32 ROM takes them
            # TODO: make this less ESP32 ROM specific somehow...
            clk, q, d, hd, cs = values
            value = (hd << 24) | (cs << 18) | (d << 12) | (q << 6) | clk
        else:
            raise argparse.ArgumentError(self, '%s is not a valid spi-connection value. '
                                         'Values are SPI, HSPI, or a sequence of 5 pin numbers CLK,Q,D,HD,CS).' % value)
        setattr(namespace, self.dest, value)


class AddrFilenamePairAction(argparse.Action):
    """ Custom parser class for the address/filename pairs passed as arguments """
    def __init__(self, option_strings, dest, nargs='+', **kwargs):
        super(AddrFilenamePairAction, self).__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        # validate pair arguments
        pairs = []
        for i in range(0, len(values), 2):
            try:
                address = int(values[i], 0)
            except ValueError:
                raise argparse.ArgumentError(self, 'Address "%s" must be a number' % values[i])
            try:
                argfile = open(values[i + 1], 'rb')
            except IOError as e:
                raise argparse.ArgumentError(self, e)
            except IndexError:
                raise argparse.ArgumentError(self, 'Must be pairs of an address and the binary filename to write there')
            pairs.append((address, argfile))

        # Sort the addresses and check for overlapping
        end = 0
        for address, argfile in sorted(pairs, key=lambda x: x[0]):
            argfile.seek(0, 2)  # seek to end
            size = argfile.tell()
            argfile.seek(0)
            sector_start = address & ~(ESPLoader.FLASH_SECTOR_SIZE - 1)
            sector_end = ((address + size + ESPLoader.FLASH_SECTOR_SIZE - 1) & ~(ESPLoader.FLASH_SECTOR_SIZE - 1)) - 1
            if sector_start < end:
                message = 'Detected overlap at address: 0x%x for file: %s' % (address, argfile.name)
                raise argparse.ArgumentError(self, message)
            end = sector_end
        setattr(namespace, self.dest, pairs)


# Binary stub code (see flasher_stub dir for source & details)
ESP8266ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32S2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32S3BETA2ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
eNqVW3t31DYW/yqTCXkB3WPZM7aUQ5eE9AyhlDaBEFKa7iLLdmEP5YQwXQZK97Ov7kuS7cm2+8cEW9bj3qt7f/ch8fvOsl0td/Yn9c7lKtP+l8Hv1eVKueSFHvjFzu5crlx93/eJzeUh/LNxueqs/3W+QzaBFpgy\
998602ve9X9mE/9oZv7nl2pz31L63zxdDQbOaaBW/t+yN4knBab3M2hN1Ftoy5Z+uixhp552QIVvrXxXmGMG8wCxqjehoW6q8a2BhjP89Oos5dPTDCObATmeDL+2hqfs1vkxfcWe9q/07K8Lv7uTsAGT0VYAh0JO\
C1JywlVN82WOhBBXZQaRpDqRqxmQZ/LX9BBbUMLnn8Z8+Bm/+NYcWJlmsKewI2Ne4HdA9LZCrO/nt8PYSErbJFJzQ7LMgKE+VcM1Df+LugrjQN7O3hfBx556lr4fHMjTMazFY0BTeTaReg1Ealh8gnq3dblq2GyM\
56u1pM+p6prkOWirYVZ0KvE630tUreDhLPNeTwM6qyPP8AMVV36LnWEWuC0McvkFj/BUmjo1qvzRcPOTBXCTbKRGFhOR4nMFe7XgzrPIecvGbOFZc7sl5iNlaBt1MhTn84JVMCcocJZ9oQngi/ITtGoBg1JtS7X+\
XSpXc7kM0/Tb3/VHLYnoJiEU9d3Bl0Q4LMi++t1lkc0PluGJcEnN8aUk8WBv95isFVjRiXFGGPPTZRVBpLpxlB6Oujo7ijCAXf34Boie0zxgbiAJbQ7hj4J92zD0DdFCwcKMJboBt3CXV7YwtHxj35zyPnfD1Xsd\
+5oTO70sXk5PviEFbYE7v+d1xVSPwPh/Ca0txgSgFyv553qObCQa2xcNcWx6QvJdrDkFIaG4NkhI0LsZCss5JlHz1z5pxDIwH9l2zU1sJ0i1pi1TjISCdV0Xf9hhJt7DMKNe/16HJ4Kz4KammwzhQFYOum7nRLoA\
dm0ZTzXLEByIUA4maeHdo7zON9njMG4pRhPLZOvMg5wuJpNlSzEAooNfrmELqPUmQwfy401I16yeFdjsHeIJ5uxq/1Ijcvo5CqDoO1GVA/7CoN1Tm/oGtckXxEQQM06XjtTrNB6EtgAoEexukPLzadLSJjCohi4V\
cUir7v90fohKuLyekF6a4quwTxOSv8MFjuBl8/bu3mZUtFaCsNlBaTn2apC2i9lJwdBhQKr1Bajry2cnl5eHFE+RhLYksHrtdduWNCKbvb71C20phAjgAJrZ0PWvYEL/5Cp4y16AXvg/dfkrb2ZGGpkK34ys/epk\
ycqFCHHyBtj1a9cFCw7Myz/XbM6IS4ypaLVgIK6ECKbOJ1e+QzV56slln2XQ0vefExOkqycXhwmIJOEr6LszIPTcxu0DtUVb4j1HbwJeuinJHOBZ3LvGyABsRv0LaHlFsvCS0cA10FoAh1vRNgeQ+PtYPfUgxL5J\
Jghas/H4ELJotz+lVzfbO9uFDdyf7sE/uzOYyGU5T91HsisWncWQrB/UYtjllashNVyFJ1LILdgdICmJWBUa9ASoKibsBUcu5glaIxom6XktnlyxwuRx1wSlyPu1EPwlkVseDVeeBzG9xafJKJKoeT3LYrnJZdrs\
FiDi2APgBnfBER7GcEyLhibAavJj6ABMuUMJ6PM0G8EWtacx9oEszE5vF9k9Ueh878IctxJUfIWYhJol2z4fkjhhSJodBOKYIEAd20T3gPGkIrnDdwD79WFP0sctGASGHjGdhCdH0Esi7bUTNtxnjZoTY8TGfk56\
l6k4XoJHVU85qEXKefVudrP/jinzRfoCJP0bFOOAIgeIZbwgQXTUfPAR/yk3NogCgGaV3aTxbOjBeZ2mCchLRK4jt0+yQwiYMQQoSGTyiXhXAgNg0Ik7SiQRdkDFTHotWHTu9nCdMRdtO5zh2+kBItz5JuWC6C4r\
jguS0YB2VnyyWUNHkkqgZ6/jGNy8klQc7TIbMYgK79Ztqei5TfQciHDVTSolI9+mm/86fblKX1bpyzJ9OT5mBYHUAkOD2cHZMVvfhhWEvAt2qwA2dPYjMFeL2J4yVmRPuySDGBH+XgDwIYflWKe5z3wnkb1bI/iI\
ce8JeDtZS38mKApBTfkV+uwPDBZqGzpfLXtKWkXlQfW0l0tRV1RRBmTcwTyxLEEeReNvVFPjXkZvrnMMUf6gN5NEaugbm8gM8KAtqZlFrPfGd51GRYjPVyDACZMDjkVyIYyNWD2FT/ZrUG0r2a/V2ZD0z9PPz0EO\
c0JjpAtlcL1NlCn2c1Qeu/qNNbSqCMsBI2RXgu/AAH3xllh2TXSzyCYq+17cXTeS57knAhhrKdI2jBuImuVboqmuacckdgS1A2koiOnKhxET3DzVGWHkMzmaUKdQ9ceFINAXggBTUWzpMlDcTJNEKtHhjyQ109Ku\
GdacmvU5BRQzH3LYRqnBYN2uQ5Y26gtGfHWwRtxL/WcAgUWnH44PH0GRU+qtWOpU1QGlizqDp5jVvtIHHE71cr9Bojhqm7Ey9JzUwbhjnHTNR6yQiXfGF7+FO8mMs6SA3GV9EhMGdTJDnZbvOv0EwU0Txr3dZ/jD\
4qfClyvKpLEZ4J6bVyGvIQr55Zi+vqYdxq8QBXUUwVxeklvFdqgKcPvdM3TDJyHUAV34iWDXU6q4CN7YUIF9N8Vk+UE0L0RFN1SADck0FKUDAclwzgc1/H08rXK2lnnMIqnIAiCpJlsStm/J98OfwBg38C9YFDbe\
vhXi00cEjnUwZk8IoBMYMOoW/l6aiKHNyOYD/D/l5Ev1Cv2F1/uTaQyJ9yQC/m29y2jKNcJx+egAIadYCaJ5MD5XgKtW8Ac7S10HEgMoB+iCueFo062JvkH6NUehjbrHSyaNdfLchlyTdpqntWuorw1vLSa87e1v\
wA8Xd2LVJDkuwdLLhx63qyT/LXpynMHhikJ3V7GyuF1sA2jKTy+Xe6fbnLiDX3FSNC1om1HFkEqZoiCPm7Gz15jDYammmHRH8KzBshOCC3O66IOLcpuwNJdysngcAcUbUlUC+XYuIP9XlmdEZv2LFeeKEFXl/VAM\
J8+i/4F2iDJt0o59cMKFVGpiWhFFSiU89CqaCYM6GPsvXZnvu9cSHFHMg9pUriYd94fAGQRP7YBiuhMlBr+Ioiu34aE75uqTQavvLuLMDjPhxTQWm8yALljHtoEuXGcVPzmcckHuJoPAkAb6lrqLs9a9WRexvoju\
0cguD9bOyhdh4dsd57z5og1FtaXQ5KRu+DOnpT3JPmbgL2PEqxyt21/u16BuvWa2dUmD6niKgYlfPpTYw0RcaYUSy8FgLPpW0qikUXE6NEhKQ8diyFedlBwyQup+h3/ADCySlnuhZjqTlBfn50cSIl2vC2efMf/l\
31PCtrlVcISN3+WUjO7oCovfk3isU8/OuXTdbtFZa9edfybX4BLBEm5jP+8YrTt8wfZIAfu7UelU0xyjfLVgHALJdRnX3hRoayb7qf65JnIqY8yJMW3TD3+cwGYpZ4Incm51/iOlli45HzBqT1iBPvMXZA5gMMSN\
S0qSNi1mKwDGtZzNZOoHcpYEyqG+lrfnjMSBzZP1bBobxd+4BK0UZm4VpFLz/fki0XpFUk/3xnAZf93ekJn1mQgbELaEJVYMCwGH68luE7Jdm+5ORfGXw4/vOZ4LGC46y3ir28Q+cLt4Tu1Yw6HWC+mWKxumlzan\
4zJwjZWDHSLd0lPe0oEFHck+pSXxzGfOYJIUTNuw37xaoC2PAQzV7mn22eTpJGEprwQWYdh/+OhRv0D72iHfZFx0mGCmltfVxeJzAgMamfqbfsibjG50AB60ngRv5W9yclDJoiwCsIdnxARVrFtyjUbiFgxYG8rA\
WrXn0Erv/LjJBc88kZrmTC/EuqCajQB9HjUjEIlnBY/4JFdf4Co7ORW4O7lm4BJodez6MdUr5EhWKoHgfvWgCIBHdxUy/I6KJlBrB/aoYJtVe1TSNeL35/LAh9tUwMeHiXwqRRclSkHoLML3igMYRH0fwARWhA/F\
fBTEhy7PJJ7uEqGhbhXrhHbMqSAKX77oczxER8zT+RGP08+A4CdpkAYDE2sCXZPYkBzjIxn7C8TTH+Es/AXMDcUgPOdDncXKUTZGPprzZxB4VGGY9sEggcR+20ey6v1wuWcnnkwETRouUrIvy7jerbPZ0AigKIGl\
gzY7O6Qg1FRfwxxfCP7Tgk1SOMJDNEPbBB64UUxHPqYDrzAoEjz203vkMwFOm3A0gC2AVH7cdXJI0OIrhrQYuqYnETDMpicKHq2uQYELUleHYcuLghYHgZDZdkcRnky1Dh2yxa3eFkRIc+UGayKEhcCsga3XuCdY\
tSvgGyeKeFhSxJNy3JQmXpKpbUwowfbgSkVWBwunmD7LWYxgCQ2jClqFWN8wNHLlORMzP+X0vU2+GhbIHIdV975jYapZKgKmqiMvUmt2beJYrcRobx7Tlhg8n0WCOy78NWzFEEhk4INBDuD3oAgLaTgojeWoB8/G\
a8KuTC8+DUo1uBEdHwFVME7Y0pwdsaVGc+d8mny44rCF1dOi0e2F7XknIgw35RDuHXkeTKe6E7nMpLNYwdKS9eegGO78e6ilDXKkLiSXhyAFNYsa+DtmGy6J0BE2t4uYmmD5gx266gSjdvlUJ3REH1ZJcs8KlXbJ\
yq9j5OVYe0enRbmQ+kPSOJPGDwtKldKh5IgqrvrB7rYXCH+Gak1aKontoDYCW4kWpOimGTKZpM/iVbMlJqbBlcCDZ3XCTkTL+Wx+QnbqGBa1GcOR5TsQLZ+EEb1j6AyWyQw2FBBQOX2HT2xixOTNn4NsTEvqeRxd\
hwy+l75TuQQdZ11PqBtKlol0Fe2gBSuVopfFXfurJYHVkLVTiLKbFF4ghPMC5WsM0AxmiKfrc76CVrD3dnKpQcWDe6e2OCAXmLf5FicAXC/GZ73FUYYhDLDzbHzNkYZiDF2IQFgIWr0Zb5Mqv4WHazlu//QcjoXm\
+x8/wT+rOcjFZQZPANya0N0UcZN0IlMz2Cf0N0pOweHqQyArJyTtBKDgLFYF1FLfwQLv+Xje8bVc2DXzHoj+CPR9sqttwaiP8Tg8wxMetiDLvtbO+UasRWm//yZBThWR0Cr+UDdBZamy5CiWw2dNFUu61fD9WLwO\
s6Bab8Ny78UWSdh1TR6iNtsSKHKDkACZm9V8XgDdAdqtY2fvJhx9F9wAMptfycTnNIztjk6wsxiLgQ+EUg66ArlPmiWXNFhsFJq0T7hkGAIQ+PqJPTWIp2tW7D+sxNOd4ge+JtqUe3yIg0eBJRVjreNDZCxeNeJ4\
KvN8kUCju0epC+pjyZqI5sY1jnDE74LrMheLV6Kdp3zZIHw1fv6f5atHnnO6BwtXa+OZ3p012CfZEHrezTUpudod2cnzsFDFvrugO79xqc0/h1lVj/vgs2TKJWvg4Fqj3CpvYsBP0ckuW1LFgQ5ssMvjdRZEqirG\
DhmezhVfkhv1HefGCu19e8o2vS5/T69SZHA7jNYFItxUJu7kQkQ1OiXHosROPNYlKnGgXEVLqxzhJoZcIBcuy97QaaSKxLZzd4L/b+GfH5b2Gv73gsqqqqhMVuX+S/tuef1JGnVmZplvbOzSDv6bg7P3d/hLOpGP\
FM3c5H/8F+n4R7s=\
""")))
ESP32S3BETA3ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32C3ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))


def _main():
    try:
        main()
    except FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)


if __name__ == '__main__':
    _main()
