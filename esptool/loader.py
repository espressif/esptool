# SPDX-FileCopyrightText: 2014-2023 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import base64
import hashlib
import itertools
import json
import os
import re
import string
import struct
import sys
import time

from .config import load_config_file
from .reset import (
    ClassicReset,
    CustomReset,
    DEFAULT_RESET_DELAY,
    HardReset,
    USBJTAGSerialReset,
    UnixTightReset,
)
from .util import FatalError, NotImplementedInROMError, UnsupportedCommandError
from .util import byte, hexify, mask_to_shift, pad_to, strip_chip_name

try:
    import serial
except ImportError:
    print(
        "Pyserial is not installed for %s. "
        "Check the README for installation instructions." % (sys.executable)
    )
    raise

# check 'serial' is 'pyserial' and not 'serial'
# ref. https://github.com/espressif/esptool/issues/269
try:
    if "serialization" in serial.__doc__ and "deserialization" in serial.__doc__:
        raise ImportError(
            "esptool.py depends on pyserial, but there is a conflict with a currently "
            "installed package named 'serial'.\n"
            "You may work around this by 'pip uninstall serial; pip install pyserial' "
            "but this may break other installed Python software "
            "that depends on 'serial'.\n"
            "There is no good fix for this right now, "
            "apart from configuring virtualenvs. "
            "See https://github.com/espressif/esptool/issues/269#issuecomment-385298196"
            " for discussion of the underlying issue(s)."
        )
except TypeError:
    pass  # __doc__ returns None for pyserial

try:
    import serial.tools.list_ports as list_ports
except ImportError:
    print(
        "The installed version (%s) of pyserial appears to be too old for esptool.py "
        "(Python interpreter %s). Check the README for installation instructions."
        % (sys.VERSION, sys.executable)
    )
    raise
except Exception:
    if sys.platform == "darwin":
        # swallow the exception, this is a known issue in pyserial+macOS Big Sur preview
        # ref https://github.com/espressif/esptool/issues/540
        list_ports = None
    else:
        raise


cfg, _ = load_config_file()
cfg = cfg["esptool"]

# Timeout for most flash operations
DEFAULT_TIMEOUT = cfg.getfloat("timeout", 3)
# Timeout for full chip erase
CHIP_ERASE_TIMEOUT = cfg.getfloat("chip_erase_timeout", 120)
# Longest any command can run
MAX_TIMEOUT = cfg.getfloat("max_timeout", CHIP_ERASE_TIMEOUT * 2)
# Timeout for syncing with bootloader
SYNC_TIMEOUT = cfg.getfloat("sync_timeout", 0.1)
# Timeout (per megabyte) for calculating md5sum
MD5_TIMEOUT_PER_MB = cfg.getfloat("md5_timeout_per_mb", 8)
# Timeout (per megabyte) for erasing a region
ERASE_REGION_TIMEOUT_PER_MB = cfg.getfloat("erase_region_timeout_per_mb", 30)
# Timeout (per megabyte) for erasing and writing data
ERASE_WRITE_TIMEOUT_PER_MB = cfg.getfloat("erase_write_timeout_per_mb", 40)
# Short timeout for ESP_MEM_END, as it may never respond
MEM_END_ROM_TIMEOUT = cfg.getfloat("mem_end_rom_timeout", 0.2)
# Timeout for serial port write
DEFAULT_SERIAL_WRITE_TIMEOUT = cfg.getfloat("serial_write_timeout", 10)
# Default number of times to try connection
DEFAULT_CONNECT_ATTEMPTS = cfg.getint("connect_attempts", 7)
# Number of times to try writing a data block
WRITE_BLOCK_ATTEMPTS = cfg.getint("write_block_attempts", 3)

STUBS_DIR = os.path.join(os.path.dirname(__file__), "targets", "stub_flasher")


def get_stub_json_path(chip_name):
    chip_name = strip_chip_name(chip_name)
    chip_name = chip_name.replace("esp", "")
    return os.path.join(STUBS_DIR, f"stub_flasher_{chip_name}.json")


def timeout_per_mb(seconds_per_mb, size_bytes):
    """Scales timeouts which are size-specific"""
    result = seconds_per_mb * (size_bytes / 1e6)
    if result < DEFAULT_TIMEOUT:
        return DEFAULT_TIMEOUT
    return result


def check_supported_function(func, check_func):
    """
    Decorator implementation that wraps a check around an ESPLoader
    bootloader function to check if it's supported.

    This is used to capture the multidimensional differences in
    functionality between the ESP8266 & ESP32 (and later chips) ROM loaders, and the
    software stub that runs on these. Not possible to do this cleanly
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
    """Attribute for a function only supported in the software stub loader"""
    return check_supported_function(func, lambda o: o.IS_STUB)


def stub_and_esp32_function_only(func):
    """Attribute for a function only supported by stubs or ESP32 and later chips ROM"""
    return check_supported_function(
        func, lambda o: o.IS_STUB or o.CHIP_NAME not in ["ESP8266"]
    )


def esp32s3_or_newer_function_only(func):
    """Attribute for a function only supported by ESP32S3 and later chips ROM"""
    return check_supported_function(
        func, lambda o: o.CHIP_NAME not in ["ESP8266", "ESP32", "ESP32-S2"]
    )


class StubFlasher:
    def __init__(self, json_path):
        with open(json_path) as json_file:
            stub = json.load(json_file)

        self.text = base64.b64decode(stub["text"])
        self.text_start = stub["text_start"]
        self.entry = stub["entry"]

        try:
            self.data = base64.b64decode(stub["data"])
            self.data_start = stub["data_start"]
        except KeyError:
            self.data = None
            self.data_start = None

        self.bss_start = stub.get("bss_start")


class ESPLoader(object):
    """Base class providing access to ESP ROM & software stub bootloaders.
    Subclasses provide ESP8266 & ESP32 Family specific functionality.

    Don't instantiate this base class directly, either instantiate a subclass or
    call cmds.detect_chip() which will interrogate the chip and return the
    appropriate subclass instance.

    """

    CHIP_NAME = "Espressif device"
    IS_STUB = False

    DEFAULT_PORT = "/dev/ttyUSB0"

    USES_RFC2217 = False

    # Commands supported by ESP8266 ROM bootloader
    ESP_FLASH_BEGIN = 0x02
    ESP_FLASH_DATA = 0x03
    ESP_FLASH_END = 0x04
    ESP_MEM_BEGIN = 0x05
    ESP_MEM_END = 0x06
    ESP_MEM_DATA = 0x07
    ESP_SYNC = 0x08
    ESP_WRITE_REG = 0x09
    ESP_READ_REG = 0x0A

    # Some comands supported by ESP32 and later chips ROM bootloader (or -8266 w/ stub)
    ESP_SPI_SET_PARAMS = 0x0B
    ESP_SPI_ATTACH = 0x0D
    ESP_READ_FLASH_SLOW = 0x0E  # ROM only, much slower than the stub flash read
    ESP_CHANGE_BAUDRATE = 0x0F
    ESP_FLASH_DEFL_BEGIN = 0x10
    ESP_FLASH_DEFL_DATA = 0x11
    ESP_FLASH_DEFL_END = 0x12
    ESP_SPI_FLASH_MD5 = 0x13

    # Commands supported by ESP32-S2 and later chips ROM bootloader only
    ESP_GET_SECURITY_INFO = 0x14

    # Some commands supported by stub only
    ESP_ERASE_FLASH = 0xD0
    ESP_ERASE_REGION = 0xD1
    ESP_READ_FLASH = 0xD2
    ESP_RUN_USER_CODE = 0xD3

    # Flash encryption encrypted data command
    ESP_FLASH_ENCRYPT_DATA = 0xD4

    # Response code(s) sent by ROM
    ROM_INVALID_RECV_MSG = 0x05  # response if an invalid message is received

    # Maximum block sized for RAM and Flash writes, respectively.
    ESP_RAM_BLOCK = 0x1800

    FLASH_WRITE_SIZE = 0x400

    # Default baudrate. The ROM auto-bauds, so we can use more or less whatever we want.
    ESP_ROM_BAUD = 115200

    # First byte of the application image
    ESP_IMAGE_MAGIC = 0xE9

    # Initial state for the checksum routine
    ESP_CHECKSUM_MAGIC = 0xEF

    # Flash sector size, minimum unit of erase.
    FLASH_SECTOR_SIZE = 0x1000

    UART_DATE_REG_ADDR = 0x60000078

    # This ROM address has a different value on each chip model
    CHIP_DETECT_MAGIC_REG_ADDR = 0x40001000

    UART_CLKDIV_MASK = 0xFFFFF

    # Memory addresses
    IROM_MAP_START = 0x40200000
    IROM_MAP_END = 0x40300000

    # The number of bytes in the UART response that signify command status
    STATUS_BYTES_LENGTH = 2

    # Bootloader flashing offset
    BOOTLOADER_FLASH_OFFSET = 0x0

    # ROM supports an encrypted flashing mode
    SUPPORTS_ENCRYPTED_FLASH = False

    # Response to ESP_SYNC might indicate that flasher stub is running
    # instead of the ROM bootloader
    sync_stub_detected = False

    # Device PIDs
    USB_JTAG_SERIAL_PID = 0x1001

    # Chip IDs that are no longer supported by esptool
    UNSUPPORTED_CHIPS = {6: "ESP32-S3(beta 3)"}

    def __init__(self, port=DEFAULT_PORT, baud=ESP_ROM_BAUD, trace_enabled=False):
        """Base constructor for ESPLoader bootloader interaction

        Don't call this constructor, either instantiate a specific
        ROM class directly, or use cmds.detect_chip().

        This base class has all of the instance methods for bootloader
        functionality supported across various chips & stub
        loaders. Subclasses replace the functions they don't support
        with ones which throw NotImplementedInROMError().

        """
        # True if esptool detects the ROM is in Secure Download Mode
        self.secure_download_mode = False
        # True if esptool detects conditions which require the stub to be disabled
        self.stub_is_disabled = False

        # Device-and-runtime-specific cache
        self.cache = {
            "flash_id": None,
            "chip_id": None,
            "uart_no": None,
            "usb_pid": None,
        }

        if isinstance(port, str):
            try:
                self._port = serial.serial_for_url(port)
            except serial.serialutil.SerialException as e:
                port_issues = [
                    [  # does not exist error
                        re.compile(r"Errno 2|FileNotFoundError", re.IGNORECASE),
                        "Check if the port is correct and ESP connected",
                    ],
                    [  # busy port error
                        re.compile(r"Access is denied", re.IGNORECASE),
                        "Check if the port is not used by another task",
                    ],
                ]
                if sys.platform.startswith("linux"):
                    port_issues.append(
                        [  # permission denied error
                            re.compile(r"Permission denied", re.IGNORECASE),
                            (
                                "Try to add user into dialout group: "
                                "sudo usermod -a -G dialout $USER"
                            ),
                        ],
                    )

                hint_msg = ""
                for port_issue in port_issues:
                    if port_issue[0].search(str(e)):
                        hint_msg = f"\nHint: {port_issue[1]}\n"
                        break

                raise FatalError(
                    f"Could not open {port}, the port is busy or doesn't exist."
                    f"\n({e})\n"
                    f"{hint_msg}"
                )
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
            raise FatalError(
                "Failed to set baud rate %d. The driver may not support this rate."
                % baud
            )

    def read(self):
        """Read a SLIP packet from the serial port"""
        return next(self._slip_reader)

    def write(self, packet):
        """Write bytes to the serial port while performing SLIP escaping"""
        buf = (
            b"\xc0"
            + (packet.replace(b"\xdb", b"\xdb\xdd").replace(b"\xc0", b"\xdb\xdc"))
            + b"\xc0"
        )
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

    @staticmethod
    def checksum(data, state=ESP_CHECKSUM_MAGIC):
        """Calculate checksum of a blob, as it is defined by the ROM"""
        for b in data:
            state ^= b

        return state

    def command(
        self,
        op=None,
        data=b"",
        chk=0,
        wait_response=True,
        timeout=DEFAULT_TIMEOUT,
    ):
        """Send a request and read the response"""
        saved_timeout = self._port.timeout
        new_timeout = min(timeout, MAX_TIMEOUT)
        if new_timeout != saved_timeout:
            self._port.timeout = new_timeout

        try:
            if op is not None:
                self.trace(
                    "command op=0x%02x data len=%s wait_response=%d "
                    "timeout=%.3f data=%s",
                    op,
                    len(data),
                    1 if wait_response else 0,
                    timeout,
                    HexFormatter(data),
                )
                pkt = struct.pack(b"<BBHI", 0x00, op, len(data), chk) + data
                self.write(pkt)

            if not wait_response:
                return

            # tries to get a response until that response has the
            # same operation as the request or a retries limit has
            # exceeded. This is needed for some esp8266s that
            # reply with more sync responses than expected.
            for retry in range(100):
                p = self.read()
                if len(p) < 8:
                    continue
                (resp, op_ret, len_ret, val) = struct.unpack("<BBHI", p[:8])
                if resp != 1:
                    continue
                data = p[8:]

                if op is None or op_ret == op:
                    return val, data
                if byte(data, 0) != 0 and byte(data, 1) == self.ROM_INVALID_RECV_MSG:
                    # Unsupported read_reg can result in
                    # more than one error response for some reason
                    self.flush_input()
                    raise UnsupportedCommandError(self, op)

        finally:
            if new_timeout != saved_timeout:
                self._port.timeout = saved_timeout

        raise FatalError("Response doesn't match request")

    def check_command(
        self, op_description, op=None, data=b"", chk=0, timeout=DEFAULT_TIMEOUT
    ):
        """
        Execute a command with 'command', check the result code and throw an appropriate
        FatalError if it fails.

        Returns the "result" of a successful command.
        """
        val, data = self.command(op, data, chk, timeout=timeout)

        # things are a bit weird here, bear with us

        # the status bytes are the last 2/4 bytes in the data (depending on chip)
        if len(data) < self.STATUS_BYTES_LENGTH:
            raise FatalError(
                "Failed to %s. Only got %d byte status response."
                % (op_description, len(data))
            )
        status_bytes = data[-self.STATUS_BYTES_LENGTH :]
        # only care if the first one is non-zero. If it is, the second byte is a reason.
        if byte(status_bytes, 0) != 0:
            raise FatalError.WithResult("Failed to %s" % op_description, status_bytes)

        # if we had more data than just the status bytes, return it as the result
        # (this is used by the md5sum command, maybe other commands?)
        if len(data) > self.STATUS_BYTES_LENGTH:
            return data[: -self.STATUS_BYTES_LENGTH]
        else:
            # otherwise, just return the 'val' field which comes from the reply header
            # (this is used by read_reg)
            return val

    def flush_input(self):
        self._port.flushInput()
        self._slip_reader = slip_reader(self._port, self.trace)

    def sync(self):
        val, _ = self.command(
            self.ESP_SYNC, b"\x07\x07\x12\x20" + 32 * b"\x55", timeout=SYNC_TIMEOUT
        )

        # ROM bootloaders send some non-zero "val" response. The flasher stub sends 0.
        # If we receive 0 then it probably indicates that the chip wasn't or couldn't be
        # reseted properly and esptool is talking to the flasher stub.
        self.sync_stub_detected = val == 0

        for _ in range(7):
            val, _ = self.command()
            self.sync_stub_detected &= val == 0

    def _get_pid(self):
        if self.cache["usb_pid"] is not None:
            return self.cache["usb_pid"]

        if list_ports is None:
            print(
                "\nListing all serial ports is currently not available. "
                "Can't get device PID."
            )
            return
        active_port = self._port.port

        # Pyserial only identifies regular ports, URL handlers are not supported
        if not active_port.lower().startswith(("com", "/dev/")):
            print(
                "\nDevice PID identification is only supported on "
                "COM and /dev/ serial ports."
            )
            return
        # Return the real path if the active port is a symlink
        if active_port.startswith("/dev/") and os.path.islink(active_port):
            active_port = os.path.realpath(active_port)

        active_ports = [active_port]

        # The "cu" (call-up) device has to be used for outgoing communication on MacOS
        if sys.platform == "darwin" and "tty" in active_port:
            active_ports.append(active_port.replace("tty", "cu"))
        ports = list_ports.comports()
        for p in ports:
            if p.device in active_ports:
                self.cache["usb_pid"] = p.pid
                return p.pid
        print(
            f"\nFailed to get PID of a device on {active_port}, "
            "using standard reset sequence."
        )

    def _connect_attempt(self, reset_strategy, mode="default_reset"):
        """A single connection attempt"""
        last_error = None
        boot_log_detected = False
        download_mode = False

        # If we're doing no_sync, we're likely communicating as a pass through
        # with an intermediate device to the ESP32
        if mode == "no_reset_no_sync":
            return last_error

        if mode != "no_reset":
            if not self.USES_RFC2217:  # Might block on rfc2217 ports
                # Empty serial buffer to isolate boot log
                self._port.reset_input_buffer()

            reset_strategy()  # Reset the chip to bootloader (download mode)

            # Detect the ROM boot log and check actual boot mode (ESP32 and later only)
            waiting = self._port.inWaiting()
            read_bytes = self._port.read(waiting)
            data = re.search(
                b"boot:(0x[0-9a-fA-F]+)(.*waiting for download)?", read_bytes, re.DOTALL
            )
            if data is not None:
                boot_log_detected = True
                boot_mode = data.group(1)
                download_mode = data.group(2) is not None

        for _ in range(5):
            try:
                self.flush_input()
                self._port.flushOutput()
                self.sync()
                return None
            except FatalError as e:
                print(".", end="")
                sys.stdout.flush()
                time.sleep(0.05)
                last_error = e

        if boot_log_detected:
            last_error = FatalError(
                "Wrong boot mode detected ({})! "
                "The chip needs to be in download mode.".format(
                    boot_mode.decode("utf-8")
                )
            )
            if download_mode:
                last_error = FatalError(
                    "Download mode successfully detected, but getting no sync reply: "
                    "The serial TX path seems to be down."
                )
        return last_error

    def get_memory_region(self, name):
        """
        Returns a tuple of (start, end) for the memory map entry with the given name,
        or None if it doesn't exist
        """
        try:
            return [(start, end) for (start, end, n) in self.MEMORY_MAP if n == name][0]
        except IndexError:
            return None

    def _construct_reset_strategy_sequence(self, mode):
        """
        Constructs a sequence of reset strategies based on the OS,
        used ESP chip, external settings, and environment variables.
        Returns a tuple of one or more reset strategies to be tried sequentially.
        """
        cfg_custom_reset_sequence = cfg.get("custom_reset_sequence")
        if cfg_custom_reset_sequence is not None:
            return (CustomReset(self._port, cfg_custom_reset_sequence),)

        cfg_reset_delay = cfg.getfloat("reset_delay")
        if cfg_reset_delay is not None:
            delay = extra_delay = cfg_reset_delay
        else:
            delay = DEFAULT_RESET_DELAY
            extra_delay = DEFAULT_RESET_DELAY + 0.5

        # This FPGA delay is for Espressif internal use
        if (
            self.CHIP_NAME == "ESP32"
            and os.environ.get("ESPTOOL_ENV_FPGA", "").strip() == "1"
        ):
            delay = extra_delay = 7

        # USB-JTAG/Serial mode
        if mode == "usb_reset" or self._get_pid() == self.USB_JTAG_SERIAL_PID:
            return (USBJTAGSerialReset(self._port),)

        # USB-to-Serial bridge
        if os.name != "nt" and not self._port.name.startswith("rfc2217:"):
            return (
                UnixTightReset(self._port, delay),
                UnixTightReset(self._port, extra_delay),
                ClassicReset(self._port, delay),
                ClassicReset(self._port, extra_delay),
            )

        return (
            ClassicReset(self._port, delay),
            ClassicReset(self._port, extra_delay),
        )

    def connect(
        self,
        mode="default_reset",
        attempts=DEFAULT_CONNECT_ATTEMPTS,
        detecting=False,
        warnings=True,
    ):
        """Try connecting repeatedly until successful, or giving up"""
        if warnings and mode in ["no_reset", "no_reset_no_sync"]:
            print(
                'WARNING: Pre-connection option "{}" was selected.'.format(mode),
                "Connection may fail if the chip is not in bootloader "
                "or flasher stub mode.",
            )
        print("Connecting...", end="")
        sys.stdout.flush()
        last_error = None

        reset_sequence = self._construct_reset_strategy_sequence(mode)
        try:
            for _, reset_strategy in zip(
                range(attempts) if attempts > 0 else itertools.count(),
                itertools.cycle(reset_sequence),
            ):
                last_error = self._connect_attempt(reset_strategy, mode)
                if last_error is None:
                    break
        finally:
            print("")  # end 'Connecting...' line

        if last_error is not None:
            additional_msg = ""
            if self.CHIP_NAME == "ESP32-C2" and self._port.baudrate < 115200:
                additional_msg = (
                    "\nNote: Please set a higher baud rate (--baud)"
                    " if ESP32-C2 doesn't connect"
                    " (at least 115200 Bd is recommended)."
                )

            raise FatalError(
                "Failed to connect to {}: {}"
                f"{additional_msg}"
                "\nFor troubleshooting steps visit: "
                "https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html".format(  # noqa E501
                    self.CHIP_NAME, last_error
                )
            )

        if not detecting:
            try:
                from .targets import ROM_LIST

                # check the date code registers match what we expect to see
                chip_magic_value = self.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR)
                if chip_magic_value not in self.CHIP_DETECT_MAGIC_VALUE:
                    actually = None
                    for cls in ROM_LIST:
                        if chip_magic_value in cls.CHIP_DETECT_MAGIC_VALUE:
                            actually = cls
                            break
                    if warnings and actually is None:
                        print(
                            "WARNING: This chip doesn't appear to be a %s "
                            "(chip magic value 0x%08x). "
                            "Probably it is unsupported by this version of esptool."
                            % (self.CHIP_NAME, chip_magic_value)
                        )
                    else:
                        raise FatalError(
                            "This chip is %s not %s. Wrong --chip argument?"
                            % (actually.CHIP_NAME, self.CHIP_NAME)
                        )
            except UnsupportedCommandError:
                self.secure_download_mode = True

            try:
                self.check_chip_id()
            except UnsupportedCommandError:
                # Fix for ROM not responding in SDM, reconnect and try again
                if self.secure_download_mode:
                    self._connect_attempt(mode, reset_sequence[0])
                    self.check_chip_id()
                else:
                    raise
            self._post_connect()

    def _post_connect(self):
        """
        Additional initialization hook, may be overridden by the chip-specific class.
        Gets called after connect, and after auto-detection.
        """
        pass

    def read_reg(self, addr, timeout=DEFAULT_TIMEOUT):
        """Read memory address in target"""
        # we don't call check_command here because read_reg() function is called
        # when detecting chip type, and the way we check for success
        # (STATUS_BYTES_LENGTH) is different for different chip types (!)
        val, data = self.command(
            self.ESP_READ_REG, struct.pack("<I", addr), timeout=timeout
        )
        if byte(data, 0) != 0:
            raise FatalError.WithResult(
                "Failed to read register address %08x" % addr, data
            )
        return val

    def write_reg(self, addr, value, mask=0xFFFFFFFF, delay_us=0, delay_after_us=0):
        """Write to memory address in target"""
        command = struct.pack("<IIII", addr, value, mask, delay_us)
        if delay_after_us > 0:
            # add a dummy write to a date register as an excuse to have a delay
            command += struct.pack(
                "<IIII", self.UART_DATE_REG_ADDR, 0, 0, delay_after_us
            )

        return self.check_command("write target memory", self.ESP_WRITE_REG, command)

    def update_reg(self, addr, mask, new_val):
        """
        Update register at 'addr', replace the bits masked out by 'mask'
        with new_val. new_val is shifted left to match the LSB of 'mask'

        Returns just-written value of register.
        """
        shift = mask_to_shift(mask)
        val = self.read_reg(addr)
        val &= ~mask
        val |= (new_val << shift) & mask
        self.write_reg(addr, val)

        return val

    def mem_begin(self, size, blocks, blocksize, offset):
        """Start downloading an application image to RAM"""
        # check we're not going to overwrite a running stub with this data
        if self.IS_STUB:
            stub = StubFlasher(get_stub_json_path(self.CHIP_NAME))
            load_start = offset
            load_end = offset + size
            for stub_start, stub_end in [
                (stub.bss_start, stub.data_start + len(stub.data)),  # DRAM = bss+data
                (stub.text_start, stub.text_start + len(stub.text)),  # IRAM
            ]:
                if load_start < stub_end and load_end > stub_start:
                    raise FatalError(
                        "Software loader is resident at 0x%08x-0x%08x. "
                        "Can't load binary at overlapping address range 0x%08x-0x%08x. "
                        "Either change binary loading address, or use the --no-stub "
                        "option to disable the software loader."
                        % (stub_start, stub_end, load_start, load_end)
                    )

        return self.check_command(
            "enter RAM download mode",
            self.ESP_MEM_BEGIN,
            struct.pack("<IIII", size, blocks, blocksize, offset),
        )

    def mem_block(self, data, seq):
        """Send a block of an image to RAM"""
        return self.check_command(
            "write to target RAM",
            self.ESP_MEM_DATA,
            struct.pack("<IIII", len(data), seq, 0, 0) + data,
            self.checksum(data),
        )

    def mem_finish(self, entrypoint=0):
        """Leave download mode and run the application"""
        # Sending ESP_MEM_END usually sends a correct response back, however sometimes
        # (with ROM loader) the executed code may reset the UART or change the baud rate
        # before the transmit FIFO is empty. So in these cases we set a short timeout
        # and ignore errors.
        timeout = DEFAULT_TIMEOUT if self.IS_STUB else MEM_END_ROM_TIMEOUT
        data = struct.pack("<II", int(entrypoint == 0), entrypoint)
        try:
            return self.check_command(
                "leave RAM download mode", self.ESP_MEM_END, data=data, timeout=timeout
            )
        except FatalError:
            if self.IS_STUB:
                raise
            pass

    def flash_begin(self, size, offset, begin_rom_encrypted=False):
        """
        Start downloading to Flash (performs an erase)

        Returns number of blocks (of size self.FLASH_WRITE_SIZE) to write.
        """
        num_blocks = (size + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE
        erase_size = self.get_erase_size(offset, size)

        t = time.time()
        if self.IS_STUB:
            timeout = DEFAULT_TIMEOUT
        else:
            timeout = timeout_per_mb(
                ERASE_REGION_TIMEOUT_PER_MB, size
            )  # ROM performs the erase up front

        params = struct.pack(
            "<IIII", erase_size, num_blocks, self.FLASH_WRITE_SIZE, offset
        )
        if self.SUPPORTS_ENCRYPTED_FLASH and not self.IS_STUB:
            params += struct.pack("<I", 1 if begin_rom_encrypted else 0)
        self.check_command(
            "enter Flash download mode", self.ESP_FLASH_BEGIN, params, timeout=timeout
        )
        if size != 0 and not self.IS_STUB:
            print("Took %.2fs to erase flash block" % (time.time() - t))
        return num_blocks

    def flash_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        """Write block to flash, retry if fail"""
        for attempts_left in range(WRITE_BLOCK_ATTEMPTS - 1, -1, -1):
            try:
                self.check_command(
                    "write to target Flash after seq %d" % seq,
                    self.ESP_FLASH_DATA,
                    struct.pack("<IIII", len(data), seq, 0, 0) + data,
                    self.checksum(data),
                    timeout=timeout,
                )
                break
            except FatalError:
                if attempts_left:
                    self.trace(
                        "Block write failed, "
                        f"retrying with {attempts_left} attempts left"
                    )
                else:
                    raise

    def flash_encrypt_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        """Encrypt, write block to flash, retry if fail"""
        if self.SUPPORTS_ENCRYPTED_FLASH and not self.IS_STUB:
            # ROM support performs the encrypted writes via the normal write command,
            # triggered by flash_begin(begin_rom_encrypted=True)
            return self.flash_block(data, seq, timeout)

        for attempts_left in range(WRITE_BLOCK_ATTEMPTS - 1, -1, -1):
            try:
                self.check_command(
                    "Write encrypted to target Flash after seq %d" % seq,
                    self.ESP_FLASH_ENCRYPT_DATA,
                    struct.pack("<IIII", len(data), seq, 0, 0) + data,
                    self.checksum(data),
                    timeout=timeout,
                )
                break
            except FatalError:
                if attempts_left:
                    self.trace(
                        "Encrypted block write failed, "
                        f"retrying with {attempts_left} attempts left"
                    )
                else:
                    raise

    def flash_finish(self, reboot=False):
        """Leave flash mode and run/reboot"""
        pkt = struct.pack("<I", int(not reboot))
        # stub sends a reply to this command
        self.check_command("leave Flash mode", self.ESP_FLASH_END, pkt)

    def run(self, reboot=False):
        """Run application code in flash"""
        # Fake flash begin immediately followed by flash end
        self.flash_begin(0, 0)
        self.flash_finish(reboot)

    def flash_id(self):
        """Read SPI flash manufacturer and device id"""
        if self.cache["flash_id"] is None:
            SPIFLASH_RDID = 0x9F
            self.cache["flash_id"] = self.run_spiflash_command(SPIFLASH_RDID, b"", 24)
        return self.cache["flash_id"]

    def flash_type(self):
        """Read flash type bit field from eFuse. Returns 0, 1, None (not present)"""
        return None  # not implemented for all chip targets

    def get_security_info(self):
        res = self.check_command("get security info", self.ESP_GET_SECURITY_INFO, b"")
        esp32s2 = True if len(res) == 12 else False
        res = struct.unpack("<IBBBBBBBB" if esp32s2 else "<IBBBBBBBBII", res)
        return {
            "flags": res[0],
            "flash_crypt_cnt": res[1],
            "key_purposes": res[2:9],
            "chip_id": None if esp32s2 else res[9],
            "api_version": None if esp32s2 else res[10],
        }

    @esp32s3_or_newer_function_only
    def get_chip_id(self):
        if self.cache["chip_id"] is None:
            res = self.check_command(
                "get security info", self.ESP_GET_SECURITY_INFO, b""
            )
            res = struct.unpack(
                "<IBBBBBBBBI", res[:16]
            )  # 4b flags, 1b flash_crypt_cnt, 7*1b key_purposes, 4b chip_id
            self.cache["chip_id"] = res[9]  # 2/4 status bytes invariant
        return self.cache["chip_id"]

    def get_uart_no(self):
        """
        Read the UARTDEV_BUF_NO register to get the number of the currently used console
        """
        if self.cache["uart_no"] is None:
            self.cache["uart_no"] = self.read_reg(self.UARTDEV_BUF_NO) & 0xFF
        return self.cache["uart_no"]

    @classmethod
    def parse_flash_size_arg(cls, arg):
        try:
            return cls.FLASH_SIZES[arg]
        except KeyError:
            raise FatalError(
                "Flash size '%s' is not supported by this chip type. "
                "Supported sizes: %s" % (arg, ", ".join(cls.FLASH_SIZES.keys()))
            )

    @classmethod
    def parse_flash_freq_arg(cls, arg):
        if arg is None:
            # The encoding of the default flash frequency in FLASH_FREQUENCY is always 0
            return 0
        try:
            return cls.FLASH_FREQUENCY[arg]
        except KeyError:
            raise FatalError(
                "Flash frequency '%s' is not supported by this chip type. "
                "Supported frequencies: %s"
                % (arg, ", ".join(cls.FLASH_FREQUENCY.keys()))
            )

    def run_stub(self, stub=None):
        if stub is None:
            stub = StubFlasher(get_stub_json_path(self.CHIP_NAME))

        if self.sync_stub_detected:
            print("Stub is already running. No upload is necessary.")
            return self.STUB_CLASS(self)

        # Upload
        print("Uploading stub...")
        for field in [stub.text, stub.data]:
            if field is not None:
                offs = stub.text_start if field == stub.text else stub.data_start
                length = len(field)
                blocks = (length + self.ESP_RAM_BLOCK - 1) // self.ESP_RAM_BLOCK
                self.mem_begin(length, blocks, self.ESP_RAM_BLOCK, offs)
                for seq in range(blocks):
                    from_offs = seq * self.ESP_RAM_BLOCK
                    to_offs = from_offs + self.ESP_RAM_BLOCK
                    self.mem_block(field[from_offs:to_offs], seq)
        print("Running stub...")
        self.mem_finish(stub.entry)
        try:
            p = self.read()
        except StopIteration:
            raise FatalError(
                "Failed to start stub. There was no response."
                "\nTry increasing timeouts, for more information see: "
                "https://docs.espressif.com/projects/esptool/en/latest/esptool/configuration-file.html"  # noqa E501
            )

        if p != b"OHAI":
            raise FatalError(f"Failed to start stub. Unexpected response: {p}")
        print("Stub running...")
        return self.STUB_CLASS(self)

    @stub_and_esp32_function_only
    def flash_defl_begin(self, size, compsize, offset):
        """
        Start downloading compressed data to Flash (performs an erase)

        Returns number of blocks (size self.FLASH_WRITE_SIZE) to write.
        """
        num_blocks = (compsize + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE
        erase_blocks = (size + self.FLASH_WRITE_SIZE - 1) // self.FLASH_WRITE_SIZE

        t = time.time()
        if self.IS_STUB:
            write_size = (
                size  # stub expects number of bytes here, manages erasing internally
            )
            timeout = DEFAULT_TIMEOUT
        else:
            write_size = (
                erase_blocks * self.FLASH_WRITE_SIZE
            )  # ROM expects rounded up to erase block size
            timeout = timeout_per_mb(
                ERASE_REGION_TIMEOUT_PER_MB, write_size
            )  # ROM performs the erase up front
        print("Compressed %d bytes to %d..." % (size, compsize))
        params = struct.pack(
            "<IIII", write_size, num_blocks, self.FLASH_WRITE_SIZE, offset
        )
        if self.SUPPORTS_ENCRYPTED_FLASH and not self.IS_STUB:
            # extra param is to enter encrypted flash mode via ROM
            # (not supported currently)
            params += struct.pack("<I", 0)
        self.check_command(
            "enter compressed flash mode",
            self.ESP_FLASH_DEFL_BEGIN,
            params,
            timeout=timeout,
        )
        if size != 0 and not self.IS_STUB:
            # (stub erases as it writes, but ROM loaders erase on begin)
            print("Took %.2fs to erase flash block" % (time.time() - t))
        return num_blocks

    @stub_and_esp32_function_only
    def flash_defl_block(self, data, seq, timeout=DEFAULT_TIMEOUT):
        """Write block to flash, send compressed, retry if fail"""
        for attempts_left in range(WRITE_BLOCK_ATTEMPTS - 1, -1, -1):
            try:
                self.check_command(
                    "write compressed data to flash after seq %d" % seq,
                    self.ESP_FLASH_DEFL_DATA,
                    struct.pack("<IIII", len(data), seq, 0, 0) + data,
                    self.checksum(data),
                    timeout=timeout,
                )
                break
            except FatalError:
                if attempts_left:
                    self.trace(
                        "Compressed block write failed, "
                        f"retrying with {attempts_left} attempts left"
                    )
                else:
                    raise

    @stub_and_esp32_function_only
    def flash_defl_finish(self, reboot=False):
        """Leave compressed flash mode and run/reboot"""
        if not reboot and not self.IS_STUB:
            # skip sending flash_finish to ROM loader, as this
            # exits the bootloader. Stub doesn't do this.
            return
        pkt = struct.pack("<I", int(not reboot))
        self.check_command("leave compressed flash mode", self.ESP_FLASH_DEFL_END, pkt)
        self.in_bootloader = False

    @stub_and_esp32_function_only
    def flash_md5sum(self, addr, size):
        # the MD5 command returns additional bytes in the standard
        # command reply slot
        timeout = timeout_per_mb(MD5_TIMEOUT_PER_MB, size)
        res = self.check_command(
            "calculate md5sum",
            self.ESP_SPI_FLASH_MD5,
            struct.pack("<IIII", addr, size, 0, 0),
            timeout=timeout,
        )

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
        self.command(self.ESP_CHANGE_BAUDRATE, struct.pack("<II", baud, second_arg))
        print("Changed.")
        self._set_port_baudrate(baud)
        time.sleep(0.05)  # get rid of crap sent during baud rate change
        self.flush_input()

    @stub_function_only
    def erase_flash(self):
        # depending on flash chip model the erase may take this long (maybe longer!)
        self.check_command(
            "erase flash", self.ESP_ERASE_FLASH, timeout=CHIP_ERASE_TIMEOUT
        )

    @stub_function_only
    def erase_region(self, offset, size):
        if offset % self.FLASH_SECTOR_SIZE != 0:
            raise FatalError("Offset to erase from must be a multiple of 4096")
        if size % self.FLASH_SECTOR_SIZE != 0:
            raise FatalError("Size of data to erase must be a multiple of 4096")
        timeout = timeout_per_mb(ERASE_REGION_TIMEOUT_PER_MB, size)
        self.check_command(
            "erase region",
            self.ESP_ERASE_REGION,
            struct.pack("<II", offset, size),
            timeout=timeout,
        )

    def read_flash_slow(self, offset, length, progress_fn):
        raise NotImplementedInROMError(self, self.read_flash_slow)

    def read_flash(self, offset, length, progress_fn=None):
        if not self.IS_STUB:
            return self.read_flash_slow(offset, length, progress_fn)  # ROM-only routine

        # issue a standard bootloader command to trigger the read
        self.check_command(
            "read flash",
            self.ESP_READ_FLASH,
            struct.pack("<IIII", offset, length, self.FLASH_SECTOR_SIZE, 64),
        )
        # now we expect (length // block_size) SLIP frames with the data
        data = b""
        while len(data) < length:
            p = self.read()
            data += p
            if len(data) < length and len(p) < self.FLASH_SECTOR_SIZE:
                raise FatalError(
                    "Corrupt data, expected 0x%x bytes but received 0x%x bytes"
                    % (self.FLASH_SECTOR_SIZE, len(p))
                )
            self.write(struct.pack("<I", len(data)))
            if progress_fn and (len(data) % 1024 == 0 or len(data) == length):
                progress_fn(len(data), length)
        if progress_fn:
            progress_fn(len(data), length)
        if len(data) > length:
            raise FatalError("Read more than expected")

        digest_frame = self.read()
        if len(digest_frame) != 16:
            raise FatalError("Expected digest, got: %s" % hexify(digest_frame))
        expected_digest = hexify(digest_frame).upper()
        digest = hashlib.md5(data).hexdigest().upper()
        if digest != expected_digest:
            raise FatalError(
                "Digest mismatch: expected %s, got %s" % (expected_digest, digest)
            )
        return data

    def flash_spi_attach(self, hspi_arg):
        """Send SPI attach command to enable the SPI flash pins

        ESP8266 ROM does this when you send flash_begin, ESP32 ROM
        has it as a SPI command.
        """
        # last 3 bytes in ESP_SPI_ATTACH argument are reserved values
        arg = struct.pack("<I", hspi_arg)
        if not self.IS_STUB:
            # ESP32 ROM loader takes additional 'is legacy' arg, which is not
            # currently supported in the stub loader or esptool.py
            # (as it's not usually needed.)
            is_legacy = 0
            arg += struct.pack("BBBB", is_legacy, 0, 0, 0)
        self.check_command("configure SPI flash pins", self.ESP_SPI_ATTACH, arg)

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
        status_mask = 0xFFFF
        self.check_command(
            "set SPI params",
            self.ESP_SPI_SET_PARAMS,
            struct.pack(
                "<IIIIII",
                fl_id,
                total_size,
                block_size,
                sector_size,
                page_size,
                status_mask,
            ),
        )

    def run_spiflash_command(
        self,
        spiflash_command,
        data=b"",
        read_bits=0,
        addr=None,
        addr_len=0,
        dummy_len=0,
    ):
        """Run an arbitrary SPI flash command.

        This function uses the "USR_COMMAND" functionality in the ESP
        SPI hardware, rather than the precanned commands supported by
        hardware. So the value of spiflash_command is an actual command
        byte, sent over the wire.

        After writing command byte, writes 'data' to MOSI and then
        reads back 'read_bits' of reply on MISO. Result is a number.
        """

        # SPI_USR register flags
        SPI_USR_COMMAND = 1 << 31
        SPI_USR_ADDR = 1 << 30
        SPI_USR_DUMMY = 1 << 29
        SPI_USR_MISO = 1 << 28
        SPI_USR_MOSI = 1 << 27

        # SPI registers, base address differs ESP32* vs 8266
        base = self.SPI_REG_BASE
        SPI_CMD_REG = base + 0x00
        SPI_ADDR_REG = base + 0x04
        SPI_USR_REG = base + self.SPI_USR_OFFS
        SPI_USR1_REG = base + self.SPI_USR1_OFFS
        SPI_USR2_REG = base + self.SPI_USR2_OFFS
        SPI_W0_REG = base + self.SPI_W0_OFFS

        # following two registers are ESP32 and later chips only
        if self.SPI_MOSI_DLEN_OFFS is not None:
            # ESP32 and later chips have a more sophisticated way
            # to set up "user" commands
            def set_data_lengths(mosi_bits, miso_bits):
                SPI_MOSI_DLEN_REG = base + self.SPI_MOSI_DLEN_OFFS
                SPI_MISO_DLEN_REG = base + self.SPI_MISO_DLEN_OFFS
                if mosi_bits > 0:
                    self.write_reg(SPI_MOSI_DLEN_REG, mosi_bits - 1)
                if miso_bits > 0:
                    self.write_reg(SPI_MISO_DLEN_REG, miso_bits - 1)
                flags = 0
                if dummy_len > 0:
                    flags |= dummy_len - 1
                if addr_len > 0:
                    flags |= (addr_len - 1) << SPI_USR_ADDR_LEN_SHIFT
                if flags:
                    self.write_reg(SPI_USR1_REG, flags)

        else:

            def set_data_lengths(mosi_bits, miso_bits):
                SPI_DATA_LEN_REG = SPI_USR1_REG
                SPI_MOSI_BITLEN_S = 17
                SPI_MISO_BITLEN_S = 8
                mosi_mask = 0 if (mosi_bits == 0) else (mosi_bits - 1)
                miso_mask = 0 if (miso_bits == 0) else (miso_bits - 1)
                flags = (miso_mask << SPI_MISO_BITLEN_S) | (
                    mosi_mask << SPI_MOSI_BITLEN_S
                )
                if dummy_len > 0:
                    flags |= dummy_len - 1
                if addr_len > 0:
                    flags |= (addr_len - 1) << SPI_USR_ADDR_LEN_SHIFT
                self.write_reg(SPI_DATA_LEN_REG, flags)

        # SPI peripheral "command" bitmasks for SPI_CMD_REG
        SPI_CMD_USR = 1 << 18

        # shift values
        SPI_USR2_COMMAND_LEN_SHIFT = 28
        SPI_USR_ADDR_LEN_SHIFT = 26

        if read_bits > 32:
            raise FatalError(
                "Reading more than 32 bits back from a SPI flash "
                "operation is unsupported"
            )
        if len(data) > 64:
            raise FatalError(
                "Writing more than 64 bytes of data with one SPI "
                "command is unsupported"
            )

        data_bits = len(data) * 8
        old_spi_usr = self.read_reg(SPI_USR_REG)
        old_spi_usr2 = self.read_reg(SPI_USR2_REG)
        flags = SPI_USR_COMMAND
        if read_bits > 0:
            flags |= SPI_USR_MISO
        if data_bits > 0:
            flags |= SPI_USR_MOSI
        if addr_len > 0:
            flags |= SPI_USR_ADDR
        if dummy_len > 0:
            flags |= SPI_USR_DUMMY
        set_data_lengths(data_bits, read_bits)
        self.write_reg(SPI_USR_REG, flags)
        self.write_reg(
            SPI_USR2_REG, (7 << SPI_USR2_COMMAND_LEN_SHIFT) | spiflash_command
        )
        if addr and addr_len > 0:
            self.write_reg(SPI_ADDR_REG, addr)
        if data_bits == 0:
            self.write_reg(SPI_W0_REG, 0)  # clear data register before we read it
        else:
            data = pad_to(data, 4, b"\00")  # pad to 32-bit multiple
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

    def read_spiflash_sfdp(self, addr, read_bits):
        CMD_RDSFDP = 0x5A
        return self.run_spiflash_command(
            CMD_RDSFDP, read_bits=read_bits, addr=addr, addr_len=24, dummy_len=8
        )

    def read_status(self, num_bytes=2):
        """Read up to 24 bits (num_bytes) of SPI flash status register contents
        via RDSR, RDSR2, RDSR3 commands

        Not all SPI flash supports all three commands. The upper 1 or 2
        bytes may be 0xFF.
        """
        SPIFLASH_RDSR = 0x05
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

        # also try using individual commands
        # (also not supported by all chips for num_bytes 2 & 3)
        for cmd in [SPIFLASH_WRSR, SPIFLASH_WRSR2, SPIFLASH_WRSR3][0:num_bytes]:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(cmd, struct.pack("B", new_status & 0xFF))
            new_status >>= 8

        self.run_spiflash_command(SPIFLASH_WRDI)

    def get_crystal_freq(self):
        """
        Figure out the crystal frequency from the UART clock divider

        Returns a normalized value in integer MHz (only values 40 or 26 are supported)
        """
        # The logic here is:
        # - We know that our baud rate and the ESP UART baud rate are roughly the same,
        #   or we couldn't communicate
        # - We can read the UART clock divider register to know how the ESP derives this
        #   from the APB bus frequency
        # - Multiplying these two together gives us the bus frequency which is either
        #   the crystal frequency (ESP32) or double the crystal frequency (ESP8266).
        #   See the self.XTAL_CLK_DIVIDER parameter for this factor.
        uart_div = self.read_reg(self.UART_CLKDIV_REG) & self.UART_CLKDIV_MASK
        est_xtal = (self._port.baudrate * uart_div) / 1e6 / self.XTAL_CLK_DIVIDER
        if est_xtal > 45:
            norm_xtal = 48
        elif est_xtal > 33:
            norm_xtal = 40
        else:
            norm_xtal = 26
        if abs(norm_xtal - est_xtal) > 1:
            print(
                "WARNING: Detected crystal freq %.2fMHz is quite different to "
                "normalized freq %dMHz. Unsupported crystal in use?"
                % (est_xtal, norm_xtal)
            )
        return norm_xtal

    def hard_reset(self):
        print("Hard resetting via RTS pin...")
        HardReset(self._port)()

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
                raise FatalError(
                    "Soft resetting is currently only supported on ESP8266"
                )
            else:
                # running user code from stub loader requires some hacks
                # in the stub loader
                self.command(self.ESP_RUN_USER_CODE, wait_response=False)

    def check_chip_id(self):
        try:
            chip_id = self.get_chip_id()
            if chip_id != self.IMAGE_CHIP_ID:
                print(
                    "WARNING: Chip ID {} ({}) doesn't match expected Chip ID {}. "
                    "esptool may not work correctly.".format(
                        chip_id,
                        self.UNSUPPORTED_CHIPS.get(chip_id, "Unknown"),
                        self.IMAGE_CHIP_ID,
                    )
                )
                # Try to flash anyways by disabling stub
                self.stub_is_disabled = True
        except NotImplementedInROMError:
            pass


def slip_reader(port, trace_function):
    """Generator to read SLIP packets from a serial port.
    Yields one full SLIP packet at a time, raises exception on timeout or invalid data.

    Designed to avoid too many calls to serial.read(1), which can bog
    down on slow systems.
    """

    def detect_panic_handler(input):
        """
        Checks the input bytes for panic handler messages.
        Raises a FatalError if Guru Meditation or Fatal Exception is found, as both
        of these are used between different ROM versions.
        Tries to also parse the error cause (e.g. IllegalInstruction).
        """

        guru_meditation = (
            rb"G?uru Meditation Error: (?:Core \d panic'ed \(([a-zA-Z ]*)\))?"
        )
        fatal_exception = rb"F?atal exception \(\d+\): (?:([a-zA-Z ]*)?.*epc)?"

        # Search either for Guru Meditation or Fatal Exception
        data = re.search(
            rb"".join([rb"(?:", guru_meditation, rb"|", fatal_exception, rb")"]),
            input,
            re.DOTALL,
        )
        if data is not None:
            cause = [
                "({})".format(i.decode("utf-8"))
                for i in [data.group(1), data.group(2)]
                if i is not None
            ]
            cause = f" {cause[0]}" if len(cause) else ""
            msg = f"Guru Meditation Error detected{cause}"
            raise FatalError(msg)

    partial_packet = None
    in_escape = False
    successful_slip = False
    while True:
        waiting = port.inWaiting()
        read_bytes = port.read(1 if waiting == 0 else waiting)
        if read_bytes == b"":
            if partial_packet is None:  # fail due to no data
                msg = (
                    "Serial data stream stopped: Possible serial noise or corruption."
                    if successful_slip
                    else "No serial data received."
                )
            else:  # fail during packet transfer
                msg = "Packet content transfer stopped (received {} bytes)".format(
                    len(partial_packet)
                )
            trace_function(msg)
            raise FatalError(msg)
        trace_function("Read %d bytes: %s", len(read_bytes), HexFormatter(read_bytes))
        for b in read_bytes:
            b = bytes([b])
            if partial_packet is None:  # waiting for packet header
                if b == b"\xc0":
                    partial_packet = b""
                else:
                    trace_function("Read invalid data: %s", HexFormatter(read_bytes))
                    remaining_data = port.read(port.inWaiting())
                    trace_function(
                        "Remaining data in serial buffer: %s",
                        HexFormatter(remaining_data),
                    )
                    detect_panic_handler(read_bytes + remaining_data)
                    raise FatalError(
                        "Invalid head of packet (0x%s): "
                        "Possible serial noise or corruption." % hexify(b)
                    )
            elif in_escape:  # part-way through escape sequence
                in_escape = False
                if b == b"\xdc":
                    partial_packet += b"\xc0"
                elif b == b"\xdd":
                    partial_packet += b"\xdb"
                else:
                    trace_function("Read invalid data: %s", HexFormatter(read_bytes))
                    remaining_data = port.read(port.inWaiting())
                    trace_function(
                        "Remaining data in serial buffer: %s",
                        HexFormatter(remaining_data),
                    )
                    detect_panic_handler(read_bytes + remaining_data)
                    raise FatalError("Invalid SLIP escape (0xdb, 0x%s)" % (hexify(b)))
            elif b == b"\xdb":  # start of escape sequence
                in_escape = True
            elif b == b"\xc0":  # end of packet
                trace_function("Received full packet: %s", HexFormatter(partial_packet))
                yield partial_packet
                partial_packet = None
                successful_slip = True
            else:  # normal byte in packet
                partial_packet += b


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
                ascii_line = "".join(
                    c
                    if (
                        c == " "
                        or (c in string.printable and c not in string.whitespace)
                    )
                    else "."
                    for c in line.decode("ascii", "replace")
                )
                s = s[16:]
                result += "\n    %-16s %-16s | %s" % (
                    hexify(line[:8], False),
                    hexify(line[8:], False),
                    ascii_line,
                )
            return result
        else:
            return hexify(self._s, False)
