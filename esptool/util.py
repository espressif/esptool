# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
import sys


def byte(bitstr, index):
    return bitstr[index]


def mask_to_shift(mask):
    """Return the index of the least significant bit in the mask"""
    shift = 0
    while mask & 0x1 == 0:
        shift += 1
        mask >>= 1
    return shift


def div_roundup(a, b):
    """Return a/b rounded up to nearest integer,
    equivalent result to int(math.ceil(float(int(a)) / float(int(b))), only
    without possible floating point accuracy errors.
    """
    return (int(a) + int(b) - 1) // int(b)


def flash_size_bytes(size):
    """Given a flash size of the type passed in args.flash_size
    (ie 512KB or 1MB) then return the size in bytes.
    """
    if "MB" in size:
        return int(size[: size.index("MB")]) * 1024 * 1024
    elif "KB" in size:
        return int(size[: size.index("KB")]) * 1024
    else:
        raise FatalError("Unknown size %s" % size)


def hexify(s, uppercase=True):
    format_str = "%02X" if uppercase else "%02x"
    return "".join(format_str % c for c in s)


def pad_to(data, alignment, pad_character=b"\xFF"):
    """Pad to the next alignment boundary"""
    pad_mod = len(data) % alignment
    if pad_mod != 0:
        data += pad_character * (alignment - pad_mod)
    return data


def print_overwrite(message, last_line=False):
    """Print a message, overwriting the currently printed line.

    If last_line is False, don't append a newline at the end
    (expecting another subsequent call will overwrite this one.)

    After a sequence of calls with last_line=False, call once with last_line=True.

    If output is not a TTY (for example redirected a pipe),
    no overwriting happens and this function is the same as print().
    """
    if sys.stdout.isatty():
        print("\r%s" % message, end="\n" if last_line else "")
    else:
        print(message)


class FatalError(RuntimeError):
    """
    Wrapper class for runtime errors that aren't caused by internal bugs, but by
    ESP ROM responses or input content.
    """

    def __init__(self, message):
        RuntimeError.__init__(self, message)

    @staticmethod
    def WithResult(message, result):
        """
        Return a fatal error object that appends the hex values of
        'result' and its meaning as a string formatted argument.
        """

        err_defs = {
            # ROM error codes
            0x101: "Out of memory",
            0x102: "Invalid argument",
            0x103: "Invalid state",
            0x104: "Invalid size",
            0x105: "Requested resource not found",
            0x106: "Operation or feature not supported",
            0x107: "Operation timed out",
            0x108: "Received response was invalid",
            0x109: "CRC or checksum was invalid",
            0x10A: "Version was invalid",
            0x10B: "MAC address was invalid",
            # Flasher stub error codes
            0xC000: "Bad data length",
            0xC100: "Bad data checksum",
            0xC200: "Bad blocksize",
            0xC300: "Invalid command",
            0xC400: "Failed SPI operation",
            0xC500: "Failed SPI unlock",
            0xC600: "Not in flash mode",
            0xC700: "Inflate error",
            0xC800: "Not enough data",
            0xC900: "Too much data",
            0xFF00: "Command not implemented",
        }

        err_code = struct.unpack(">H", result[:2])
        message += " (result was {}: {})".format(
            hexify(result), err_defs.get(err_code[0], "Unknown result")
        )
        return FatalError(message)


class NotImplementedInROMError(FatalError):
    """
    Wrapper class for the error thrown when a particular ESP bootloader function
    is not implemented in the ROM bootloader.
    """

    def __init__(self, bootloader, func):
        FatalError.__init__(
            self,
            "%s ROM does not support function %s."
            % (bootloader.CHIP_NAME, func.__name__),
        )


class NotSupportedError(FatalError):
    def __init__(self, esp, function_name):
        FatalError.__init__(
            self,
            "Function %s is not supported for %s." % (function_name, esp.CHIP_NAME),
        )


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
