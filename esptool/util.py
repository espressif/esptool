# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later
from __future__ import annotations
import os
import re
import struct

from typing import IO, TypeAlias

# Define a custom type for the input
ImageSource: TypeAlias = str | bytes | IO[bytes]


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
    """Given a flash size of the type passed in size
    (ie 512KB or 1MB) then return the size in bytes.
    """
    if size is None:
        return None
    if "MB" in size:
        return int(size[: size.index("MB")]) * 1024 * 1024
    elif "KB" in size:
        return int(size[: size.index("KB")]) * 1024
    else:
        raise FatalError(f"Unknown size {size}")


def hexify(s, uppercase=True):
    format_str = "%02X" if uppercase else "%02x"
    return "".join(format_str % c for c in s)


def pad_to(data, alignment, pad_character=b"\xff"):
    """Pad to the next alignment boundary"""
    pad_mod = len(data) % alignment
    if pad_mod != 0:
        data += pad_character * (alignment - pad_mod)
    return data


def expand_chip_name(chip_name):
    """Change chip name to official form, e.g. `esp32s3beta2` -> `ESP32-S3(beta2)`"""
    # Put "-" after "esp32"
    chip_name = re.sub(r"(esp32)(?!$)", r"\1-", chip_name)
    # Put "()" around "betaN"
    chip_name = re.sub(r"(beta\d*)", r"(\1)", chip_name)
    # Uppercase everything before "(betaN)"
    chip_name = re.sub(r"^[^\(]+", lambda x: x.group(0).upper(), chip_name)
    return chip_name


def strip_chip_name(chip_name):
    """Strip chip name to normalized form, e.g. `ESP32-S3(beta2)` -> `esp32s3beta2`"""
    return re.sub(r"[-()]", "", chip_name.lower())


def get_file_size(path_to_file):
    """Returns the file size in bytes"""
    file_size = 0
    with open(path_to_file, "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
    return file_size


def sanitize_string(byte_string):
    return byte_string.decode("utf-8").replace("\0", "")


def get_bytes(input: ImageSource) -> tuple[bytes, str | None]:
    """
    Normalize the input (file path, bytes, or an opened file-like object) into bytes
    and provide a name of the source.

    Args:
        input: The input file path, bytes, or an opened file-like object.

    Returns:
        A tuple containing the normalized bytes and the source of the input.
    """
    if isinstance(input, str):
        with open(input, "rb") as f:
            data = f.read()
            source = input
    elif isinstance(input, bytes):
        data = input
        source = None
    elif hasattr(input, "read") and hasattr(input, "write") and hasattr(input, "close"):
        pos = input.tell()
        data = input.read()
        input.seek(pos)  # Reset the file pointer
        source = input.name
    else:
        raise FatalError(f"Invalid input type {type(input)}")
    return data, source


def get_key_from_value(dict, val):
    """
    Get key from value in dictionary, assumes unique values in dictionary
    """
    for key, value in dict.items():
        if value == val:
            return key
    return None


def check_deprecated_py_suffix(module_name: str) -> None:
    """Check if called with deprecated .py suffix"""
    import sys
    from esptool import log

    script_name = sys.argv[0] if sys.argv else ""
    if script_name.endswith(module_name + ".py"):
        log.warning(
            f"DEPRECATED: '{module_name}.py' is deprecated. Please use '{module_name}' "
            "instead. The '.py' suffix will be removed in a future major release."
        )


class PrintOnce:
    """
    Class for printing messages just once. Can be useful when running in a loop
    """

    def __init__(self, print_callback) -> None:
        self.already_printed = False
        self.print_callback = print_callback

    def __call__(self, text) -> None:
        if not self.already_printed:
            self.print_callback(text)
            self.already_printed = True


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
            0x100: "Undefined errors",
            0x101: "The input parameter is invalid",
            0x102: "Failed to malloc memory from system",
            0x103: "Failed to send out message",
            0x104: "Failed to receive message",
            0x105: "The format of the received message is invalid",
            0x106: "Message is ok, but the running result is wrong",
            0x107: "Checksum error",
            0x108: "Flash write error",
            0x109: "Flash read error",
            0x10A: "Flash read length error",
            0x10B: "Deflate failed error",
            0x10C: "Deflate Adler32 error",
            0x10D: "Deflate parameter error",
            0x10E: "Invalid RAM binary size",
            0x10F: "Invalid RAM binary address",
            0x164: "Invalid parameter",
            0x165: "Invalid format",
            0x166: "Description too long",
            0x167: "Bad encoding description",
            0x169: "Insufficient storage",
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
            f"{bootloader.CHIP_NAME} ROM does not support function {func.__name__}.",
        )


class NotSupportedError(FatalError):
    def __init__(self, esp, function_name):
        FatalError.__init__(
            self,
            f"{function_name} is not supported by {esp.CHIP_NAME}.",
        )


class UnsupportedCommandError(RuntimeError):
    """
    Wrapper class for when ROM loader returns an invalid command response.

    Usually this indicates the loader is running in Secure Download Mode.
    """

    def __init__(self, esp, op):
        if esp.secure_download_mode:
            msg = f"This command ({op:#x}) is not supported in Secure Download Mode"
        else:
            msg = f"Invalid (unsupported) command {op:#x}"
        RuntimeError.__init__(self, msg)
