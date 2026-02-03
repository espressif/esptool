# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass
from io import StringIO
from typing import Any

from espefuse.efuse.base_operations import BaseCommands
from espefuse.efuse.emulate_efuse_controller_base import EmulateEfuseControllerBase
import esptool
from esptool.util import strip_chip_name

import espefuse.efuse.esp32 as esp32_efuse
import espefuse.efuse.esp32c2 as esp32c2_efuse
import espefuse.efuse.esp32c3 as esp32c3_efuse
import espefuse.efuse.esp32c5 as esp32c5_efuse
import espefuse.efuse.esp32c6 as esp32c6_efuse
import espefuse.efuse.esp32c61 as esp32c61_efuse
import espefuse.efuse.esp32e22 as esp32e22_efuse
import espefuse.efuse.esp32h2 as esp32h2_efuse
import espefuse.efuse.esp32h21 as esp32h21_efuse
import espefuse.efuse.esp32h4 as esp32h4_efuse
import espefuse.efuse.esp32p4 as esp32p4_efuse
import espefuse.efuse.esp32s2 as esp32s2_efuse
import espefuse.efuse.esp32s3 as esp32s3_efuse
import espefuse.efuse.esp32s31 as esp32s31_efuse


@dataclass
class DefChip:
    efuse_lib: Any
    chip_class: type[esptool.ESPLoader]


SUPPORTED_BURN_COMMANDS = [
    "read-protect-efuse",
    "write-protect-efuse",
    "burn-efuse",
    "burn-block-data",
    "burn-bit",
    "burn-key",
    "burn-key-digest",
    "burn-custom-mac",
    "set-flash-voltage",
]

SUPPORTED_READ_COMMANDS = [
    "summary",
    "dump",
    "get-custom-mac",
    "adc-info",
    "check-error",
]

DEPRECATED_COMMANDS = ["execute-scripts"]

SUPPORTED_COMMANDS = (
    SUPPORTED_READ_COMMANDS + SUPPORTED_BURN_COMMANDS + DEPRECATED_COMMANDS
)

SUPPORTED_CHIPS = {
    "esp32": DefChip(esp32_efuse, esptool.targets.ESP32ROM),
    "esp32c2": DefChip(esp32c2_efuse, esptool.targets.ESP32C2ROM),
    "esp32c3": DefChip(esp32c3_efuse, esptool.targets.ESP32C3ROM),
    "esp32c6": DefChip(esp32c6_efuse, esptool.targets.ESP32C6ROM),
    "esp32c61": DefChip(esp32c61_efuse, esptool.targets.ESP32C61ROM),
    "esp32c5": DefChip(esp32c5_efuse, esptool.targets.ESP32C5ROM),
    "esp32e22": DefChip(esp32e22_efuse, esptool.targets.ESP32E22ROM),
    "esp32h2": DefChip(esp32h2_efuse, esptool.targets.ESP32H2ROM),
    "esp32h21": DefChip(esp32h21_efuse, esptool.targets.ESP32H21ROM),
    "esp32h4": DefChip(esp32h4_efuse, esptool.targets.ESP32H4ROM),
    "esp32p4": DefChip(esp32p4_efuse, esptool.targets.ESP32P4ROM),
    "esp32s2": DefChip(esp32s2_efuse, esptool.targets.ESP32S2ROM),
    "esp32s3": DefChip(esp32s3_efuse, esptool.targets.ESP32S3ROM),
    "esp32s31": DefChip(esp32s31_efuse, esptool.targets.ESP32S31ROM),
}


def _get_command_class(chip_name: str) -> BaseCommands:
    return SUPPORTED_CHIPS[chip_name].efuse_lib.commands()  # type: ignore


def init_commands(
    port: str | None = None,
    baud: int = 115200,
    before: str = "default-reset",
    chip: str = "auto",
    esp: esptool.ESPLoader | EmulateEfuseControllerBase | None = None,
    **kwargs: Any,
) -> BaseCommands:
    """Get the ESP eFuse commands class for the given chip
    This function will establish a connection to the chip and
    return the ESP eFuse commands class with initialized chip
    and eFuse values.

    Either esp or port should be provided. If both are provided, esp will be used.
    If neither is provided, the function will create a mock ESPLoader object for tests.

    Args:
        port: The port to connect to the chip
        baud: The baud rate to connect to the chip
        before: The reset mode to use before connecting to the chip
        chip: The chip to use.
        esp: Optional ESPLoader object to use. If provided, the port, baud, before, and
            chip arguments will be ignored. If provided, user has to take care of
            closing the port.

    Keyword Args:
        skip_connect (bool): Whether to skip connecting to the chip. Default is False.
        virt (bool): Whether to use virtual mode. Default is False.
        debug (bool): Whether to enable debug mode. Default is False.
        virt_efuse_file (str): The file to save the eFuse values to. Default is None.
        do_not_confirm (bool): Whether to skip confirmation before burning eFuse.
            Default is False.
        extend_efuse_table (str): The file to extend the eFuse table from.
            Default is None.
        batch_mode (bool): Whether to enable batch mode. Default is False.

    Returns:
        The ESP eFuse commands class
    """
    skip_connect = kwargs.get("skip_connect", False)
    virt = kwargs.get("virt", False)
    debug = kwargs.get("debug", False)
    virt_efuse_file = kwargs.get("virt_efuse_file", None)
    do_not_confirm = kwargs.get("do_not_confirm", False)
    extend_efuse_table = kwargs.get("extend_efuse_table", None)
    external_esp = esp is not None
    batch_mode = kwargs.get("batch_mode", False)

    if esp is None:
        esp = get_esp(
            port, baud, before, chip, skip_connect, virt, debug, virt_efuse_file
        )

    try:
        commands = _get_command_class(strip_chip_name(esp.CHIP_NAME))
        commands.esp = esp
        commands.external_esp = external_esp
        commands.get_efuses(
            skip_connect=skip_connect,
            debug_mode=debug,
            do_not_confirm=do_not_confirm,
            extend_efuse_table=extend_efuse_table,
        )
    except Exception:
        # If creating commands fails, ensure the port is closed
        BaseCommands._close_port(esp, external_esp)
        raise
    if batch_mode:
        commands.use_batch_mode()
    return commands


def get_esp(
    port: str | None = None,
    baud: int = 115200,
    before: str = "default-reset",
    chip: str = "auto",
    skip_connect: bool = False,
    virt: bool = False,
    debug: bool = False,
    virt_efuse_file: str | None = None,
) -> esptool.ESPLoader | EmulateEfuseControllerBase:
    """Get the ESPLoader object for the given chip.
    Uses :func:`esptool.cmds.detect_chip` function.

    Args:
        port: The port to connect to the chip
        baud: The baud rate to connect to the chip
        before: The reset mode to use before connecting to the chip
            Supported values are: "default-reset", "usb-reset", "no-reset",
            "no-reset-no-sync"
        chip: The chip to use
        skip_connect: Whether to skip connecting to the chip
        virt: Whether to use virtual mode
        debug: Whether to enable debug mode
        virt_efuse_file: The file to save the eFuse values to

    Returns:
        The ESPLoader object or EmulateEfuseController object
    """
    if chip not in ["auto"] + list(SUPPORTED_CHIPS.keys()):
        raise esptool.FatalError(f"get_esp: Unsupported chip ({chip})")

    if virt:
        efuse = SUPPORTED_CHIPS.get(chip, SUPPORTED_CHIPS["esp32"]).efuse_lib
        return efuse.EmulateEfuseController(virt_efuse_file, debug)  # type: ignore

    if chip == "auto" and not skip_connect:
        if port is None:
            raise esptool.FatalError(
                "get_esp: Port is required when chip is 'auto' to detect the chip"
            )
        return esptool.detect_chip(port, baud, before)

    esp = SUPPORTED_CHIPS.get(chip, SUPPORTED_CHIPS["esp32"]).chip_class(
        port if not skip_connect else StringIO(),  # type: ignore
        baud,
    )
    if not skip_connect:
        esp.connect(before)
        if esp.sync_stub_detected:
            esp = esp.STUB_CLASS(esp)  # type: ignore
    return esp
