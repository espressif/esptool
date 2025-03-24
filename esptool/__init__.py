# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

__all__ = [
    "chip_id",
    "detect_chip",
    "dump_mem",
    "elf2image",
    "erase_flash",
    "erase_region",
    "flash_id",
    "attach_flash",
    "get_security_info",
    "image_info",
    "load_ram",
    "merge_bin",
    "read_flash",
    "read_flash_status",
    "read_flash_sfdp",
    "read_mac",
    "read_mem",
    "reset_chip",
    "run",
    "run_stub",
    "verify_flash",
    "version",
    "write_flash",
    "write_flash_status",
    "write_mem",
]

__version__ = "4.8.1"

import os
import shlex
import sys
import time
import traceback
import rich_click as click
import typing as t

from esptool.cmds import (
    chip_id,
    detect_chip,
    dump_mem,
    elf2image,
    erase_flash,
    erase_region,
    attach_flash,
    flash_id,
    read_flash_sfdp,
    get_security_info,
    image_info,
    load_ram,
    merge_bin,
    read_flash,
    read_flash_status,
    read_mac,
    read_mem,
    reset_chip,
    run,
    run_stub,
    verify_flash,
    version,
    write_flash,
    write_flash_status,
    write_mem,
)
from esptool.config import load_config_file
from esptool.loader import (
    DEFAULT_CONNECT_ATTEMPTS,
    DEFAULT_OPEN_PORT_ATTEMPTS,
    StubFlasher,
    ESPLoader,
    list_ports,
)
from esptool.logger import log
from esptool.targets import CHIP_DEFS, CHIP_LIST, ESP32ROM
from esptool.util import (
    FatalError,
    NotImplementedInROMError,
)
from itertools import chain, cycle, repeat

import serial

from esptool.cli_util import (
    AutoSizeType,
    Group,
    AddrFilenameArg,
    AutoChunkSizeType,
    ChipType,
    AnyIntType,
    OptionEatAll,
    MutuallyExclusiveOption,
    ResetModeType,
    SpiConnectionType,
    AutoHex2BinType,
    AddrFilenamePairType,
    parse_port_filters,
    parse_size_arg,
)

# Show arguments in the help output, this was default in argparse
click.rich_click.SHOW_ARGUMENTS = True
# Force alignment of commands table with groups
click.rich_click.STYLE_COMMANDS_TABLE_COLUMN_WIDTH_RATIO = (1, 3)
# Option group definitions, used for grouping options in the help output
# Similar to 'add_argument_group' from argparse
click.rich_click.OPTION_GROUPS = {
    "esptool.py merge-bin": [
        {
            "name": "UF2 options",
            "options": [
                "--chunk-size",
                "--md5-disable",
            ],
        },
        {
            "name": "RAW options",
            "options": [
                "--target-offset",
                "--pad-to-size",
            ],
        },
    ],
    "*": [
        {
            "name": "Flash options",
            "options": [
                "--flash-freq",
                "--flash-mode",
                "--flash-size",
                "--spi-connection",
            ],
        }
    ],
}
click.rich_click.COMMAND_GROUPS = {
    "esptool.py": [
        {
            "name": "Basic commands",
            "commands": [
                "write-flash",
                "read-flash",
                "erase-flash",
                "erase-region",
                "read-mac",
                "flash-id",
                "elf2image",
                "image-info",
                "merge-bin",
                "version",
            ],
        },
        {
            "name": "Advanced commands",
            "commands": [
                "verify-flash",
                "load-ram",
                "dump-mem",
                "read-mem",
                "write-mem",
                "read-flash-status",
                "write-flash-status",
                "read-flash-sfdp",
                "get-security-info",
                "chip-id",
                "run",
            ],
        },
    ],
}

################################### REUSABLE OPTIONS ###################################


def add_spi_connection_arg(function):
    function = click.option(
        "--spi-connection",
        "-sc",
        help="Override default SPI flash memory connection. "
        "Value can be SPI, HSPI or a comma-separated list of 5 I/O numbers "
        "to use for SPI flash (CLK,Q,D,HD,CS). Not supported with ESP8266.",
        type=SpiConnectionType(),
    )(function)
    return function


def add_spi_flash_options(
    allow_keep: bool = False, auto_detect: bool = False, size_only: bool = False
) -> t.Callable:
    """Add common parser arguments for SPI flash properties"""

    extra_keep_args = ["keep"] if allow_keep else []

    flash_sizes = []
    if auto_detect:
        flash_sizes.append("detect")
    if allow_keep:
        flash_sizes.append("keep")

    def wrapper(function):
        if not size_only:
            function = click.option(
                "--flash-freq",
                "-ff",
                help="SPI flash memory frequency.",
                type=click.Choice(
                    extra_keep_args
                    + [
                        "80m",
                        "60m",
                        "48m",
                        "40m",
                        "30m",
                        "26m",
                        "24m",
                        "20m",
                        "16m",
                        "15m",
                        "12m",
                    ]
                ),
                default=os.environ.get("ESPTOOL_FF", "keep" if allow_keep else None),
            )(function)
            function = click.option(
                "--flash-mode",
                "-fm",
                help="SPI flash memory mode.",
                type=click.Choice(extra_keep_args + ["qio", "qout", "dio", "dout"]),
                default=os.environ.get("ESPTOOL_FM", "keep" if allow_keep else "qio"),
            )(function)

        function = click.option(
            "--flash-size",
            "-fs",
            help="SPI flash memory size. "
            "ESP8266-only sizes: 256KB, 512KB, 2MB-c1, 4MB-c1.",
            type=click.Choice(
                flash_sizes
                + [
                    "256KB",
                    "512KB",
                    "1MB",
                    "2MB",
                    "2MB-c1",
                    "4MB",
                    "4MB-c1",
                    "8MB",
                    "16MB",
                    "32MB",
                    "64MB",
                    "128MB",
                ]
            ),
            default=os.environ.get("ESPTOOL_FS", "keep" if allow_keep else "1MB"),
        )(function)
        return function

    return wrapper


def check_flash_size(esp: ESPLoader, address: int, size: int) -> None:
    # Check if we are writing/erasing/reading past 16MB boundary
    if not (esp.IS_STUB and esp.CHIP_NAME == "ESP32-S3") and address + size > 0x1000000:
        raise FatalError(
            f"Can't access flash regions larger than 16MB "
            f"(set size {size:#x} from address {address:#010x} goes past 16MB "
            f"by {address + size - 0x1000000:#x} bytes)."
        )


############################### GLOBAL OPTIONS AND MAIN ###############################


@click.group(
    cls=Group,
    no_args_is_help=True,
    context_settings=dict(help_option_names=["-h", "--help"], max_content_width=120),
    help=f"esptool.py v{__version__} - serial utility for flashing, provisioning, "
    "and interacting with Espressif SoCs.",
)
@click.option(
    "--chip",
    "-c",
    type=ChipType(["auto"] + CHIP_LIST),
    default=os.environ.get("ESPTOOL_CHIP", "auto"),
    help="Target chip type.",
)
@click.option(
    "--port",
    "-p",
    default=os.environ.get("ESPTOOL_PORT", None),
    help="Serial port device.",
)
@click.option(
    "--baud",
    "-b",
    type=AnyIntType(),
    default=os.environ.get("ESPTOOL_BAUD", ESPLoader.ESP_ROM_BAUD),
    help="Serial port baud rate used when flashing/reading.",
)
@click.option(
    "--port-filter",
    multiple=True,
    type=str,
    cls=OptionEatAll,
    help="Serial port device filter, can be vid=NUMBER, pid=NUMBER, name=SUBSTRING, "
    "serial=SUBSTRING.",
)
@click.option(
    "--before",
    type=ResetModeType(["default-reset", "usb-reset", "no-reset", "no-reset-no-sync"]),
    default=os.environ.get("ESPTOOL_BEFORE", "default-reset"),
    help="Which reset to perform before connecting to the chip.",
)
@click.option(
    "--after",
    "-a",
    type=ResetModeType(
        ["hard-reset", "soft-reset", "no-reset", "no-reset-stub", "watchdog-reset"]
    ),
    default=os.environ.get("ESPTOOL_AFTER", "hard-reset"),
    help="Which reset to perform after operation is finished.",
)
@click.option(
    "--no-stub",
    is_flag=True,
    help="Disable launching the flasher stub, only talk to ROM bootloader. "
    "Some features will not be available.",
)
# --stub-version can be set with --no-stub so the tests wouldn't fail if this option
# is implied globally
@click.option(
    "--stub-version",
    default=os.environ.get("ESPTOOL_STUB_VERSION", StubFlasher.STUB_SUBDIRS[0]),
    type=click.Choice(StubFlasher.STUB_SUBDIRS),
    # not a public option and is not subject to the semantic versioning policy
    hidden=True,
)
@click.option(
    "--trace",
    "-t",
    is_flag=True,
    help="Enable trace-level output of esptool.py interactions.",
)
@click.option(
    "--override-vddsdio",
    type=click.Choice(ESP32ROM.OVERRIDE_VDDSDIO_CHOICES),
    help="Override ESP32 VDDSDIO internal voltage regulator (use with care).",
)
@click.option(
    "--connect-attempts",
    type=int,
    default=os.environ.get("ESPTOOL_CONNECT_ATTEMPTS", DEFAULT_CONNECT_ATTEMPTS),
    help=f"Number of attempts to connect, negative or 0 for infinite. "
    f"Default: {DEFAULT_CONNECT_ATTEMPTS}.",
)
@click.pass_context
def cli(
    ctx,
    **kwargs,
):
    ctx.ensure_object(dict)
    ctx.obj.update(kwargs)
    ctx.obj["invoked_subcommand"] = ctx.invoked_subcommand
    ctx.obj["esp"] = getattr(ctx, "esp", None)
    log.print(f"esptool.py v{__version__}")
    load_config_file(verbose=True)


def prepare_esp_object(ctx):
    """Prepare ESP object for operation"""
    StubFlasher.set_preferred_stub_subdir(ctx.obj["stub_version"])
    # Commands that require an ESP object (flash read/write, etc.)
    # 1) Get the ESP object
    #######################

    # Disable output stage collapsing, colors, and overwriting in trace mode
    if ctx.obj["trace"]:
        log._smart_features = False

    log.stage()

    if ctx.obj["before"] != "no-reset-no-sync":
        initial_baud = min(
            ESPLoader.ESP_ROM_BAUD, ctx.obj["baud"]
        )  # don't sync faster than the default baud rate
    else:
        initial_baud = ctx.obj["baud"]

    if ctx.obj["port"] is None:
        filters = parse_port_filters(ctx.obj["port_filter"])
        ser_list = get_port_list(*filters)
        log.print(f"Found {len(ser_list)} serial ports...")
    else:
        ser_list = [ctx.obj["port"]]
    open_port_attempts = os.environ.get(
        "ESPTOOL_OPEN_PORT_ATTEMPTS", DEFAULT_OPEN_PORT_ATTEMPTS
    )
    try:
        open_port_attempts = int(open_port_attempts)
    except ValueError:
        raise SystemExit("Invalid value for ESPTOOL_OPEN_PORT_ATTEMPTS.")

    esp = ctx.obj.get("esp", None)
    ctx.obj["external_esp"] = esp is not None
    if open_port_attempts != 1:
        if ctx.obj["port"] is None or ctx.obj["chip"] == "auto":
            log.warning(
                "The ESPTOOL_OPEN_PORT_ATTEMPTS (open_port_attempts) option "
                "can only be used with --port and --chip arguments."
            )
        else:
            esp = esp or connect_loop(
                ctx.obj["port"],
                initial_baud,
                ctx.obj["chip"],
                open_port_attempts,
                ctx.obj["trace"],
                ctx.obj["before"],
            )
    esp = esp or get_default_connected_device(
        ser_list,
        port=ctx.obj["port"],
        connect_attempts=ctx.obj["connect_attempts"],
        initial_baud=initial_baud,
        chip=ctx.obj["chip"],
        trace=ctx.obj["trace"],
        before=ctx.obj["before"],
    )

    if esp is None:
        raise FatalError(
            "Could not connect to an Espressif device "
            f"on any of the {len(ser_list)} available serial ports."
        )

    log.stage(finish=True)
    log.print(f"Connected to {esp.CHIP_NAME} on {esp._port.port}:")

    # 2) Print the chip info
    ########################

    if esp.secure_download_mode:
        log.print(f"{'Chip type:':<20}{esp.CHIP_NAME} in Secure Download Mode")
    else:
        log.print(f"{'Chip type:':<20}{esp.get_chip_description()}")
        log.print(f"{'Features:':<20}{', '.join(esp.get_chip_features())}")
        log.print(f"{'Crystal frequency:':<20}{esp.get_crystal_freq()}MHz")
        usb_mode = esp.get_usb_mode()
        if usb_mode is not None:
            log.print(f"{'USB mode:':<20}{usb_mode}")
        read_mac(esp)
    log.print()

    # 3) Perform sanity checks
    ##########################

    if esp.secure_download_mode and ctx.obj["invoked_subcommand"] not in (
        "get-security-info",
        "write-flash",
        "erase-region",
    ):
        raise FatalError(
            f"The '{ctx.obj['invoked_subcommand']}' command is not available "
            "in Secure Download Mode."
        )

    # 4) Upload the stub flasher
    ############################

    if not ctx.obj["no_stub"]:
        esp = run_stub(esp)

    # 5) Configure the baud rate and voltage regulator
    ##################################################

    if ctx.obj["override_vddsdio"]:
        esp.override_vddsdio(ctx.obj["override_vddsdio"])

    if ctx.obj["baud"] > initial_baud:
        try:
            esp.change_baud(ctx.obj["baud"])
        except NotImplementedInROMError:
            log.warning(
                f"ROM doesn't support changing baud rate. "
                f"Keeping initial baud rate {initial_baud}."
            )

    # 6) Prepare to run the operation
    #################################
    # Running operation is done inside each command function, as they have different
    # arguments and behaviour
    # Prepare object for operation (commands)
    ctx.obj["esp"] = esp
    log.print()

    # 7) Attach the onboard/external flash chip and perform command
    ###############################################################
    # This will follow in command-specific functions or argument processing decorators
    # After the command is done (either successfully or with an error), the following
    # teardown function will be called

    @ctx.call_on_close
    def teardown():
        """Common teardown for all commands with chip - reset chip and close port"""
        # 8) Close all open files
        #########################
        for f in getattr(ctx, "_open_files", []):
            f.close()

        # 9) Reset the chip
        ###################
        log.print()
        # Handle post-operation behaviour (reset or other)
        if ctx.obj["invoked_subcommand"] == "load-ram":
            # the ESP is now running the loaded image, so let it run
            log.print("Exiting immediately.")
        else:
            reset_chip(esp, ctx.obj["after"])

        # 10) Finish and close the port
        ##############################

        if not ctx.obj["external_esp"]:
            esp._port.close()


###################################### COMMANDS #######################################


@cli.command("load-ram")
@click.argument("filename", type=AutoHex2BinType())
@click.pass_context
def load_ram_cli(ctx, filename):
    """Download an image to RAM and execute."""
    prepare_esp_object(ctx)
    load_ram(ctx.obj["esp"], filename)


@cli.command("dump-mem")
@click.argument("address", type=AnyIntType())
@click.argument("size", type=AnyIntType())
@click.argument("output", type=click.Path())
@click.pass_context
def dump_mem_cli(ctx, address, size, output):
    """Dump arbitrary memory to a file."""
    prepare_esp_object(ctx)
    dump_mem(ctx.obj["esp"], address, size, output)


@cli.command("read-mem")
@click.argument("address", type=AnyIntType())
@click.pass_context
def read_mem_cli(ctx, address):
    """Read arbitrary memory location."""
    prepare_esp_object(ctx)
    read_mem(ctx.obj["esp"], address)


@cli.command("write-mem")
@click.argument("address", type=AnyIntType())
@click.argument("value", type=AnyIntType())
@click.argument("mask", type=AnyIntType(), default=0xFFFFFFFF)
@click.pass_context
def write_mem_cli(ctx, address, value, mask):
    """Modify or write to arbitrary memory location."""
    prepare_esp_object(ctx)
    write_mem(ctx.obj["esp"], address, value, mask)


@cli.command(name="write-flash")
@click.argument("addr-filename", nargs=-1, required=True, cls=AddrFilenameArg)
@click.option(
    "--erase-all",
    "-e",
    is_flag=True,
    help="Erase all regions of flash (not just write areas) before programming.",
)
@click.option("--no-progress", "-p", is_flag=True, help="Suppress progress output.")
@click.option(
    "--encrypt",
    is_flag=True,
    help="Apply flash encryption when writing data (required correct eFuse settings).",
)
@click.option(
    "--encrypt-files",
    type=AddrFilenamePairType(),
    cls=OptionEatAll,
    help="Files to be encrypted during flashing. The address is followed by binary "
    "filename, separated by space.",
)
@click.option(
    "--ignore-flash-enc-efuse",
    is_flag=True,
    help="Ignore flash encryption eFuse settings.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Force write, skip security and compatibility checks. Use with caution!",
)
@click.option(
    "--compress",
    "-z",
    is_flag=True,
    help="Compress data during transfer (default unless --no-stub is specified).",
    exclusive_with=["no-compress"],
    cls=MutuallyExclusiveOption,
)
@click.option(
    "--no-compress",
    "-u",
    is_flag=True,
    default=False,
    help="Disable data compression during transfer (default if --no-stub is specified)",
    exclusive_with=["compress"],
    cls=MutuallyExclusiveOption,
)
@add_spi_flash_options(allow_keep=True, auto_detect=True)
@add_spi_connection_arg
@click.pass_context
def write_flash_cli(ctx, addr_filename, **kwargs):
    """Write a binary blob to flash. The address is followed by binary filename,
    separated by space."""
    # Forbid the usage of both --encrypt, which means encrypt all the given files,
    # and --encrypt-files, which represents the list of files to encrypt.
    # The reason is that allowing both at the same time increases the chances of
    # having contradictory lists (e.g. one file not available in one of list).
    if kwargs["encrypt"] and kwargs["encrypt_files"] is not None:
        raise FatalError(
            "Options --encrypt and --encrypt-files "
            "must not be specified at the same time."
        )
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    write_flash(ctx.obj["esp"], addr_filename, **kwargs)


@cli.command("run")
@click.pass_context
def run_cli(ctx):
    """Run application code loaded in flash."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"])
    run(ctx.obj["esp"])


@cli.command("image-info")
@click.argument("filename", type=AutoHex2BinType())
@click.pass_context
def image_info_cli(ctx, filename):
    """Print information about a firmware image (bootloader or application)."""
    image_info(filename, chip=None if ctx.obj["chip"] == "auto" else ctx.obj["chip"])


@cli.command("elf2image")
@click.argument("filename", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=str,
    help="Output filename or filename prefix (for ESP8266 v1 image).",
)
@click.option(
    "--version",
    "-e",
    type=click.Choice(["1", "2", "3"]),
    default="1",
    help="Output image version.",
)
@click.option(
    # Kept for compatibility
    # Minimum chip revision (deprecated, consider using --min-rev-full)
    "--min-rev",
    "-r",
    type=click.IntRange(0, 256),
    default=0,
    hidden=True,
)
@click.option(
    "--min-rev-full",
    type=click.IntRange(0, 65536),
    default=0,
    help="Minimal chip revision (in format: major * 100 + minor).",
)
@click.option(
    "--max-rev-full",
    type=click.IntRange(0, 65536),
    default=65535,
    help="Maximal chip revision (in format: major * 100 + minor).",
)
@click.option(
    "--secure-pad",
    is_flag=True,
    help="Pad image so once signed it will end on a 64KB boundary. For Secure Boot "
    "v1 images only.",
)
@click.option(
    "--secure-pad-v2",
    is_flag=True,
    help="Pad image to 64KB, so once signed its signature sector will start at the "
    "next 64K block. For Secure Boot v2 images only.",
)
@click.option(
    "--elf-sha256-offset",
    type=AnyIntType(),
    default=None,
    help="If set, insert SHA256 hash (32 bytes) of the input ELF file at specified "
    "offset in the binary.",
)
@click.option(
    "--dont-append-digest",
    is_flag=True,
    default=False,
    help="Don't append a SHA256 digest of the entire image after the checksum. "
    "This argument is not supported and ignored for ESP8266.",
)
@click.option(
    "--use-segments",
    is_flag=True,
    help="If set, ELF segments will be used instead of ELF sections to generate the "
    "image.",
)
@click.option(
    "--flash-mmu-page-size",
    type=click.Choice(["64KB", "32KB", "16KB", "8KB"]),
    help="Change flash MMU page size.",
)
@click.option(
    "--pad-to-size",
    type=int,
    default=None,
    help="The block size to pad the final binary image to. "
    "Value 0xFF is used for padding.",
)
@click.option(
    "--ram-only-header",
    is_flag=True,
    help="Order segments so IRAM and DRAM are placed at the beginning "
    "and force the main header segment number to RAM segments quantity. This will "
    "make the other segments invisible to the ROM loader. Use with "
    "care, the ROM loader will only load the RAM segments although the other "
    "segments being present in the output. Implies --dont-append-digest.",
)
@add_spi_flash_options(allow_keep=False, auto_detect=False)
@click.pass_context
def elf2image_cli(ctx, filename, **kwargs):
    """Create an application image from ELF file"""
    if ctx.obj["chip"] == "auto":
        raise FatalError(
            f"Specify the --chip argument (choose from {', '.join(CHIP_LIST)})."
        )
    append_digest = not kwargs.pop("dont_append_digest", False)
    output = kwargs.pop("output", None)
    output = "auto" if output is None else output
    elf2image(filename, ctx.obj["chip"], output, append_digest=append_digest, **kwargs)


@cli.command("read-mac")
@click.pass_context
def read_mac_cli(ctx):
    """Print the device MAC address."""
    prepare_esp_object(ctx)
    read_mac(ctx.obj["esp"])


@cli.command("chip-id")
@click.pass_context
def chip_id_cli(ctx):
    """Print the device chip ID."""
    prepare_esp_object(ctx)
    chip_id(ctx.obj["esp"])


@cli.command("flash-id")
@add_spi_connection_arg
@click.pass_context
def flash_id_cli(ctx, **kwargs):
    """Print the SPI flash memory manufacturer and device ID."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    flash_id(ctx.obj["esp"])


@cli.command("read-flash-status")
@click.option(
    "--bytes",
    type=click.Choice(["1", "2", "3"]),
    default="2",
    help="Number of status bytes to read (1-3).",
)
@add_spi_connection_arg
@click.pass_context
def read_flash_status_cli(ctx, bytes, **kwargs):
    """Read SPI flash memory status register."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    read_flash_status(ctx.obj["esp"], int(bytes))


@cli.command("write-flash-status")
@click.option(
    "--non-volatile",
    is_flag=True,
    help="Write non-volatile bits (use with caution).",
)
@click.option(
    "--bytes",
    type=click.Choice(["1", "2", "3"]),
    default="2",
    help="Number of status bytes to write (1-3).",
)
@click.argument("value", type=AnyIntType())
@add_spi_connection_arg
@click.pass_context
def write_flash_status_cli(ctx, value, bytes, **kwargs):
    """Write SPI flash memory status register."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    write_flash_status(ctx.obj["esp"], value, int(bytes), **kwargs)


@cli.command("read-flash")
@click.argument("address", type=AnyIntType())
@click.argument("size", type=AutoSizeType())
@click.argument("output", type=click.Path())
@click.option("--no-progress", "-p", is_flag=True, help="Suppress progress output.")
@add_spi_flash_options(allow_keep=True, auto_detect=True, size_only=True)
@add_spi_connection_arg
@click.pass_context
def read_flash_cli(ctx, address, size, output, **kwargs):
    """Read SPI flash memory content."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    size = parse_size_arg(ctx.obj["esp"], size)
    check_flash_size(ctx.obj["esp"], address, size)
    read_flash(ctx.obj["esp"], address, size, output, **kwargs)


@cli.command("verify-flash")
@click.argument("addr-filename", nargs=-1, required=True, cls=AddrFilenameArg)
@click.option("--diff", "-d", is_flag=True, help="Show differences.")
@add_spi_flash_options(allow_keep=True, auto_detect=True)
@add_spi_connection_arg
@click.pass_context
def verify_flash_cli(ctx, addr_filename, diff, **kwargs):
    """Verify a binary blob against the flash memory content."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    verify_flash(ctx.obj["esp"], addr_filename, diff=diff, **kwargs)


@cli.command("erase-flash")
@click.option(
    "--force",
    is_flag=True,
    help="Erase flash even if security features are enabled. Use with caution!",
)
@add_spi_connection_arg
@click.pass_context
def erase_flash_cli(ctx, force, **kwargs):
    """Erase the SPI flash memory."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    erase_flash(ctx.obj["esp"], force)


@cli.command("erase-region")
@click.option(
    "--force",
    is_flag=True,
    help="Erase region even if security features are enabled. Use with caution!",
)
@click.argument("address", type=AnyIntType())
@click.argument("size", type=AutoSizeType())
@click.option(
    "--force",
    is_flag=True,
    help="Erase region even if security features are enabled. Use with caution!",
)
@add_spi_connection_arg
@click.pass_context
def erase_region_cli(ctx, address, size, force, **kwargs):
    """Erase a region of the SPI flash memory."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    size = parse_size_arg(ctx.obj["esp"], size)
    check_flash_size(ctx.obj["esp"], address, size)
    erase_region(ctx.obj["esp"], address, size, force)


@cli.command("read-flash-sfdp")
@click.argument("address", type=AnyIntType())
@click.argument("bytes", type=AnyIntType())
@add_spi_flash_options(allow_keep=True, auto_detect=True)
@add_spi_connection_arg
@click.pass_context
def read_flash_sfdp_cli(ctx, address, bytes, **kwargs):
    """Read SPI flash SFDP (Serial Flash Discoverable Parameters)."""
    prepare_esp_object(ctx)
    attach_flash(ctx.obj["esp"], kwargs.pop("spi_connection", None))
    read_flash_sfdp(ctx.obj["esp"], address, bytes)


@cli.command("merge-bin")
@click.argument("addr-filename", nargs=-1, required=True, cls=AddrFilenameArg)
@click.option("--output", "-o", type=str, required=True, help="Output filename.")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["raw", "uf2", "hex"]),
    default="raw",
    help="Format of the output file.",
)
@click.option(  # UF2 only
    "--chunk-size",
    type=AutoChunkSizeType(),
    help="Specify the used data part of the 512 byte UF2 block. A common value is 256. "
    "By default the largest possible value will be used.",
)
@click.option(  # UF2 only
    "--md5-disable",
    is_flag=True,
    help="Disable MD5 checksum in UF2 output.",
)
@click.option(  # RAW only
    "--target-offset",
    "-t",
    type=AnyIntType(),
    default=0,
    help="Target offset where the output file will be flashed.",
)
@click.option(  # RAW only
    "--pad-to-size",
    type=click.Choice(
        ["256KB", "512KB", "1MB", "2MB", "4MB", "8MB", "16MB", "32MB", "64MB", "128MB"]
    ),
    help="If set, the final binary file will be padded with 0xFF bytes up to this flash"
    " size.",
)
@add_spi_flash_options(allow_keep=True, auto_detect=False)
@click.pass_context
def merge_bin_cli(ctx, addr_filename, **kwargs):
    """Merge multiple raw binary files into a single flashable file."""
    if ctx.obj["chip"] == "auto":
        raise FatalError(
            f"Specify the --chip argument (choose from {', '.join(CHIP_LIST)})."
        )
    merge_bin(addr_filename, chip=ctx.obj["chip"], **kwargs)


@cli.command("get-security-info")
@click.pass_context
def get_security_info_cli(ctx):
    """Print security information report."""
    prepare_esp_object(ctx)
    get_security_info(ctx.obj["esp"])


@cli.command("version")
def version_cli():
    """Print esptool version."""
    version()


def main(argv: list[str] | None = None, esp: ESPLoader | None = None):
    """
    Main function for esptool

    argv - Optional override for default arguments parsing (that uses sys.argv),
    can be a list of custom arguments as strings. Arguments and their values
    need to be added as individual items to the list
    e.g. "-b 115200" thus becomes ['-b', '115200'].

    esp - Optional override of the connected device previously
    returned by get_default_connected_device()
    """
    args = expand_file_arguments(argv or sys.argv[1:])
    cli(args=args, esp=esp)


def get_port_list(
    vids: list[str] = [],
    pids: list[str] = [],
    names: list[str] = [],
    serials: list[str] = [],
) -> list[str]:
    if list_ports is None:
        raise FatalError(
            "Listing all serial ports is currently not available. "
            "Please try to specify the port when running esptool.py or update "
            "the pyserial package to the latest version."
        )
    ports = []
    for port in list_ports.comports():
        if sys.platform == "darwin" and port.device.endswith(
            ("Bluetooth-Incoming-Port", "wlan-debug")
        ):
            continue
        if vids and (port.vid is None or port.vid not in vids):
            continue
        if pids and (port.pid is None or port.pid not in pids):
            continue
        if names and (
            port.name is None or all(name not in port.name for name in names)
        ):
            continue
        if serials and (
            port.serial_number is None
            or all(serial not in port.serial_number for serial in serials)
        ):
            continue
        ports.append(port.device)
    return sorted(ports)


def expand_file_arguments(argv: list[str]) -> list[str]:
    """
    Any argument starting with "@" gets replaced with all values read from a text file.
    Text file arguments can be split by newline or by space.
    Values are added "as-is", as if they were specified in this order
    on the command line.
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
        log.print(f"esptool.py {' '.join(new_args)}")
        return new_args
    return argv


def connect_loop(
    port: str,
    initial_baud: int,
    chip: str,
    max_retries: int,
    trace: bool = False,
    before: str = "default-reset",
):
    chip_class = CHIP_DEFS[chip]
    esp = None
    log.print(f"Serial port {port}:")

    first = True
    ten_cycle = cycle(chain(repeat(False, 9), (True,)))
    retry_loop = chain(
        repeat(False, max_retries - 1), (True,) if max_retries else cycle((False,))
    )

    for last, every_tenth in zip(retry_loop, ten_cycle):
        try:
            esp = chip_class(port, initial_baud, trace)
            if not first:
                # break the retrying line
                log.print("")
            esp.connect(before)
            return esp
        except (
            FatalError,
            serial.serialutil.SerialException,
            IOError,
            OSError,
        ) as err:
            if esp and esp._port:
                esp._port.close()
            esp = None
            if first:
                log.print(err)
                log.print("Retrying failed connection", end="", flush=True)
                first = False
            if last:
                raise err
            if every_tenth:
                # print a dot every second
                log.print(".", end="", flush=True)
            time.sleep(0.1)


def get_default_connected_device(
    serial_list: list[str],
    port: str,
    connect_attempts: int,
    initial_baud: int,
    chip: str = "auto",
    trace: bool = False,
    before: str = "default-reset",
):
    _esp = None
    for each_port in reversed(serial_list):
        log.print(f"Serial port {each_port}:")
        try:
            if chip == "auto":
                _esp = detect_chip(
                    each_port, initial_baud, before, trace, connect_attempts
                )
            else:
                chip_class = CHIP_DEFS[chip]
                _esp = chip_class(each_port, initial_baud, trace)
                _esp.connect(before, connect_attempts)
            break
        except (FatalError, OSError) as err:
            if port is not None:
                raise
            log.error(f"{each_port} failed to connect: {err}")
            if _esp and _esp._port:
                _esp._port.close()
            _esp = None
    return _esp


def _main():
    try:
        main()
    except FatalError as e:
        log.error(f"\nA fatal error occurred: {e}")
        sys.exit(2)
    except serial.serialutil.SerialException as e:
        log.error(f"\nA serial exception error occurred: {e}")
        log.error(
            "Note: This error originates from pySerial. "
            "It is likely not a problem with esptool, "
            "but with the hardware connection or drivers."
        )
        log.error(
            "For troubleshooting steps visit: "
            "https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html"
        )
        sys.exit(1)
    except StopIteration:
        log.error(traceback.format_exc())
        log.error("A fatal error occurred: The chip stopped responding.")
        sys.exit(2)
    except KeyboardInterrupt:
        log.error("KeyboardInterrupt: Run cancelled by user.")
        sys.exit(2)


if __name__ == "__main__":
    _main()
