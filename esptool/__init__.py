# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
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
    "get_security_info",
    "image_info",
    "load_ram",
    "make_image",
    "merge_bin",
    "read_flash",
    "read_flash_status",
    "read_mac",
    "read_mem",
    "run",
    "verify_flash",
    "version",
    "write_flash",
    "write_flash_status",
    "write_mem",
]

__version__ = "4.7.0"

import argparse
import inspect
import os
import shlex
import sys
import time
import traceback

from esptool.bin_image import intel_hex_to_bin
from esptool.cmds import (
    DETECTED_FLASH_SIZES,
    chip_id,
    detect_chip,
    detect_flash_size,
    dump_mem,
    elf2image,
    erase_flash,
    erase_region,
    flash_id,
    get_security_info,
    image_info,
    load_ram,
    make_image,
    merge_bin,
    read_flash,
    read_flash_status,
    read_mac,
    read_mem,
    run,
    verify_flash,
    version,
    write_flash,
    write_flash_status,
    write_mem,
)
from esptool.config import load_config_file
from esptool.loader import DEFAULT_CONNECT_ATTEMPTS, ESPLoader, list_ports
from esptool.targets import CHIP_DEFS, CHIP_LIST, ESP32ROM
from esptool.util import (
    FatalError,
    NotImplementedInROMError,
    flash_size_bytes,
    strip_chip_name,
)

import serial


def main(argv=None, esp=None):
    """
    Main function for esptool

    argv - Optional override for default arguments parsing (that uses sys.argv),
    can be a list of custom arguments as strings. Arguments and their values
    need to be added as individual items to the list
    e.g. "-b 115200" thus becomes ['-b', '115200'].

    esp - Optional override of the connected device previously
    returned by get_default_connected_device()
    """

    external_esp = esp is not None

    parser = argparse.ArgumentParser(
        description="esptool.py v%s - Espressif chips ROM Bootloader Utility"
        % __version__,
        prog="esptool",
    )

    parser.add_argument(
        "--chip",
        "-c",
        help="Target chip type",
        type=strip_chip_name,
        choices=["auto"] + CHIP_LIST,
        default=os.environ.get("ESPTOOL_CHIP", "auto"),
    )

    parser.add_argument(
        "--port",
        "-p",
        help="Serial port device",
        default=os.environ.get("ESPTOOL_PORT", None),
    )

    parser.add_argument(
        "--baud",
        "-b",
        help="Serial port baud rate used when flashing/reading",
        type=arg_auto_int,
        default=os.environ.get("ESPTOOL_BAUD", ESPLoader.ESP_ROM_BAUD),
    )

    parser.add_argument(
        "--before",
        help="What to do before connecting to the chip",
        choices=["default_reset", "usb_reset", "no_reset", "no_reset_no_sync"],
        default=os.environ.get("ESPTOOL_BEFORE", "default_reset"),
    )

    parser.add_argument(
        "--after",
        "-a",
        help="What to do after esptool.py is finished",
        choices=["hard_reset", "soft_reset", "no_reset", "no_reset_stub"],
        default=os.environ.get("ESPTOOL_AFTER", "hard_reset"),
    )

    parser.add_argument(
        "--no-stub",
        help="Disable launching the flasher stub, only talk to ROM bootloader. "
        "Some features will not be available.",
        action="store_true",
    )

    parser.add_argument(
        "--trace",
        "-t",
        help="Enable trace-level output of esptool.py interactions.",
        action="store_true",
    )

    parser.add_argument(
        "--override-vddsdio",
        help="Override ESP32 VDDSDIO internal voltage regulator (use with care)",
        choices=ESP32ROM.OVERRIDE_VDDSDIO_CHOICES,
        nargs="?",
    )

    parser.add_argument(
        "--connect-attempts",
        help=(
            "Number of attempts to connect, negative or 0 for infinite. "
            "Default: %d." % DEFAULT_CONNECT_ATTEMPTS
        ),
        type=int,
        default=os.environ.get("ESPTOOL_CONNECT_ATTEMPTS", DEFAULT_CONNECT_ATTEMPTS),
    )

    subparsers = parser.add_subparsers(
        dest="operation", help="Run esptool.py {command} -h for additional help"
    )

    def add_spi_connection_arg(parent):
        parent.add_argument(
            "--spi-connection",
            "-sc",
            help="Override default SPI Flash connection. "
            "Value can be SPI, HSPI or a comma-separated list of 5 I/O numbers "
            "to use for SPI flash (CLK,Q,D,HD,CS). Not supported with ESP8266.",
            action=SpiConnectionAction,
        )

    parser_load_ram = subparsers.add_parser(
        "load_ram", help="Download an image to RAM and execute"
    )
    parser_load_ram.add_argument(
        "filename", help="Firmware image", action=AutoHex2BinAction
    )

    parser_dump_mem = subparsers.add_parser(
        "dump_mem", help="Dump arbitrary memory to disk"
    )
    parser_dump_mem.add_argument("address", help="Base address", type=arg_auto_int)
    parser_dump_mem.add_argument(
        "size", help="Size of region to dump", type=arg_auto_int
    )
    parser_dump_mem.add_argument("filename", help="Name of binary dump")

    parser_read_mem = subparsers.add_parser(
        "read_mem", help="Read arbitrary memory location"
    )
    parser_read_mem.add_argument("address", help="Address to read", type=arg_auto_int)

    parser_write_mem = subparsers.add_parser(
        "write_mem", help="Read-modify-write to arbitrary memory location"
    )
    parser_write_mem.add_argument("address", help="Address to write", type=arg_auto_int)
    parser_write_mem.add_argument("value", help="Value", type=arg_auto_int)
    parser_write_mem.add_argument(
        "mask",
        help="Mask of bits to write",
        type=arg_auto_int,
        nargs="?",
        default="0xFFFFFFFF",
    )

    def add_spi_flash_subparsers(
        parent: argparse.ArgumentParser,
        allow_keep: bool,
        auto_detect: bool,
        size_only: bool = False,
    ):
        """Add common parser arguments for SPI flash properties"""
        extra_keep_args = ["keep"] if allow_keep else []

        if auto_detect and allow_keep:
            extra_fs_message = ", detect, or keep"
            flash_sizes = ["detect", "keep"]
        elif auto_detect:
            extra_fs_message = ", or detect"
            flash_sizes = ["detect"]
        elif allow_keep:
            extra_fs_message = ", or keep"
            flash_sizes = ["keep"]
        else:
            extra_fs_message = ""
            flash_sizes = []

        if not size_only:
            parent.add_argument(
                "--flash_freq",
                "-ff",
                help="SPI Flash frequency",
                choices=extra_keep_args
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
                ],
                default=os.environ.get("ESPTOOL_FF", "keep" if allow_keep else None),
            )
            parent.add_argument(
                "--flash_mode",
                "-fm",
                help="SPI Flash mode",
                choices=extra_keep_args + ["qio", "qout", "dio", "dout"],
                default=os.environ.get("ESPTOOL_FM", "keep" if allow_keep else "qio"),
            )

        parent.add_argument(
            "--flash_size",
            "-fs",
            help="SPI Flash size in MegaBytes "
            "(1MB, 2MB, 4MB, 8MB, 16MB, 32MB, 64MB, 128MB) "
            "plus ESP8266-only (256KB, 512KB, 2MB-c1, 4MB-c1)" + extra_fs_message,
            choices=flash_sizes
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
            ],
            default=os.environ.get("ESPTOOL_FS", "keep" if allow_keep else "1MB"),
        )
        add_spi_connection_arg(parent)

    parser_write_flash = subparsers.add_parser(
        "write_flash", help="Write a binary blob to flash"
    )

    parser_write_flash.add_argument(
        "addr_filename",
        metavar="<address> <filename>",
        help="Address followed by binary filename, separated by space",
        action=AddrFilenamePairAction,
    )
    parser_write_flash.add_argument(
        "--erase-all",
        "-e",
        help="Erase all regions of flash (not just write areas) before programming",
        action="store_true",
    )

    add_spi_flash_subparsers(parser_write_flash, allow_keep=True, auto_detect=True)
    parser_write_flash.add_argument(
        "--no-progress", "-p", help="Suppress progress output", action="store_true"
    )
    parser_write_flash.add_argument(
        "--verify",
        help="Verify just-written data on flash "
        "(mostly superfluous, data is read back during flashing)",
        action="store_true",
    )
    parser_write_flash.add_argument(
        "--encrypt",
        help="Apply flash encryption when writing data "
        "(required correct efuse settings)",
        action="store_true",
    )
    # In order to not break backward compatibility,
    # our list of encrypted files to flash is a new parameter
    parser_write_flash.add_argument(
        "--encrypt-files",
        metavar="<address> <filename>",
        help="Files to be encrypted on the flash. "
        "Address followed by binary filename, separated by space.",
        action=AddrFilenamePairAction,
    )
    parser_write_flash.add_argument(
        "--ignore-flash-encryption-efuse-setting",
        help="Ignore flash encryption efuse settings ",
        action="store_true",
    )
    parser_write_flash.add_argument(
        "--force",
        help="Force write, skip security and compatibility checks. Use with caution!",
        action="store_true",
    )

    compress_args = parser_write_flash.add_mutually_exclusive_group(required=False)
    compress_args.add_argument(
        "--compress",
        "-z",
        help="Compress data in transfer (default unless --no-stub is specified)",
        action="store_true",
        default=None,
    )
    compress_args.add_argument(
        "--no-compress",
        "-u",
        help="Disable data compression during transfer "
        "(default if --no-stub is specified)",
        action="store_true",
    )

    subparsers.add_parser("run", help="Run application code in flash")

    parser_image_info = subparsers.add_parser(
        "image_info", help="Dump headers from a binary file (bootloader or application)"
    )
    parser_image_info.add_argument(
        "filename", help="Image file to parse", action=AutoHex2BinAction
    )
    parser_image_info.add_argument(
        "--version",
        "-v",
        help="Output format version (1 - legacy, 2 - extended)",
        choices=["1", "2"],
        default="1",
    )

    parser_make_image = subparsers.add_parser(
        "make_image", help="Create an application image from binary files"
    )
    parser_make_image.add_argument("output", help="Output image file")
    parser_make_image.add_argument(
        "--segfile", "-f", action="append", help="Segment input file"
    )
    parser_make_image.add_argument(
        "--segaddr",
        "-a",
        action="append",
        help="Segment base address",
        type=arg_auto_int,
    )
    parser_make_image.add_argument(
        "--entrypoint",
        "-e",
        help="Address of entry point",
        type=arg_auto_int,
        default=0,
    )

    parser_elf2image = subparsers.add_parser(
        "elf2image", help="Create an application image from ELF file"
    )
    parser_elf2image.add_argument("input", help="Input ELF file")
    parser_elf2image.add_argument(
        "--output",
        "-o",
        help="Output filename prefix (for version 1 image), "
        "or filename (for version 2 single image)",
        type=str,
    )
    parser_elf2image.add_argument(
        "--version",
        "-e",
        help="Output image version",
        choices=["1", "2", "3"],
        default="1",
    )
    parser_elf2image.add_argument(
        # it kept for compatibility
        # Minimum chip revision (deprecated, consider using --min-rev-full)
        "--min-rev",
        "-r",
        help=argparse.SUPPRESS,
        type=int,
        choices=range(256),
        metavar="{0, ... 255}",
        default=0,
    )
    parser_elf2image.add_argument(
        "--min-rev-full",
        help="Minimal chip revision (in format: major * 100 + minor)",
        type=int,
        choices=range(65536),
        metavar="{0, ... 65535}",
        default=0,
    )
    parser_elf2image.add_argument(
        "--max-rev-full",
        help="Maximal chip revision (in format: major * 100 + minor)",
        type=int,
        choices=range(65536),
        metavar="{0, ... 65535}",
        default=65535,
    )
    parser_elf2image.add_argument(
        "--secure-pad",
        action="store_true",
        help="Pad image so once signed it will end on a 64KB boundary. "
        "For Secure Boot v1 images only.",
    )
    parser_elf2image.add_argument(
        "--secure-pad-v2",
        action="store_true",
        help="Pad image to 64KB, so once signed its signature sector will"
        "start at the next 64K block. For Secure Boot v2 images only.",
    )
    parser_elf2image.add_argument(
        "--elf-sha256-offset",
        help="If set, insert SHA256 hash (32 bytes) of the input ELF file "
        "at specified offset in the binary.",
        type=arg_auto_int,
        default=None,
    )
    parser_elf2image.add_argument(
        "--dont-append-digest",
        dest="append_digest",
        help="Don't append a SHA256 digest of the entire image after the checksum. "
        "This argument is not supported and ignored for ESP8266.",
        action="store_false",
        default=True,
    )
    parser_elf2image.add_argument(
        "--use_segments",
        help="If set, ELF segments will be used instead of ELF sections "
        "to genereate the image.",
        action="store_true",
    )
    parser_elf2image.add_argument(
        "--flash-mmu-page-size",
        help="Change flash MMU page size.",
        choices=["64KB", "32KB", "16KB", "8KB"],
    )
    parser_elf2image.add_argument(
        "--pad-to-size",
        help="The block size with which the final binary image after padding "
        "must be aligned to. Value 0xFF is used for padding, similar to erase_flash",
        default=None,
    )
    parser_elf2image.add_argument(
        "--ram-only-header",
        help="Order segments of the output so IRAM and DRAM are placed at the "
        "beginning and force the main header segment number to RAM segments "
        "quantity. This will make the other segments invisible to the ROM "
        "loader. Use this argument with care because the ROM loader will load "
        "only the RAM segments although the other segments being present in "
        "the output.",
        action="store_true",
        default=None,
    )

    add_spi_flash_subparsers(parser_elf2image, allow_keep=False, auto_detect=False)

    subparsers.add_parser("read_mac", help="Read MAC address from OTP ROM")

    subparsers.add_parser("chip_id", help="Read Chip ID from OTP ROM")

    parser_flash_id = subparsers.add_parser(
        "flash_id", help="Read SPI flash manufacturer and device ID"
    )
    add_spi_connection_arg(parser_flash_id)

    parser_read_status = subparsers.add_parser(
        "read_flash_status", help="Read SPI flash status register"
    )

    add_spi_connection_arg(parser_read_status)
    parser_read_status.add_argument(
        "--bytes",
        help="Number of bytes to read (1-3)",
        type=int,
        choices=[1, 2, 3],
        default=2,
    )

    parser_write_status = subparsers.add_parser(
        "write_flash_status", help="Write SPI flash status register"
    )

    add_spi_connection_arg(parser_write_status)
    parser_write_status.add_argument(
        "--non-volatile",
        help="Write non-volatile bits (use with caution)",
        action="store_true",
    )
    parser_write_status.add_argument(
        "--bytes",
        help="Number of status bytes to write (1-3)",
        type=int,
        choices=[1, 2, 3],
        default=2,
    )
    parser_write_status.add_argument("value", help="New value", type=arg_auto_int)

    parser_read_flash = subparsers.add_parser(
        "read_flash", help="Read SPI flash content"
    )
    add_spi_flash_subparsers(
        parser_read_flash, allow_keep=True, auto_detect=True, size_only=True
    )
    parser_read_flash.add_argument("address", help="Start address", type=arg_auto_int)
    parser_read_flash.add_argument(
        "size",
        help="Size of region to dump. Use `ALL` to read to the end of flash.",
        type=arg_auto_size,
    )
    parser_read_flash.add_argument("filename", help="Name of binary dump")
    parser_read_flash.add_argument(
        "--no-progress", "-p", help="Suppress progress output", action="store_true"
    )

    parser_verify_flash = subparsers.add_parser(
        "verify_flash", help="Verify a binary blob against flash"
    )
    parser_verify_flash.add_argument(
        "addr_filename",
        help="Address and binary file to verify there, separated by space",
        action=AddrFilenamePairAction,
    )
    parser_verify_flash.add_argument(
        "--diff", "-d", help="Show differences", choices=["no", "yes"], default="no"
    )
    add_spi_flash_subparsers(parser_verify_flash, allow_keep=True, auto_detect=True)

    parser_erase_flash = subparsers.add_parser(
        "erase_flash", help="Perform Chip Erase on SPI flash"
    )
    parser_erase_flash.add_argument(
        "--force",
        help="Erase flash even if security features are enabled. Use with caution!",
        action="store_true",
    )
    add_spi_connection_arg(parser_erase_flash)

    parser_erase_region = subparsers.add_parser(
        "erase_region", help="Erase a region of the flash"
    )
    parser_erase_region.add_argument(
        "--force",
        help="Erase region even if security features are enabled. Use with caution!",
        action="store_true",
    )
    add_spi_connection_arg(parser_erase_region)
    parser_erase_region.add_argument(
        "address", help="Start address (must be multiple of 4096)", type=arg_auto_int
    )
    parser_erase_region.add_argument(
        "size",
        help="Size of region to erase (must be multiple of 4096). "
        "Use `ALL` to erase to the end of flash.",
        type=arg_auto_size,
    )

    parser_merge_bin = subparsers.add_parser(
        "merge_bin",
        help="Merge multiple raw binary files into a single file for later flashing",
    )

    parser_merge_bin.add_argument(
        "--output", "-o", help="Output filename", type=str, required=True
    )
    parser_merge_bin.add_argument(
        "--format",
        "-f",
        help="Format of the output file",
        choices=["raw", "uf2", "hex"],
        default="raw",
    )
    uf2_group = parser_merge_bin.add_argument_group("UF2 format")
    uf2_group.add_argument(
        "--chunk-size",
        help="Specify the used data part of the 512 byte UF2 block. "
        "A common value is 256. By default the largest possible value will be used.",
        default=None,
        type=arg_auto_chunk_size,
    )
    uf2_group.add_argument(
        "--md5-disable",
        help="Disable MD5 checksum in UF2 output",
        action="store_true",
    )
    add_spi_flash_subparsers(parser_merge_bin, allow_keep=True, auto_detect=False)

    raw_group = parser_merge_bin.add_argument_group("RAW format")
    raw_group.add_argument(
        "--target-offset",
        "-t",
        help="Target offset where the output file will be flashed",
        type=arg_auto_int,
        default=0,
    )
    raw_group.add_argument(
        "--fill-flash-size",
        help="If set, the final binary file will be padded with FF "
        "bytes up to this flash size.",
        choices=[
            "256KB",
            "512KB",
            "1MB",
            "2MB",
            "4MB",
            "8MB",
            "16MB",
            "32MB",
            "64MB",
            "128MB",
        ],
    )
    parser_merge_bin.add_argument(
        "addr_filename",
        metavar="<address> <filename>",
        help="Address followed by binary filename, separated by space",
        action=AddrFilenamePairAction,
    )

    subparsers.add_parser("get_security_info", help="Get some security-related data")

    subparsers.add_parser("version", help="Print esptool version")

    # internal sanity check - every operation matches a module function of the same name
    for operation in subparsers.choices.keys():
        assert operation in globals(), "%s should be a module function" % operation

    argv = expand_file_arguments(argv or sys.argv[1:])

    args = parser.parse_args(argv)
    print("esptool.py v%s" % __version__)
    load_config_file(verbose=True)

    # operation function can take 1 arg (args), 2 args (esp, arg)
    # or be a member function of the ESPLoader class.

    if args.operation is None:
        parser.print_help()
        sys.exit(1)

    # Forbid the usage of both --encrypt, which means encrypt all the given files,
    # and --encrypt-files, which represents the list of files to encrypt.
    # The reason is that allowing both at the same time increases the chances of
    # having contradictory lists (e.g. one file not available in one of list).
    if (
        args.operation == "write_flash"
        and args.encrypt
        and args.encrypt_files is not None
    ):
        raise FatalError(
            "Options --encrypt and --encrypt-files "
            "must not be specified at the same time."
        )

    operation_func = globals()[args.operation]
    operation_args = inspect.getfullargspec(operation_func).args

    if (
        operation_args[0] == "esp"
    ):  # operation function takes an ESPLoader connection object
        if args.before != "no_reset_no_sync":
            initial_baud = min(
                ESPLoader.ESP_ROM_BAUD, args.baud
            )  # don't sync faster than the default baud rate
        else:
            initial_baud = args.baud

        if args.port is None:
            ser_list = get_port_list()
            print("Found %d serial ports" % len(ser_list))
        else:
            ser_list = [args.port]
        esp = esp or get_default_connected_device(
            ser_list,
            port=args.port,
            connect_attempts=args.connect_attempts,
            initial_baud=initial_baud,
            chip=args.chip,
            trace=args.trace,
            before=args.before,
        )

        if esp is None:
            raise FatalError(
                "Could not connect to an Espressif device "
                "on any of the %d available serial ports." % len(ser_list)
            )

        if esp.secure_download_mode:
            print("Chip is %s in Secure Download Mode" % esp.CHIP_NAME)
        else:
            print("Chip is %s" % (esp.get_chip_description()))
            print("Features: %s" % ", ".join(esp.get_chip_features()))
            print("Crystal is %dMHz" % esp.get_crystal_freq())
            read_mac(esp, args)

        if not args.no_stub:
            if esp.secure_download_mode:
                print(
                    "WARNING: Stub loader is not supported in Secure Download Mode, "
                    "setting --no-stub"
                )
                args.no_stub = True
            elif not esp.IS_STUB and esp.stub_is_disabled:
                print(
                    "WARNING: Stub loader has been disabled for compatibility, "
                    "setting --no-stub"
                )
                args.no_stub = True
            else:
                try:
                    esp = esp.run_stub()
                except Exception:
                    # The CH9102 bridge (PID: 0x55D4) can have issues on MacOS
                    if sys.platform == "darwin" and esp._get_pid() == 0x55D4:
                        print(
                            "\nNote: If issues persist, "
                            "try installing the WCH USB-to-Serial MacOS driver."
                        )
                    raise

        if args.override_vddsdio:
            esp.override_vddsdio(args.override_vddsdio)

        if args.baud > initial_baud:
            try:
                esp.change_baud(args.baud)
            except NotImplementedInROMError:
                print(
                    "WARNING: ROM doesn't support changing baud rate. "
                    "Keeping initial baud rate %d" % initial_baud
                )

        def _define_spi_conn(spi_connection):
            """Prepare SPI configuration string and value for flash_spi_attach()"""
            clk, q, d, hd, cs = spi_connection
            spi_config_txt = f"CLK:{clk}, Q:{q}, D:{d}, HD:{hd}, CS:{cs}"
            value = (hd << 24) | (cs << 18) | (d << 12) | (q << 6) | clk
            return spi_config_txt, value

        # Override the common SPI flash parameter stuff if configured to do so
        if hasattr(args, "spi_connection") and args.spi_connection is not None:
            spi_config = args.spi_connection
            if args.spi_connection == "SPI":
                value = 0
            elif args.spi_connection == "HSPI":
                value = 1
            else:
                esp.check_spi_connection(args.spi_connection)
                # Encode the pin numbers as a 32-bit integer with packed 6-bit values,
                # the same way the ESP ROM takes them
                spi_config, value = _define_spi_conn(args.spi_connection)
            print(f"Configuring SPI flash mode ({spi_config})...")
            esp.flash_spi_attach(value)
        elif args.no_stub:
            if esp.CHIP_NAME != "ESP32" or esp.secure_download_mode:
                print("Enabling default SPI flash mode...")
                # ROM loader doesn't enable flash unless we explicitly do it
                esp.flash_spi_attach(0)
            else:
                # ROM doesn't attach in-package flash chips
                spi_chip_pads = esp.get_chip_spi_pads()
                spi_config_txt, value = _define_spi_conn(spi_chip_pads)
                if spi_chip_pads != (0, 0, 0, 0, 0):
                    print(
                        "Attaching flash from eFuses' SPI pads configuration"
                        f"({spi_config_txt})..."
                    )
                else:
                    print("Enabling default SPI flash mode...")
                esp.flash_spi_attach(value)

        # XMC chip startup sequence
        XMC_VENDOR_ID = 0x20

        def is_xmc_chip_strict():
            id = esp.flash_id()
            rdid = ((id & 0xFF) << 16) | ((id >> 16) & 0xFF) | (id & 0xFF00)

            vendor_id = (rdid >> 16) & 0xFF
            mfid = (rdid >> 8) & 0xFF
            cpid = rdid & 0xFF

            if vendor_id != XMC_VENDOR_ID:
                return False

            matched = False
            if mfid == 0x40:
                if cpid >= 0x13 and cpid <= 0x20:
                    matched = True
            elif mfid == 0x41:
                if cpid >= 0x17 and cpid <= 0x20:
                    matched = True
            elif mfid == 0x50:
                if cpid >= 0x15 and cpid <= 0x16:
                    matched = True
            return matched

        def flash_xmc_startup():
            # If the RDID value is a valid XMC one, may skip the flow
            fast_check = True
            if fast_check and is_xmc_chip_strict():
                return  # Successful XMC flash chip boot-up detected by RDID, skipping.

            sfdp_mfid_addr = 0x10
            mf_id = esp.read_spiflash_sfdp(sfdp_mfid_addr, 8)
            if mf_id != XMC_VENDOR_ID:  # Non-XMC chip detected by SFDP Read, skipping.
                return

            print(
                "WARNING: XMC flash chip boot-up failure detected! "
                "Running XMC25QHxxC startup flow"
            )
            esp.run_spiflash_command(0xB9)  # Enter DPD
            esp.run_spiflash_command(0x79)  # Enter UDPD
            esp.run_spiflash_command(0xFF)  # Exit UDPD
            time.sleep(0.002)  # Delay tXUDPD
            esp.run_spiflash_command(0xAB)  # Release Power-Down
            time.sleep(0.00002)
            # Check for success
            if not is_xmc_chip_strict():
                print("WARNING: XMC flash boot-up fix failed.")
            print("XMC flash chip boot-up fix successful!")

        # Check flash chip connection
        if not esp.secure_download_mode:
            try:
                flash_id = esp.flash_id()
                if flash_id in (0xFFFFFF, 0x000000):
                    print(
                        "WARNING: Failed to communicate with the flash chip, "
                        "read/write operations will fail. "
                        "Try checking the chip connections or removing "
                        "any other hardware connected to IOs."
                    )
                    if (
                        hasattr(args, "spi_connection")
                        and args.spi_connection is not None
                    ):
                        print(
                            "Some GPIO pins might be used by other peripherals, "
                            "try using another --spi-connection combination."
                        )

            except FatalError as e:
                raise FatalError(f"Unable to verify flash chip connection ({e}).")

        # Check if XMC SPI flash chip booted-up successfully, fix if not
        if not esp.secure_download_mode:
            try:
                flash_xmc_startup()
            except FatalError as e:
                esp.trace(f"Unable to perform XMC flash chip startup sequence ({e}).")

        if hasattr(args, "flash_size"):
            print("Configuring flash size...")
            if args.flash_size == "detect":
                flash_size = detect_flash_size(esp, args)
            elif args.flash_size == "keep":
                flash_size = detect_flash_size(esp, args=None)
            else:
                flash_size = args.flash_size

            if flash_size is not None:  # Secure download mode
                esp.flash_set_parameters(flash_size_bytes(flash_size))
                # Check if stub supports chosen flash size
                if (
                    esp.IS_STUB
                    and esp.CHIP_NAME != "ESP32-S3"
                    and flash_size_bytes(flash_size) > 16 * 1024 * 1024
                ):
                    print(
                        "WARNING: Flasher stub doesn't fully support flash size larger "
                        "than 16MB, in case of failure use --no-stub."
                    )

        if getattr(args, "size", "") == "all":
            if esp.secure_download_mode:
                raise FatalError(
                    "Detecting flash size is not supported in secure download mode. "
                    "Set an exact size value."
                )
            # detect flash size
            flash_id = esp.flash_id()
            size_id = flash_id >> 16
            size_str = DETECTED_FLASH_SIZES.get(size_id)
            if size_str is None:
                raise FatalError(
                    "Detecting flash size failed. Set an exact size value."
                )
            print(f"Detected flash size: {size_str}")
            args.size = flash_size_bytes(size_str)

        if esp.IS_STUB and hasattr(args, "address") and hasattr(args, "size"):
            if esp.CHIP_NAME != "ESP32-S3" and args.address + args.size > 0x1000000:
                print(
                    "WARNING: Flasher stub doesn't fully support flash size larger "
                    "than 16MB, in case of failure use --no-stub."
                )

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
            print("Exiting immediately.")
        elif args.after == "hard_reset":
            esp.hard_reset()
        elif args.after == "soft_reset":
            print("Soft resetting...")
            # flash_finish will trigger a soft reset
            esp.soft_reset(False)
        elif args.after == "no_reset_stub":
            print("Staying in flasher stub.")
        else:  # args.after == 'no_reset'
            print("Staying in bootloader.")
            if esp.IS_STUB:
                esp.soft_reset(True)  # exit stub back to ROM loader

        if not external_esp:
            esp._port.close()

    else:
        operation_func(args)


def arg_auto_int(x):
    return int(x, 0)


def arg_auto_size(x):
    x = x.lower()
    return x if x == "all" else arg_auto_int(x)


def arg_auto_chunk_size(string: str) -> int:
    num = int(string, 0)
    if num & 3 != 0:
        raise argparse.ArgumentTypeError("Chunk size should be a 4-byte aligned number")
    return num


def get_port_list():
    if list_ports is None:
        raise FatalError(
            "Listing all serial ports is currently not available. "
            "Please try to specify the port when running esptool.py or update "
            "the pyserial package to the latest version"
        )
    return sorted(ports.device for ports in list_ports.comports())


def expand_file_arguments(argv):
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
        print(f"esptool.py {' '.join(new_args)}")
        return new_args
    return argv


def get_default_connected_device(
    serial_list,
    port,
    connect_attempts,
    initial_baud,
    chip="auto",
    trace=False,
    before="default_reset",
):
    _esp = None
    for each_port in reversed(serial_list):
        print("Serial port %s" % each_port)
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
            print("%s failed to connect: %s" % (each_port, err))
            if _esp and _esp._port:
                _esp._port.close()
            _esp = None
    return _esp


class SpiConnectionAction(argparse.Action):
    """
    Custom action to parse 'spi connection' override.
    Values are SPI, HSPI, or a sequence of 5 pin numbers separated by commas.
    """

    def __call__(self, parser, namespace, value, option_string=None):
        if value.upper() in ["SPI", "HSPI"]:
            values = value.upper()
        elif "," in value:
            values = value.split(",")
            if len(values) != 5:
                raise argparse.ArgumentError(
                    self,
                    f"{value} is not a valid list of comma-separate pin numbers. "
                    "Must be 5 numbers - CLK,Q,D,HD,CS.",
                )
            try:
                values = tuple(int(v, 0) for v in values)
            except ValueError:
                raise argparse.ArgumentError(
                    self,
                    f"{values} is not a valid argument. "
                    "All pins must be numeric values",
                )
        else:
            raise argparse.ArgumentError(
                self,
                f"{value} is not a valid spi-connection value. "
                "Values are SPI, HSPI, or a sequence of 5 pin numbers - CLK,Q,D,HD,CS.",
            )
        setattr(namespace, self.dest, values)


class AutoHex2BinAction(argparse.Action):
    """Custom parser class for auto conversion of input files from hex to bin"""

    def __call__(self, parser, namespace, value, option_string=None):
        try:
            with open(value, "rb") as f:
                # if hex file was detected replace hex file with converted temp bin
                # otherwise keep the original file
                value = intel_hex_to_bin(f).name
        except IOError as e:
            raise argparse.ArgumentError(self, e)
        setattr(namespace, self.dest, value)


class AddrFilenamePairAction(argparse.Action):
    """Custom parser class for the address/filename pairs passed as arguments"""

    def __init__(self, option_strings, dest, nargs="+", **kwargs):
        super(AddrFilenamePairAction, self).__init__(
            option_strings, dest, nargs, **kwargs
        )

    def __call__(self, parser, namespace, values, option_string=None):
        # validate pair arguments
        pairs = []
        for i in range(0, len(values), 2):
            try:
                address = int(values[i], 0)
            except ValueError:
                raise argparse.ArgumentError(
                    self, 'Address "%s" must be a number' % values[i]
                )
            try:
                argfile = open(values[i + 1], "rb")
            except IOError as e:
                raise argparse.ArgumentError(self, e)
            except IndexError:
                raise argparse.ArgumentError(
                    self,
                    "Must be pairs of an address "
                    "and the binary filename to write there",
                )
            # check for intel hex files and convert them to bin
            argfile = intel_hex_to_bin(argfile, address)
            pairs.append((address, argfile))

        # Sort the addresses and check for overlapping
        end = 0
        for address, argfile in sorted(pairs, key=lambda x: x[0]):
            argfile.seek(0, 2)  # seek to end
            size = argfile.tell()
            argfile.seek(0)
            sector_start = address & ~(ESPLoader.FLASH_SECTOR_SIZE - 1)
            sector_end = (
                (address + size + ESPLoader.FLASH_SECTOR_SIZE - 1)
                & ~(ESPLoader.FLASH_SECTOR_SIZE - 1)
            ) - 1
            if sector_start < end:
                message = "Detected overlap at address: 0x%x for file: %s" % (
                    address,
                    argfile.name,
                )
                raise argparse.ArgumentError(self, message)
            end = sector_end
        setattr(namespace, self.dest, pairs)


def _main():
    try:
        main()
    except FatalError as e:
        print(f"\nA fatal error occurred: {e}")
        sys.exit(2)
    except serial.serialutil.SerialException as e:
        print(f"\nA serial exception error occurred: {e}")
        print(
            "Note: This error originates from pySerial. "
            "It is likely not a problem with esptool, "
            "but with the hardware connection or drivers."
        )
        print(
            "For troubleshooting steps visit: "
            "https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html"
        )
        sys.exit(1)
    except StopIteration:
        print(traceback.format_exc())
        print("A fatal error occurred: The chip stopped responding.")
        sys.exit(2)


if __name__ == "__main__":
    _main()
