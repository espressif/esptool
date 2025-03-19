# This file includes the operations with eFuses for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os  # noqa: F401. It is used in IDF scripts
import traceback

import espsecure

import esptool

from . import fields
from .. import util
from ..base_operations import (
    add_common_commands,
    add_force_write_always,
    add_show_sensitive_info_option,
    burn_bit,
    burn_block_data,
    burn_efuse,
    check_error,
    dump,
    read_protect_efuse,
    summary,
    write_protect_efuse,
)


def add_commands(subparsers, efuses):
    add_common_commands(subparsers, efuses)
    p = subparsers.add_parser(
        "burn_key",
        help="Burn a 256-bit key to EFUSE: %s" % ", ".join(efuses.BLOCKS_FOR_KEYS),
    )
    p.add_argument(
        "--no-protect-key",
        help="Disable default read- and write-protecting of the key. "
        "If this option is not set, once the key is flashed "
        "it cannot be read back or changed.",
        action="store_true",
    )
    add_force_write_always(p)
    add_show_sensitive_info_option(p)
    p.add_argument(
        "block",
        help='Key block to burn. "flash_encryption" (block1), '
        '"secure_boot_v1" (block2), "secure_boot_v2" (block2)',
        action="append",
        choices=efuses.BLOCKS_FOR_KEYS,
    )
    p.add_argument(
        "keyfile",
        help="File containing 256 bits of binary key data",
        action="append",
        type=argparse.FileType("rb"),
    )
    for _ in efuses.BLOCKS_FOR_KEYS:
        p.add_argument(
            "block",
            help='Key block to burn. "flash_encryption" (block1), '
            '"secure_boot_v1" (block2), "secure_boot_v2" (block2)',
            metavar="BLOCK",
            nargs="?",
            action="append",
            choices=efuses.BLOCKS_FOR_KEYS,
        )
        p.add_argument(
            "keyfile",
            help="File containing 256 bits of binary key data",
            metavar="KEYFILE",
            nargs="?",
            action="append",
            type=argparse.FileType("rb"),
        )

    burn_key_digest = subparsers.add_parser(
        "burn_key_digest",
        help="Parse a RSA public key and burn the digest "
        "to eFuse for use with Secure Boot V2",
    )
    burn_key_digest.add_argument(
        "keyfile", help="Key file to digest (PEM format)", type=argparse.FileType("rb")
    )
    burn_key_digest.add_argument(
        "--no-protect-key",
        help="Disable default write-protecting of the key digest. "
        "If this option is not set, once the key is flashed it cannot be changed.",
        action="store_true",
    )
    add_force_write_always(burn_key_digest)
    add_show_sensitive_info_option(burn_key_digest)

    p = subparsers.add_parser(
        "set_flash_voltage",
        help="Permanently set the internal flash voltage regulator "
        "to either 1.8V, 3.3V or OFF. This means GPIO12 can be high or low at reset "
        "without changing the flash voltage.",
    )
    p.add_argument("voltage", help="Voltage selection", choices=["1.8V", "3.3V", "OFF"])

    p = subparsers.add_parser(
        "burn_custom_mac", help="Burn a 48-bit Custom MAC Address to EFUSE BLOCK3."
    )
    p.add_argument(
        "mac",
        help="Custom MAC Address to burn given in hexadecimal format "
        "with bytes separated by colons "
        "(e.g. AA:CD:EF:01:02:03).",
        type=fields.base_fields.CheckArgValue(efuses, "CUSTOM_MAC"),
    )
    add_force_write_always(p)

    p = subparsers.add_parser("get_custom_mac", help="Prints the Custom MAC Address.")


def burn_custom_mac(esp, efuses, args):
    # Writing to BLK3:
    #  - MAC_VERSION = 1
    #  - CUSTOM_MAC = AA:CD:EF:01:02:03
    #  - CUSTOM_MAC_CRC = crc8(CUSTOM_MAC)
    efuses["CUSTOM_MAC"].save(args.mac)
    if not efuses.burn_all(check_batch_mode=True):
        return
    get_custom_mac(esp, efuses, args)
    print("Successful")


def get_custom_mac(esp, efuses, args):
    version = efuses["MAC_VERSION"].get()
    if version > 0:
        print(
            "Custom MAC Address version {}: {}".format(
                version, efuses["CUSTOM_MAC"].get()
            )
        )
    else:
        print("Custom MAC Address is not set in the device.")


def set_flash_voltage(esp, efuses, args):
    sdio_force = efuses["XPD_SDIO_FORCE"]
    sdio_tieh = efuses["XPD_SDIO_TIEH"]
    sdio_reg = efuses["XPD_SDIO_REG"]

    # check efuses aren't burned in a way which makes this impossible
    if args.voltage == "OFF" and sdio_reg.get() != 0:
        raise esptool.FatalError(
            "Can't set flash regulator to OFF as XPD_SDIO_REG efuse is already burned"
        )

    if args.voltage == "1.8V" and sdio_tieh.get() != 0:
        raise esptool.FatalError(
            "Can't set regulator to 1.8V is XPD_SDIO_TIEH efuse is already burned"
        )

    if args.voltage == "OFF":
        msg = "Disable internal flash voltage regulator (VDD_SDIO). "
        "SPI flash will need to be powered from an external source.\n"
        "The following efuse is burned: XPD_SDIO_FORCE.\n"
        "It is possible to later re-enable the internal regulator (%s) " % (
            "to 3.3V" if sdio_tieh.get() != 0 else "to 1.8V or 3.3V"
        )
        "by burning an additional efuse"
    elif args.voltage == "1.8V":
        msg = "Set internal flash voltage regulator (VDD_SDIO) to 1.8V.\n"
        "The following efuses are burned: XPD_SDIO_FORCE, XPD_SDIO_REG.\n"
        "It is possible to later increase the voltage to 3.3V (permanently) "
        "by burning additional efuse XPD_SDIO_TIEH"
    elif args.voltage == "3.3V":
        msg = "Enable internal flash voltage regulator (VDD_SDIO) to 3.3V.\n"
        "The following efuses are burned: XPD_SDIO_FORCE, XPD_SDIO_REG, XPD_SDIO_TIEH."
    print(msg)
    sdio_force.save(1)  # Disable GPIO12
    if args.voltage != "OFF":
        sdio_reg.save(1)  # Enable internal regulator
    if args.voltage == "3.3V":
        sdio_tieh.save(1)
    print("VDD_SDIO setting complete.")
    if not efuses.burn_all(check_batch_mode=True):
        return
    print("Successful")


def adc_info(esp, efuses, args):
    adc_vref = efuses["ADC_VREF"]
    blk3_reserve = efuses["BLK3_PART_RESERVE"]

    vref_raw = adc_vref.get_raw()
    if vref_raw == 0:
        print("ADC VRef calibration: None (1100mV nominal)")
    else:
        print("ADC VRef calibration: %dmV" % adc_vref.get())

    if blk3_reserve.get():
        print("ADC readings stored in efuse BLOCK3:")
        print("    ADC1 Low reading  (150mV): %d" % efuses["ADC1_TP_LOW"].get())
        print("    ADC1 High reading (850mV): %d" % efuses["ADC1_TP_HIGH"].get())
        print("    ADC2 Low reading  (150mV): %d" % efuses["ADC2_TP_LOW"].get())
        print("    ADC2 High reading (850mV): %d" % efuses["ADC2_TP_HIGH"].get())


def burn_key(esp, efuses, args):
    datafile_list = args.keyfile[
        0 : len([keyfile for keyfile in args.keyfile if keyfile is not None]) :
    ]
    block_name_list = args.block[
        0 : len([block for block in args.block if block is not None]) :
    ]
    efuses.force_write_always = args.force_write_always
    no_protect_key = args.no_protect_key

    util.check_duplicate_name_in_list(block_name_list)
    if len(block_name_list) != len(datafile_list):
        raise esptool.FatalError(
            "The number of blocks (%d) and datafile (%d) should be the same."
            % (len(block_name_list), len(datafile_list))
        )

    print("Burn keys to blocks:")
    for block_name, datafile in zip(block_name_list, datafile_list):
        efuse = None
        for block in efuses.blocks:
            if block_name == block.name or block_name in block.alias:
                efuse = efuses[block.name]
        if efuse is None:
            raise esptool.FatalError("Unknown block name - %s" % (block_name))
        num_bytes = efuse.bit_len // 8
        data = datafile.read()
        datafile.close()
        revers_msg = None
        if block_name in ("flash_encryption", "secure_boot_v1"):
            revers_msg = "\tReversing the byte order"
            data = data[::-1]
        print(" - %s" % (efuse.name), end=" ")
        print(
            "-> [{}]".format(
                util.hexify(data, " ")
                if args.show_sensitive_info
                else " ".join(["??"] * len(data))
            )
        )
        if revers_msg:
            print(revers_msg)
        if len(data) != num_bytes:
            raise esptool.FatalError(
                "Incorrect key file size %d. "
                "Key file must be %d bytes (%d bits) of raw binary key data."
                % (len(data), num_bytes, num_bytes * 8)
            )

        efuse.save(data)

        if block_name in ("flash_encryption", "secure_boot_v1"):
            if not no_protect_key:
                print("\tDisabling read to key block")
                efuse.disable_read()

        if not no_protect_key:
            print("\tDisabling write to key block")
            efuse.disable_write()
        print("")

    if args.no_protect_key:
        print("Key is left unprotected as per --no-protect-key argument.")

    msg = "Burn keys in efuse blocks.\n"
    if no_protect_key:
        msg += (
            "The key block will left readable and writeable (due to --no-protect-key)"
        )
    else:
        msg += "The key block will be read and write protected "
        "(no further changes or readback)"
    print(msg, "\n")
    if not efuses.burn_all(check_batch_mode=True):
        return
    print("Successful")


def burn_key_digest(esp, efuses, args):
    if efuses.coding_scheme == efuses.REGS.CODING_SCHEME_34:
        raise esptool.FatalError("burn_key_digest only works with 'None' coding scheme")

    chip_revision = esp.get_chip_revision()
    if chip_revision < 300:
        raise esptool.FatalError(
            "Incorrect chip revision for Secure boot v2. "
            "Detected: v%d.%d. Expected: >= v3.0"
            % (chip_revision / 100, chip_revision % 100)
        )

    digest = espsecure._digest_sbv2_public_key(args.keyfile)
    efuse = efuses["BLOCK2"]
    num_bytes = efuse.bit_len // 8
    if len(digest) != num_bytes:
        raise esptool.FatalError(
            "Incorrect digest size %d. "
            "Digest must be %d bytes (%d bits) of raw binary key data."
            % (len(digest), num_bytes, num_bytes * 8)
        )
    print(" - %s" % (efuse.name), end=" ")
    print(
        "-> [{}]".format(
            util.hexify(digest, " ")
            if args.show_sensitive_info
            else " ".join(["??"] * len(digest))
        )
    )

    efuse.save(digest)
    if not args.no_protect_key:
        print("Disabling write to efuse %s..." % (efuse.name))
        efuse.disable_write()

    if not efuses.burn_all(check_batch_mode=True):
        return
    print("Successful")


def espefuse(esp, efuses, args, command):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation")
    add_commands(subparsers, efuses)
    try:
        cmd_line_args = parser.parse_args(command.split())
    except SystemExit:
        traceback.print_stack()
        raise esptool.FatalError('"{}" - incorrect command'.format(command))
    if cmd_line_args.operation == "execute_scripts":
        configfiles = cmd_line_args.configfiles
        index = cmd_line_args.index
    # copy arguments from args to cmd_line_args
    vars(cmd_line_args).update(vars(args))
    if cmd_line_args.operation == "execute_scripts":
        cmd_line_args.configfiles = configfiles
        cmd_line_args.index = index
    if cmd_line_args.operation is None:
        parser.print_help()
        parser.exit(1)
    operation_func = globals()[cmd_line_args.operation]
    # each 'operation' is a module-level function of the same name
    operation_func(esp, efuses, cmd_line_args)


def execute_scripts(esp, efuses, args):
    efuses.batch_mode_cnt += 1
    del args.operation
    scripts = args.scripts
    del args.scripts

    for file in scripts:
        with open(file.name, "r") as file:
            exec(compile(file.read(), file.name, "exec"))

    if args.debug:
        for block in efuses.blocks:
            data = block.get_bitstring(from_read=False)
            block.print_block(data, "regs_for_burn", args.debug)

    efuses.batch_mode_cnt -= 1
    if not efuses.burn_all(check_batch_mode=True):
        return
    print("Successful")
