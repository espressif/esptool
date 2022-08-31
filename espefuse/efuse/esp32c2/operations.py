#!/usr/bin/env python
#
# This file includes the operations with eFuses for ESP32-C2 chip
#
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
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
    burn_bit,
    burn_block_data,
    burn_efuse,
    check_error,
    dump,
    read_protect_efuse,
    summary,
    write_protect_efuse,
)


def protect_options(p):
    p.add_argument(
        "--no-write-protect",
        help="Disable write-protecting of the key. The key remains writable. "
        "(The keys use the RS coding scheme that does not support "
        "post-write data changes. Forced write can damage RS encoding bits.) "
        "The write-protecting of keypurposes does not depend on the option, "
        "it will be set anyway.",
        action="store_true",
    )
    p.add_argument(
        "--no-read-protect",
        help="Disable read-protecting of the key. The key remains readable software.",
        action="store_true",
    )


def add_commands(subparsers, efuses):
    add_common_commands(subparsers, efuses)
    burn_key = subparsers.add_parser(
        "burn_key", help="Burn the key block with the specified name"
    )
    protect_options(burn_key)
    add_force_write_always(burn_key)
    burn_key.add_argument(
        "block",
        help="Key block to burn",
        action="append",
        choices=efuses.BLOCKS_FOR_KEYS,
    )
    burn_key.add_argument(
        "keyfile",
        help="File containing 128/256 bits of binary key data",
        action="append",
        type=argparse.FileType("rb"),
    )
    burn_key.add_argument(
        "keypurpose",
        help="Purpose to set.",
        action="append",
        choices=fields.EfuseKeyPurposeField.KEY_PURPOSES_NAME,
    )
    for _ in range(1):
        burn_key.add_argument(
            "block",
            help="Key block to burn",
            nargs="?",
            action="append",
            metavar="BLOCK",
            choices=efuses.BLOCKS_FOR_KEYS,
        )
        burn_key.add_argument(
            "keyfile",
            help="File containing 128/256 bits of binary key data",
            nargs="?",
            action="append",
            metavar="KEYFILE",
            type=argparse.FileType("rb"),
        )
        burn_key.add_argument(
            "keypurpose",
            help="Purpose to set.",
            nargs="?",
            action="append",
            metavar="KEYPURPOSE",
            choices=fields.EfuseKeyPurposeField.KEY_PURPOSES_NAME,
        )

    burn_key_digest = subparsers.add_parser(
        "burn_key_digest",
        help="Parse an ECDSA public key and burn the digest "
        "to higher 128-bits of BLOCK_KEY0",
    )
    protect_options(burn_key_digest)
    add_force_write_always(burn_key_digest)
    burn_key_digest.add_argument(
        "keyfile", help="Key file to digest (PEM format)", type=argparse.FileType("rb")
    )

    p = subparsers.add_parser(
        "set_flash_voltage",
        help="Permanently set the internal flash voltage regulator "
        "to either 1.8V, 3.3V or OFF. This means GPIO45 can be high or low "
        "at reset without changing the flash voltage.",
    )
    p.add_argument("voltage", help="Voltage selection", choices=["1.8V", "3.3V", "OFF"])

    p = subparsers.add_parser(
        "burn_custom_mac", help="Burn a 48-bit Custom MAC Address to EFUSE BLOCK1."
    )
    p.add_argument(
        "mac",
        help="Custom MAC Address to burn given in hexadecimal format "
        "with bytes separated by colons (e.g. AA:CD:EF:01:02:03).",
        type=fields.base_fields.CheckArgValue(efuses, "CUSTOM_MAC"),
    )
    add_force_write_always(p)

    p = subparsers.add_parser("get_custom_mac", help="Prints the Custom MAC Address.")


def burn_custom_mac(esp, efuses, args):
    efuses["CUSTOM_MAC"].save(args.mac)
    efuses["CUSTOM_MAC_USED"].save(1)
    if not efuses.burn_all(check_batch_mode=True):
        return
    get_custom_mac(esp, efuses, args)
    print("Successful")


def get_custom_mac(esp, efuses, args):
    print("Custom MAC Address: {}".format(efuses["CUSTOM_MAC"].get()))


def set_flash_voltage(esp, efuses, args):
    raise esptool.FatalError("set_flash_voltage is not supported!")


def adc_info(esp, efuses, args):
    print("")
    # fmt: off
    if efuses["BLK_VERSION_MINOR"].get() == 1:
        print("    RF_REF_I_BIAS_CONFIG:        {}".format(efuses["RF_REF_I_BIAS_CONFIG"].get()))

        print("    LDO_VOL_BIAS_CONFIG_LOW:     {}".format(efuses["LDO_VOL_BIAS_CONFIG_LOW"].get()))
        print("    LDO_VOL_BIAS_CONFIG_HIGH:    {}".format(efuses["LDO_VOL_BIAS_CONFIG_HIGH"].get()))

        print("    PVT_LOW:                     {}".format(efuses["PVT_LOW"].get()))
        print("    PVT_HIGH:                    {}".format(efuses["PVT_HIGH"].get()))

        print("    ADC_CALIBRATION_0:           {}".format(efuses["ADC_CALIBRATION_0"].get()))
        print("    ADC_CALIBRATION_1:           {}".format(efuses["ADC_CALIBRATION_1"].get()))
        print("    ADC_CALIBRATION_2:           {}".format(efuses["ADC_CALIBRATION_2"].get()))

    else:
        print("BLK_VERSION_MINOR = {}".format(efuses["BLK_VERSION_MINOR"].get_meaning()))
    # fmt: on


def burn_key(esp, efuses, args, digest=None):
    if digest is None:
        datafile_list = args.keyfile[
            0 : len([name for name in args.keyfile if name is not None]) :
        ]
    else:
        datafile_list = digest[0 : len([name for name in digest if name is not None]) :]
    efuses.force_write_always = args.force_write_always
    block_name_list = args.block[
        0 : len([name for name in args.block if name is not None]) :
    ]
    keypurpose_list = args.keypurpose[
        0 : len([name for name in args.keypurpose if name is not None]) :
    ]

    util.check_duplicate_name_in_list(keypurpose_list)
    if len(block_name_list) != len(datafile_list) or len(block_name_list) != len(
        keypurpose_list
    ):
        raise esptool.FatalError(
            "The number of blocks (%d), datafile (%d) and "
            "keypurpose (%d) should be the same."
            % (len(block_name_list), len(datafile_list), len(keypurpose_list))
        )

    assert 1 <= len(block_name_list) <= 2, "Unexpected case"

    if len(block_name_list) == 2:
        incompatible = True if "XTS_AES_128_KEY" in keypurpose_list else False
        permitted_purposes = [
            "XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS",
            "SECURE_BOOT_DIGEST",
        ]
        incompatible |= (
            keypurpose_list[0] in permitted_purposes
            and keypurpose_list[1] not in permitted_purposes
        )
        if incompatible:
            raise esptool.FatalError(
                "These keypurposes are incompatible %s" % (keypurpose_list)
            )

    print("Burn keys to blocks:")
    for datafile, keypurpose in zip(datafile_list, keypurpose_list):
        data = datafile if isinstance(datafile, bytes) else datafile.read()

        if keypurpose == "XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS":
            efuse = efuses["BLOCK_KEY0_LOW_128"]
        elif keypurpose == "SECURE_BOOT_DIGEST":
            efuse = efuses["BLOCK_KEY0_HI_128"]
            if len(data) == 32:
                print(
                    "\tProgramming only left-most 128-bits from SHA256 hash of "
                    "public key to highest 128-bits of BLOCK KEY0"
                )
                data = data[:16]
            elif len(data) != efuse.bit_len // 8:
                raise esptool.FatalError(
                    "Wrong length of this file for SECURE_BOOT_DIGEST. "
                    "Got %d (expected %d or %d)" % (len(data), 32, efuse.bit_len // 8)
                )
            assert len(data) == 16, "Only 16 bytes expected"
        else:
            efuse = efuses["BLOCK_KEY0"]

        num_bytes = efuse.bit_len // 8

        print(" - %s" % (efuse.name), end=" ")
        revers_msg = None
        if keypurpose.startswith("XTS_AES_"):
            revers_msg = "\tReversing byte order for AES-XTS hardware peripheral"
            data = data[::-1]
        print("-> [%s]" % (util.hexify(data, " ")))
        if revers_msg:
            print(revers_msg)
        if len(data) != num_bytes:
            raise esptool.FatalError(
                "Incorrect key file size %d. "
                "Key file must be %d bytes (%d bits) of raw binary key data."
                % (len(data), num_bytes, num_bytes * 8)
            )

        if keypurpose.startswith("XTS_AES_"):
            read_protect = False if args.no_read_protect else True
        else:
            read_protect = False
        write_protect = not args.no_write_protect

        # using efuse instead of a block gives the advantage
        # of checking it as the whole field.
        efuse.save(data)

        if keypurpose == "XTS_AES_128_KEY":
            if efuses["XTS_KEY_LENGTH_256"].get():
                print("\t'XTS_KEY_LENGTH_256' is already '1'")
            else:
                print("\tXTS_KEY_LENGTH_256 -> 1")
                efuses["XTS_KEY_LENGTH_256"].save(1)

        if read_protect:
            print("\tDisabling read to key block")
            efuse.disable_read()

        if write_protect:
            print("\tDisabling write to key block")
            efuse.disable_write()
        print("")

    if not write_protect:
        print("Keys will remain writeable (due to --no-write-protect)")
    if args.no_read_protect:
        print("Keys will remain readable (due to --no-read-protect)")

    if not efuses.burn_all(check_batch_mode=True):
        return
    print("Successful")


def burn_key_digest(esp, efuses, args):
    datafile = args.keyfile
    args.keypurpose = ["SECURE_BOOT_DIGEST"]
    args.block = ["BLOCK_KEY0"]
    digest = espsecure._digest_sbv2_public_key(datafile)
    digest = digest[:16]
    num_bytes = efuses["BLOCK_KEY0_HI_128"].bit_len // 8
    if len(digest) != num_bytes:
        raise esptool.FatalError(
            "Incorrect digest size %d. "
            "Digest must be %d bytes (%d bits) of raw binary key data."
            % (len(digest), num_bytes, num_bytes * 8)
        )
    burn_key(esp, efuses, args, digest=[digest])


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
