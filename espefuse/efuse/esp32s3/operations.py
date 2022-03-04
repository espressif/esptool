#!/usr/bin/env python
# This file includes the operations with eFuses for ESP32-S3 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function

import argparse
import io
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
        "(The keys use the RS coding scheme that does not support post-write "
        "data changes. Forced write can damage RS encoding bits.) "
        "The write-protecting of keypurposes does not depend on the option, "
        "it will be set anyway.",
        action="store_true",
    )
    p.add_argument(
        "--no-read-protect",
        help="Disable read-protecting of the key. The key remains readable software."
        "The key with keypurpose[USER, RESERVED and *_DIGEST] "
        "will remain readable anyway. "
        "For the rest keypurposes the read-protection will be defined the option "
        "(Read-protect by default).",
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
        help="File containing 256 bits of binary key data",
        action="append",
        type=argparse.FileType("rb"),
    )
    burn_key.add_argument(
        "keypurpose",
        help="Purpose to set.",
        action="append",
        choices=fields.EfuseKeyPurposeField.KEY_PURPOSES_NAME,
    )
    for _ in efuses.BLOCKS_FOR_KEYS:
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
            help="File containing 256 bits of binary key data",
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
        help="Parse a RSA public key and burn the digest to key efuse block",
    )
    protect_options(burn_key_digest)
    add_force_write_always(burn_key_digest)
    burn_key_digest.add_argument(
        "block",
        help="Key block to burn",
        action="append",
        choices=efuses.BLOCKS_FOR_KEYS,
    )
    burn_key_digest.add_argument(
        "keyfile",
        help="Key file to digest (PEM format)",
        action="append",
        type=argparse.FileType("rb"),
    )
    burn_key_digest.add_argument(
        "keypurpose",
        help="Purpose to set.",
        action="append",
        choices=fields.EfuseKeyPurposeField.DIGEST_KEY_PURPOSES,
    )
    for _ in efuses.BLOCKS_FOR_KEYS:
        burn_key_digest.add_argument(
            "block",
            help="Key block to burn",
            nargs="?",
            action="append",
            metavar="BLOCK",
            choices=efuses.BLOCKS_FOR_KEYS,
        )
        burn_key_digest.add_argument(
            "keyfile",
            help="Key file to digest (PEM format)",
            nargs="?",
            action="append",
            metavar="KEYFILE",
            type=argparse.FileType("rb"),
        )
        burn_key_digest.add_argument(
            "keypurpose",
            help="Purpose to set.",
            nargs="?",
            action="append",
            metavar="KEYPURPOSE",
            choices=fields.EfuseKeyPurposeField.DIGEST_KEY_PURPOSES,
        )

    p = subparsers.add_parser(
        "set_flash_voltage",
        help="Permanently set the internal flash voltage regulator "
        "to either 1.8V, 3.3V or OFF. This means GPIO45 can be high or low at reset "
        "without changing the flash voltage.",
    )
    p.add_argument("voltage", help="Voltage selection", choices=["1.8V", "3.3V", "OFF"])

    p = subparsers.add_parser(
        "burn_custom_mac", help="Burn a 48-bit Custom MAC Address to EFUSE BLOCK3."
    )
    p.add_argument(
        "mac",
        help="Custom MAC Address to burn given in hexadecimal format with "
        "bytes separated by colons (e.g. AA:CD:EF:01:02:03).",
        type=fields.base_fields.CheckArgValue(efuses, "CUSTOM_MAC"),
    )
    add_force_write_always(p)

    p = subparsers.add_parser("get_custom_mac", help="Prints the Custom MAC Address.")


def burn_custom_mac(esp, efuses, args):
    efuses["CUSTOM_MAC"].save(args.mac)
    if not efuses.burn_all(check_batch_mode=True):
        return
    get_custom_mac(esp, efuses, args)
    print("Successful")


def get_custom_mac(esp, efuses, args):
    print("Custom MAC Address: {}".format(efuses["CUSTOM_MAC"].get()))


def set_flash_voltage(esp, efuses, args):
    sdio_force = efuses["VDD_SPI_FORCE"]
    sdio_tieh = efuses["VDD_SPI_TIEH"]
    sdio_reg = efuses["VDD_SPI_XPD"]

    # check efuses aren't burned in a way which makes this impossible
    if args.voltage == "OFF" and sdio_reg.get() != 0:
        raise esptool.FatalError(
            "Can't set flash regulator to OFF as VDD_SPI_XPD efuse is already burned"
        )

    if args.voltage == "1.8V" and sdio_tieh.get() != 0:
        raise esptool.FatalError(
            "Can't set regulator to 1.8V is VDD_SPI_TIEH efuse is already burned"
        )

    if args.voltage == "OFF":
        msg = "Disable internal flash voltage regulator (VDD_SPI). "
        "SPI flash will need to be powered from an external source.\n"
        "The following efuse is burned: VDD_SPI_FORCE.\n"
        "It is possible to later re-enable the internal regulator (%s) " % (
            "to 3.3V" if sdio_tieh.get() != 0 else "to 1.8V or 3.3V"
        )
        "by burning an additional efuse"
    elif args.voltage == "1.8V":
        msg = "Set internal flash voltage regulator (VDD_SPI) to 1.8V.\n"
        "The following efuses are burned: VDD_SPI_FORCE, VDD_SPI_XPD.\n"
        "It is possible to later increase the voltage to 3.3V (permanently) "
        "by burning additional efuse VDD_SPI_TIEH"
    elif args.voltage == "3.3V":
        msg = "Enable internal flash voltage regulator (VDD_SPI) to 3.3V.\n"
        "The following efuses are burned: VDD_SPI_FORCE, VDD_SPI_XPD, VDD_SPI_TIEH."
    print(msg)

    sdio_force.save(1)  # Disable GPIO45
    if args.voltage != "OFF":
        sdio_reg.save(1)  # Enable internal regulator
    if args.voltage == "3.3V":
        sdio_tieh.save(1)
    print("VDD_SPI setting complete.")
    if not efuses.burn_all(check_batch_mode=True):
        return
    print("Successful")


def adc_info(esp, efuses, args):
    print("")
    # fmt: off
    if efuses["BLOCK2_VERSION"].get() == 1:
        print("Temperature Sensor Calibration = {}C".format(efuses["TEMP_SENSOR_CAL"].get()))

        print("")
        print("ADC1 readings stored in efuse BLOCK2:")
        print("    MODE0 D1 reading  (250mV):  {}".format(efuses["ADC1_MODE0_D1"].get()))
        print("    MODE0 D2 reading  (600mV):  {}".format(efuses["ADC1_MODE0_D2"].get()))

        print("    MODE1 D1 reading  (250mV):  {}".format(efuses["ADC1_MODE1_D1"].get()))
        print("    MODE1 D2 reading  (800mV):  {}".format(efuses["ADC1_MODE1_D2"].get()))

        print("    MODE2 D1 reading  (250mV):  {}".format(efuses["ADC1_MODE2_D1"].get()))
        print("    MODE2 D2 reading  (1000mV): {}".format(efuses["ADC1_MODE2_D2"].get()))

        print("    MODE3 D1 reading  (250mV):  {}".format(efuses["ADC1_MODE3_D1"].get()))
        print("    MODE3 D2 reading  (2000mV): {}".format(efuses["ADC1_MODE3_D2"].get()))

        print("")
        print("ADC2 readings stored in efuse BLOCK2:")
        print("    MODE0 D1 reading  (250mV):  {}".format(efuses["ADC2_MODE0_D1"].get()))
        print("    MODE0 D2 reading  (600mV):  {}".format(efuses["ADC2_MODE0_D2"].get()))

        print("    MODE1 D1 reading  (250mV):  {}".format(efuses["ADC2_MODE1_D1"].get()))
        print("    MODE1 D2 reading  (800mV):  {}".format(efuses["ADC2_MODE1_D2"].get()))

        print("    MODE2 D1 reading  (250mV):  {}".format(efuses["ADC2_MODE2_D1"].get()))
        print("    MODE2 D2 reading  (1000mV): {}".format(efuses["ADC2_MODE2_D2"].get()))

        print("    MODE3 D1 reading  (250mV):  {}".format(efuses["ADC2_MODE3_D1"].get()))
        print("    MODE3 D2 reading  (2000mV): {}".format(efuses["ADC2_MODE3_D2"].get()))
    else:
        print("BLOCK2_VERSION = {}".format(efuses["BLOCK2_VERSION"].get_meaning()))
    # fmt: on


def key_block_is_unused(block, key_purpose_block):
    if not block.is_readable() or not block.is_writeable():
        return False

    if key_purpose_block.get() != "USER" or not key_purpose_block.is_writeable():
        return False

    if not block.get_bitstring().all(False):
        return False

    return True


def get_next_key_block(efuses, current_key_block, block_name_list):
    key_blocks = [b for b in efuses.blocks if b.key_purpose_name]
    start = key_blocks.index(current_key_block)

    # Sort key blocks so that we pick the next free block (and loop around if necessary)
    key_blocks = key_blocks[start:] + key_blocks[0:start]

    # Exclude any other blocks that will be be burned
    key_blocks = [b for b in key_blocks if b.name not in block_name_list]

    for block in key_blocks:
        key_purpose_block = efuses[block.key_purpose_name]
        if key_block_is_unused(block, key_purpose_block):
            return block

    return None


def split_512_bit_key(efuses, block_name_list, datafile_list, keypurpose_list):
    i = keypurpose_list.index("XTS_AES_256_KEY")
    block_name = block_name_list[i]

    block_num = efuses.get_index_block_by_name(block_name)
    block = efuses.blocks[block_num]

    data = datafile_list[i].read()
    if len(data) != 64:
        raise esptool.FatalError(
            "Incorrect key file size %d, XTS_AES_256_KEY should be 64 bytes" % len(data)
        )

    key_block_2 = get_next_key_block(efuses, block, block_name_list)
    if not key_block_2:
        raise esptool.FatalError("XTS_AES_256_KEY requires two free keyblocks")

    keypurpose_list.append("XTS_AES_256_KEY_1")
    datafile_list.append(io.BytesIO(data[:32]))
    block_name_list.append(block_name)

    keypurpose_list.append("XTS_AES_256_KEY_2")
    datafile_list.append(io.BytesIO(data[32:]))
    block_name_list.append(key_block_2.name)

    keypurpose_list.pop(i)
    datafile_list.pop(i)
    block_name_list.pop(i)


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

    if "XTS_AES_256_KEY" in keypurpose_list:
        # XTS_AES_256_KEY is not an actual HW key purpose, needs to be split into
        # XTS_AES_256_KEY_1 and XTS_AES_256_KEY_2
        split_512_bit_key(efuses, block_name_list, datafile_list, keypurpose_list)

    util.check_duplicate_name_in_list(block_name_list)
    if len(block_name_list) != len(datafile_list) or len(block_name_list) != len(
        keypurpose_list
    ):
        raise esptool.FatalError(
            "The number of blocks (%d), datafile (%d) and keypurpose (%d) "
            "should be the same."
            % (len(block_name_list), len(datafile_list), len(keypurpose_list))
        )

    print("Burn keys to blocks:")
    for block_name, datafile, keypurpose in zip(
        block_name_list, datafile_list, keypurpose_list
    ):
        efuse = None
        for block in efuses.blocks:
            if block_name == block.name or block_name in block.alias:
                efuse = efuses[block.name]
        if efuse is None:
            raise esptool.FatalError("Unknown block name - %s" % (block_name))
        num_bytes = efuse.bit_len // 8

        block_num = efuses.get_index_block_by_name(block_name)
        block = efuses.blocks[block_num]

        if digest is None:
            data = datafile.read()
        else:
            data = datafile

        print(" - %s" % (efuse.name), end=" ")
        revers_msg = None
        if efuses[block.key_purpose_name].need_reverse(keypurpose):
            revers_msg = "\tReversing byte order for AES-XTS hardware peripheral"
            data = data[::-1]
        print("-> [%s]" % (util.hexify(data, " ")))
        if revers_msg:
            print(revers_msg)
        if len(data) != num_bytes:
            raise esptool.FatalError(
                "Incorrect key file size %d. Key file must be %d bytes (%d bits) "
                "of raw binary key data." % (len(data), num_bytes, num_bytes * 8)
            )

        if efuses[block.key_purpose_name].need_rd_protect(keypurpose):
            read_protect = False if args.no_read_protect else True
        else:
            read_protect = False
        write_protect = not args.no_write_protect

        # using efuse instead of a block gives the advantage of
        # checking it as the whole field.
        efuse.save(data)

        disable_wr_protect_key_purpose = False
        if efuses[block.key_purpose_name].get() != keypurpose:
            if efuses[block.key_purpose_name].is_writeable():
                print(
                    "\t'%s': '%s' -> '%s'."
                    % (
                        block.key_purpose_name,
                        efuses[block.key_purpose_name].get(),
                        keypurpose,
                    )
                )
                efuses[block.key_purpose_name].save(keypurpose)
                disable_wr_protect_key_purpose = True
            else:
                raise esptool.FatalError(
                    "It is not possible to change '%s' to '%s' because "
                    "write protection bit is set."
                    % (block.key_purpose_name, keypurpose)
                )
        else:
            print("\t'%s' is already '%s'." % (block.key_purpose_name, keypurpose))
            if efuses[block.key_purpose_name].is_writeable():
                disable_wr_protect_key_purpose = True

        if disable_wr_protect_key_purpose:
            print("\tDisabling write to '%s'." % block.key_purpose_name)
            efuses[block.key_purpose_name].disable_write()

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
    digest_list = []
    datafile_list = args.keyfile[
        0 : len([name for name in args.keyfile if name is not None]) :
    ]
    block_list = args.block[
        0 : len([block for block in args.block if block is not None]) :
    ]
    for block_name, datafile in zip(block_list, datafile_list):
        efuse = None
        for block in efuses.blocks:
            if block_name == block.name or block_name in block.alias:
                efuse = efuses[block.name]
        if efuse is None:
            raise esptool.FatalError("Unknown block name - %s" % (block_name))
        num_bytes = efuse.bit_len // 8
        digest = espsecure._digest_sbv2_public_key(datafile)
        if len(digest) != num_bytes:
            raise esptool.FatalError(
                "Incorrect digest size %d. Digest must be %d bytes (%d bits) "
                "of raw binary key data." % (len(digest), num_bytes, num_bytes * 8)
            )
        digest_list.append(digest)
    burn_key(esp, efuses, args, digest=digest_list)


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
