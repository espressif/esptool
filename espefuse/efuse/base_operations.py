# This file includes the common operations with eFuses for chips
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os
import json
import sys

from bitstring import BitStream

import esptool

from . import base_fields
from . import util


def add_common_commands(subparsers, efuses):
    class ActionEfuseValuePair(argparse.Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            self._nargs = nargs
            self._choices = kwargs.get("efuse_choices")
            self.efuses = kwargs.get("efuses")
            del kwargs["efuse_choices"]
            del kwargs["efuses"]
            super(ActionEfuseValuePair, self).__init__(
                option_strings, dest, nargs=nargs, **kwargs
            )

        def __call__(self, parser, namespace, values, option_string=None):
            def check_efuse_name(efuse_name, efuse_list):
                if efuse_name not in self._choices:
                    raise esptool.FatalError(
                        "Invalid the efuse name '{}'. "
                        "Available the efuse names: {}".format(
                            efuse_name, self._choices
                        )
                    )

            efuse_value_pairs = {}
            if len(values) > 1:
                if len(values) % 2:
                    raise esptool.FatalError(
                        "The list does not have a valid pair (name value) {}".format(
                            values
                        )
                    )
                for i in range(0, len(values), 2):
                    efuse_name, new_value = values[i : i + 2 :]
                    check_efuse_name(efuse_name, self._choices)
                    check_arg = base_fields.CheckArgValue(self.efuses, efuse_name)
                    efuse_value_pairs[efuse_name] = check_arg(new_value)
            else:
                # For the case of compatibility, when only the efuse_name is given
                # Fields with 'bitcount' and 'bool' types can be without new_value arg
                efuse_name = values[0]
                check_efuse_name(efuse_name, self._choices)
                check_arg = base_fields.CheckArgValue(self.efuses, efuse_name)
                efuse_value_pairs[efuse_name] = check_arg(None)
            setattr(namespace, self.dest, efuse_value_pairs)

    burn = subparsers.add_parser(
        "burn_efuse", help="Burn the efuse with the specified name"
    )
    burn.add_argument(
        "name_value_pairs",
        help="Name of efuse field and new value pairs to burn. EFUSE_NAME: "
        "[{}].".format(", ".join([e.name for e in efuses.efuses])),
        action=ActionEfuseValuePair,
        nargs="+",
        metavar="[EFUSE_NAME VALUE]",
        efuse_choices=[e.name for e in efuses.efuses]
        + [name for e in efuses.efuses for name in e.alt_names if name != ""],
        efuses=efuses,
    )
    burn.add_argument(
        "--force",
        help="Suppress an error to burn eFuses",
        action="store_true",
    )

    read_protect_efuse = subparsers.add_parser(
        "read_protect_efuse",
        help="Disable readback for the efuse with the specified name",
    )
    read_protect_efuse.add_argument(
        "efuse_name",
        help="Name of efuse register to burn",
        nargs="+",
        choices=[e.name for e in efuses.efuses if e.read_disable_bit is not None]
        + [
            name
            for e in efuses.efuses
            if e.read_disable_bit is not None
            for name in e.alt_names
            if name != ""
        ],
    )

    write_protect_efuse = subparsers.add_parser(
        "write_protect_efuse",
        help="Disable writing to the efuse with the specified name",
    )
    write_protect_efuse.add_argument(
        "efuse_name",
        help="Name of efuse register to burn",
        nargs="+",
        choices=[e.name for e in efuses.efuses if e.write_disable_bit is not None]
        + [
            name
            for e in efuses.efuses
            if e.write_disable_bit is not None
            for name in e.alt_names
            if name != ""
        ],
    )

    burn_block_data = subparsers.add_parser(
        "burn_block_data",
        help="Burn non-key data to EFUSE blocks. "
        "(Don't use this command to burn key data for Flash Encryption or "
        "ESP32 Secure Boot V1, as the byte order of keys is swapped (use burn_key)).",
    )
    add_force_write_always(burn_block_data)
    burn_block_data.add_argument(
        "--offset", "-o", help="Byte offset in the efuse block", type=int, default=0
    )
    burn_block_data.add_argument(
        "block",
        help="Efuse block to burn.",
        action="append",
        choices=efuses.BURN_BLOCK_DATA_NAMES,
    )
    burn_block_data.add_argument(
        "datafile",
        help="File containing data to burn into the efuse block",
        action="append",
        type=argparse.FileType("rb"),
    )
    for _ in range(0, len(efuses.BURN_BLOCK_DATA_NAMES)):
        burn_block_data.add_argument(
            "block",
            help="Efuse block to burn.",
            metavar="BLOCK",
            nargs="?",
            action="append",
            choices=efuses.BURN_BLOCK_DATA_NAMES,
        )
        burn_block_data.add_argument(
            "datafile",
            nargs="?",
            help="File containing data to burn into the efuse block",
            metavar="DATAFILE",
            action="append",
            type=argparse.FileType("rb"),
        )

    set_bit_cmd = subparsers.add_parser("burn_bit", help="Burn bit in the efuse block.")
    add_force_write_always(set_bit_cmd)
    set_bit_cmd.add_argument(
        "block", help="Efuse block to burn.", choices=efuses.BURN_BLOCK_DATA_NAMES
    )
    set_bit_cmd.add_argument(
        "bit_number",
        help="Bit number in the efuse block [0..BLK_LEN-1]",
        nargs="+",
        type=int,
    )

    subparsers.add_parser(
        "adc_info",
        help="Display information about ADC calibration data stored in efuse.",
    )

    dump_cmd = subparsers.add_parser("dump", help="Dump raw hex values of all eFuses")
    dump_cmd.add_argument(
        "--format",
        help="Select the dump format: "
        "default - usual console eFuse dump; "
        "joint - all eFuse blocks are stored in one file; "
        "split - each eFuse block is placed into its own file. The tool will create multiple files based on "
        "the given --file_name (/path/blk.bin): blk0.bin, blk1.bin ... blkN.bin. Use the burn_block_data cmd "
        "to write it back to another chip.",
        choices=["default", "split", "joint"],
        default="default",
    )
    dump_cmd.add_argument(
        "--file_name",
        help="The path to the file in which to save the dump, if not specified, output to the console.",
        default=sys.stdout,
    )

    summary_cmd = subparsers.add_parser(
        "summary", help="Print human-readable summary of efuse values"
    )
    summary_cmd.add_argument(
        "--format",
        help="Select the summary format",
        choices=["summary", "json", "value_only"],
        default="summary",
    )
    summary_cmd.add_argument(
        "--file",
        help="File to save the efuse summary",
        type=argparse.FileType("w"),
        default=sys.stdout,
    )
    summary_cmd.add_argument(
        "efuses_to_show",
        help="The efuses to show. If not provided, all efuses will be shown.",
        nargs="*",
    )

    execute_scripts = subparsers.add_parser(
        "execute_scripts", help="Executes scripts to burn at one time."
    )
    execute_scripts.add_argument(
        "scripts",
        help="The special format of python scripts.",
        nargs="+",
        type=argparse.FileType("r"),
    )
    execute_scripts.add_argument(
        "--index",
        help="integer index. "
        "It allows to retrieve unique data per chip from configfiles "
        "and then burn them (ex. CUSTOM_MAC, UNIQUE_ID).",
        type=int,
    )
    execute_scripts.add_argument(
        "--configfiles",
        help="List of configfiles with data",
        nargs="?",
        action="append",
        type=argparse.FileType("r"),
    )

    check_error_cmd = subparsers.add_parser("check_error", help="Checks eFuse errors")
    check_error_cmd.add_argument(
        "--recovery",
        help="Recovery of BLOCKs after encoding errors",
        action="store_true",
    )


def add_force_write_always(p):
    p.add_argument(
        "--force-write-always",
        help="Write the efuse even if it looks like it's already been written, "
        "or is write protected. Note that this option can't disable write protection, "
        "or clear any bit which has already been set.",
        action="store_true",
    )


def add_show_sensitive_info_option(p):
    p.add_argument(
        "--show-sensitive-info",
        help="Show data to be burned (may expose sensitive data). "
        "Enabled if --debug is used.",
        action="store_true",
        default=False,
    )


def summary(esp, efuses, args):
    """Print a human-readable or json summary of efuse contents"""
    ROW_FORMAT = "%-50s %-50s%s = %s %s %s"
    human_output = args.format in ["summary", "value_only"]
    value_only = args.format == "value_only"
    if value_only and len(args.efuses_to_show) != 1:
        raise esptool.FatalError(
            "The 'value_only' format can be used exactly for one efuse."
        )
    do_filtering = bool(args.efuses_to_show)
    json_efuse = {}
    summary_efuse = []
    if args.file != sys.stdout:
        print("Saving efuse values to " + args.file.name)
    if human_output and not value_only:
        summary_efuse.append(
            ROW_FORMAT.replace("-50", "-12")
            % (
                "EFUSE_NAME (Block)",
                "Description",
                "",
                "[Meaningful Value]",
                "[Readable/Writeable]",
                "(Hex Value)",
            )
        )
        summary_efuse.append("-" * 88)
    for category in sorted(set(e.category for e in efuses), key=lambda c: c.title()):
        if human_output and not value_only:
            summary_efuse.append(f"{category.title()} fuses:")
        for e in (e for e in efuses if e.category == category):
            if e.efuse_type.startswith("bytes"):
                raw = ""
            else:
                raw = "({})".format(e.get_bitstring())
            (readable, writeable) = (e.is_readable(), e.is_writeable())
            if readable and writeable:
                perms = "R/W"
            elif readable:
                perms = "R/-"
            elif writeable:
                perms = "-/W"
            else:
                perms = "-/-"
            base_value = e.get_meaning()
            value = str(base_value)
            if not readable:
                count_read_disable_bits = e.get_count_read_disable_bits()
                if count_read_disable_bits == 2:
                    # On the C2 chip, BLOCK_KEY0 has two read protection bits [0, 1]
                    # related to the lower and higher part of the block.
                    v = [value[: (len(value) // 2)], value[(len(value) // 2) :]]
                    for i in range(count_read_disable_bits):
                        if not e.is_readable(blk_part=i):
                            v[i] = v[i].replace("0", "?")
                    value = "".join(v)
                else:
                    value = value.replace("0", "?")
            if (
                human_output
                and (not do_filtering or e.name in args.efuses_to_show)
                and not value_only
            ):
                summary_efuse.append(
                    ROW_FORMAT
                    % (
                        e.get_info(),
                        e.description[:50],
                        "\n  " if len(value) > 20 else "",
                        value,
                        perms,
                        raw,
                    )
                )
                desc_len = len(e.description[50:])
                if desc_len:
                    desc_len += 50
                    for i in range(50, desc_len, 50):
                        summary_efuse.append(
                            f"{'':<50} {e.description[i : (50 + i)]:<50}"
                        )
            elif human_output and value_only and e.name in args.efuses_to_show:
                summary_efuse.append(f"{value}")
            elif args.format == "json" and (
                not do_filtering or e.name in args.efuses_to_show
            ):
                json_efuse[e.name] = {
                    "name": e.name,
                    "value": base_value if readable else value,
                    "readable": readable,
                    "writeable": writeable,
                    "description": e.description,
                    "category": e.category,
                    "block": e.block,
                    "word": e.word,
                    "pos": e.pos,
                    "efuse_type": e.efuse_type,
                    "bit_len": e.bit_len,
                }
        if human_output and not value_only:
            # Remove empty category if efuses are filtered and there are none to show
            if do_filtering and summary_efuse[-1] == f"{category.title()} fuses:":
                summary_efuse.pop()
            else:
                summary_efuse.append("")
    if human_output and not value_only:
        summary_efuse.append(efuses.summary())
        warnings = efuses.get_coding_scheme_warnings()
        if warnings:
            summary_efuse.append(
                "WARNING: Coding scheme has encoding bit error warnings"
            )
    if human_output:
        for line in summary_efuse:
            print(line, file=args.file)
        if args.file != sys.stdout:
            args.file.close()
            print("Done")
    elif args.format == "json":
        json.dump(json_efuse, args.file, sort_keys=True, indent=4)
        print("")


def dump(esp, efuses, args):
    """Dump raw efuse data registers"""
    dump_file = args.file_name
    to_console = args.file_name == sys.stdout

    def output_block_to_file(block, f, to_console):
        block_dump = BitStream(block.get_bitstring())
        block_dump.byteswap()
        if to_console:
            f.write(block_dump.hex + "\n")
        else:
            block_dump.tofile(f)

    if args.format == "default":
        if to_console:
            # for "espefuse.py dump" cmd
            for block in efuses.blocks:
                block.print_block(block.get_bitstring(), "dump", debug=True)
            return
        else:
            # for back compatibility to support "espefuse.py dump --file_name dump.bin"
            args.format = "split"

    if args.format == "split":
        # each efuse block is placed into its own file
        for block in efuses.blocks:
            if not to_console:
                file_dump_name = args.file_name
                fname, fextension = os.path.splitext(file_dump_name)
                file_dump_name = f"{fname}{block.id}{fextension}"
                print(f"Dump efuse block{block.id} -> {file_dump_name}")
                dump_file = open(file_dump_name, "wb")
            output_block_to_file(block, dump_file, to_console)
            if not to_console:
                dump_file.close()
    elif args.format == "joint":
        # all efuse blocks are stored in one file
        if not to_console:
            print(f"Dump efuse blocks -> {args.file_name}")
            dump_file = open(args.file_name, "wb")
        for block in efuses.blocks:
            output_block_to_file(block, dump_file, to_console)
        if not to_console:
            dump_file.close()


def burn_efuse(esp, efuses, args):
    def print_attention(blocked_efuses_after_burn):
        if len(blocked_efuses_after_burn):
            print(
                "    ATTENTION! This BLOCK uses NOT the NONE coding scheme "
                "and after 'BURN', these efuses can not be burned in the feature:"
            )
            for i in range(0, len(blocked_efuses_after_burn), 5):
                print(
                    "              ",
                    "".join("{}".format(blocked_efuses_after_burn[i : i + 5 :])),
                )

    efuse_name_list = [name for name in args.name_value_pairs.keys()]
    burn_efuses_list = [efuses[name] for name in efuse_name_list]
    old_value_list = [efuses[name].get_raw() for name in efuse_name_list]
    new_value_list = [value for value in args.name_value_pairs.values()]
    util.check_duplicate_name_in_list(efuse_name_list)

    attention = ""
    print("The efuses to burn:")
    for block in efuses.blocks:
        burn_list_a_block = [e for e in burn_efuses_list if e.block == block.id]
        if len(burn_list_a_block):
            print("  from BLOCK%d" % (block.id))
            for field in burn_list_a_block:
                print("     - %s" % (field.name))
                if (
                    efuses.blocks[field.block].get_coding_scheme()
                    != efuses.REGS.CODING_SCHEME_NONE
                ):
                    using_the_same_block_names = [
                        e.name for e in efuses if e.block == field.block
                    ]
                    wr_names = [e.name for e in burn_list_a_block]
                    blocked_efuses_after_burn = [
                        name
                        for name in using_the_same_block_names
                        if name not in wr_names
                    ]
                    attention = " (see 'ATTENTION!' above)"
            if attention:
                print_attention(blocked_efuses_after_burn)

    print("\nBurning efuses{}:".format(attention))
    for efuse, new_value in zip(burn_efuses_list, new_value_list):
        print(
            "\n    - '{}' ({}) {} -> {}".format(
                efuse.name,
                efuse.description,
                efuse.get_bitstring(),
                efuse.convert_to_bitstring(new_value),
            )
        )
        efuse.save(new_value)

    print()
    if "ENABLE_SECURITY_DOWNLOAD" in efuse_name_list:
        print(
            "ENABLE_SECURITY_DOWNLOAD -> 1: eFuses will not be read back "
            "for confirmation because this mode disables "
            "any SRAM and register operations."
        )
        print("                               espefuse will not work.")
        print("                               esptool can read/write only flash.")

    if "DIS_DOWNLOAD_MODE" in efuse_name_list:
        print(
            "DIS_DOWNLOAD_MODE -> 1: eFuses will not be read back for "
            "confirmation because this mode disables any communication with the chip."
        )
        print(
            "                        espefuse/esptool will not work because "
            "they will not be able to connect to the chip."
        )

    if (
        esp.CHIP_NAME == "ESP32"
        and esp.get_chip_revision() >= 300
        and "UART_DOWNLOAD_DIS" in efuse_name_list
    ):
        print(
            "UART_DOWNLOAD_DIS -> 1: eFuses will be read for confirmation, "
            "but after that connection to the chip will become impossible."
        )
        print("                        espefuse/esptool will not work.")

    if efuses.is_efuses_incompatible_for_burn():
        if args.force:
            print("Ignore incompatible eFuse settings.")
        else:
            raise esptool.FatalError(
                "Incompatible eFuse settings detected, abort. (use --force flag to skip it)."
            )

    if not efuses.burn_all(check_batch_mode=True):
        return

    print("Checking efuses...")
    raise_error = False
    for efuse, old_value, new_value in zip(
        burn_efuses_list, old_value_list, new_value_list
    ):
        if not efuse.is_readable():
            print(
                "Efuse %s is read-protected. Read back the burn value is not possible."
                % efuse.name
            )
        else:
            new_value = efuse.convert_to_bitstring(new_value)
            burned_value = efuse.get_bitstring()
            if burned_value != new_value:
                print(
                    burned_value,
                    "->",
                    new_value,
                    "Efuse %s failed to burn. Protected?" % efuse.name,
                )
                raise_error = True
    if raise_error:
        raise esptool.FatalError("The burn was not successful.")
    else:
        print("Successful")


def read_protect_efuse(esp, efuses, args):
    util.check_duplicate_name_in_list(args.efuse_name)

    for efuse_name in args.efuse_name:
        efuse = efuses[efuse_name]
        if not efuse.is_readable():
            print("Efuse %s is already read protected" % efuse.name)
        else:
            if esp.CHIP_NAME == "ESP32":
                if (
                    efuse_name == "BLOCK2"
                    and not efuses["ABS_DONE_0"].get()
                    and esp.get_chip_revision() >= 300
                ):
                    if efuses["ABS_DONE_1"].get():
                        raise esptool.FatalError(
                            "Secure Boot V2 is on (ABS_DONE_1 = True), "
                            "BLOCK2 must be readable, stop this operation!"
                        )
                    else:
                        print(
                            "If Secure Boot V2 is used, BLOCK2 must be readable, "
                            "please stop this operation!"
                        )
            elif esp.CHIP_NAME == "ESP32-C2":
                error = (
                    not efuses["XTS_KEY_LENGTH_256"].get()
                    and efuse_name == "BLOCK_KEY0"
                )
                error |= efuses["SECURE_BOOT_EN"].get() and efuse_name in [
                    "BLOCK_KEY0",
                    "BLOCK_KEY0_HI_128",
                ]
                if error:
                    raise esptool.FatalError(
                        "%s must be readable, stop this operation!" % efuse_name
                    )
            else:
                for block in efuses.Blocks.BLOCKS:
                    block = efuses.Blocks.get(block)
                    if block.name == efuse_name and block.key_purpose is not None:
                        if not efuses[block.key_purpose].need_rd_protect(
                            efuses[block.key_purpose].get()
                        ):
                            raise esptool.FatalError(
                                "%s must be readable, stop this operation!" % efuse_name
                            )
                        break
            # make full list of which efuses will be disabled
            # (ie share a read disable bit)
            all_disabling = [
                e for e in efuses if e.read_disable_bit == efuse.read_disable_bit
            ]
            names = ", ".join(e.name for e in all_disabling)
            print(
                "Permanently read-disabling efuse%s %s"
                % ("s" if len(all_disabling) > 1 else "", names)
            )
            efuse.disable_read()

    if not efuses.burn_all(check_batch_mode=True):
        return

    print("Checking efuses...")
    raise_error = False
    for efuse_name in args.efuse_name:
        efuse = efuses[efuse_name]
        if efuse.is_readable():
            print("Efuse %s is not read-protected." % efuse.name)
            raise_error = True
    if raise_error:
        raise esptool.FatalError("The burn was not successful.")
    else:
        print("Successful")


def write_protect_efuse(esp, efuses, args):
    util.check_duplicate_name_in_list(args.efuse_name)
    for efuse_name in args.efuse_name:
        efuse = efuses[efuse_name]
        if not efuse.is_writeable():
            print("Efuse %s is already write protected" % efuse.name)
        else:
            # make full list of which efuses will be disabled
            # (ie share a write disable bit)
            all_disabling = [
                e for e in efuses if e.write_disable_bit == efuse.write_disable_bit
            ]
            names = ", ".join(e.name for e in all_disabling)
            print(
                "Permanently write-disabling efuse%s %s"
                % ("s" if len(all_disabling) > 1 else "", names)
            )
            efuse.disable_write()

    if not efuses.burn_all(check_batch_mode=True):
        return

    print("Checking efuses...")
    raise_error = False
    for efuse_name in args.efuse_name:
        efuse = efuses[efuse_name]
        if efuse.is_writeable():
            print("Efuse %s is not write-protected." % efuse.name)
            raise_error = True
    if raise_error:
        raise esptool.FatalError("The burn was not successful.")
    else:
        print("Successful")


def burn_block_data(esp, efuses, args):
    block_name_list = args.block[
        0 : len([name for name in args.block if name is not None]) :
    ]
    datafile_list = args.datafile[
        0 : len([name for name in args.datafile if name is not None]) :
    ]
    efuses.force_write_always = args.force_write_always

    util.check_duplicate_name_in_list(block_name_list)
    if args.offset and len(block_name_list) > 1:
        raise esptool.FatalError(
            "The 'offset' option is not applicable when a few blocks are passed. "
            "With 'offset', should only one block be used."
        )
    else:
        offset = args.offset
        if offset:
            num_block = efuses.get_index_block_by_name(block_name_list[0])
            block = efuses.blocks[num_block]
            num_bytes = block.get_block_len()
            if offset >= num_bytes:
                raise esptool.FatalError(
                    "Invalid offset: the block%d only holds %d bytes."
                    % (block.id, num_bytes)
                )
    if len(block_name_list) != len(datafile_list):
        raise esptool.FatalError(
            "The number of block_name (%d) and datafile (%d) should be the same."
            % (len(block_name_list), len(datafile_list))
        )

    for block_name, datafile in zip(block_name_list, datafile_list):
        num_block = efuses.get_index_block_by_name(block_name)
        block = efuses.blocks[num_block]
        data = datafile.read()
        num_bytes = block.get_block_len()
        if offset != 0:
            data = (b"\x00" * offset) + data
            data = data + (b"\x00" * (num_bytes - len(data)))
        if len(data) != num_bytes:
            raise esptool.FatalError(
                "Data does not fit: the block%d size is %d bytes, "
                "data file is %d bytes, offset %d"
                % (block.id, num_bytes, len(data), offset)
            )
        print(
            "[{:02}] {:20} size={:02} bytes, offset={:02} - > [{}].".format(
                block.id, block.name, len(data), offset, util.hexify(data, " ")
            )
        )
        block.save(data)

    if not efuses.burn_all(check_batch_mode=True):
        return
    print("Successful")


def burn_bit(esp, efuses, args):
    efuses.force_write_always = args.force_write_always
    num_block = efuses.get_index_block_by_name(args.block)
    block = efuses.blocks[num_block]
    data_block = BitStream(block.get_block_len() * 8)
    data_block.set(0)
    try:
        data_block.set(True, args.bit_number)
    except IndexError:
        raise esptool.FatalError(
            "%s has bit_number in [0..%d]" % (args.block, data_block.len - 1)
        )
    data_block.reverse()
    print(
        "bit_number:   "
        "[%-03d]........................................................[0]"
        % (data_block.len - 1)
    )
    print("BLOCK%-2d   :" % block.id, data_block)
    block.print_block(data_block, "regs_to_write", debug=True)
    block.save(data_block.bytes[::-1])

    if not efuses.burn_all(check_batch_mode=True):
        return
    print("Successful")


def get_error_summary(efuses):
    efuses.get_coding_scheme_warnings()
    error_in_blocks = any(blk.fail or blk.num_errors != 0 for blk in efuses.blocks)
    if not error_in_blocks:
        return False
    writable = True
    for blk in efuses.blocks:
        if blk.fail or blk.num_errors:
            if blk.id == 0:
                for field in efuses:
                    if field.block == blk.id and (field.fail or field.num_errors):
                        wr = "writable" if field.is_writeable() else "not writable"
                        writable &= wr == "writable"
                        name = field.name
                        val = field.get()
                        print(f"BLOCK{field.block:<2}: {name:<40} = {val:<8} ({wr})")
            else:
                wr = "writable" if blk.is_writeable() else "not writable"
                writable &= wr == "writable"
                name = f"{blk.name} [ERRORS:{blk.num_errors} FAIL:{int(blk.fail)}]"
                val = str(blk.get_bitstring())
                print(f"BLOCK{blk.id:<2}: {name:<40} = {val:<8} ({wr})")
    if not writable and error_in_blocks:
        print("Not all errors can be fixed because some fields are write-protected!")
    return True


def check_error(esp, efuses, args):
    error_in_blocks = get_error_summary(efuses)
    if args.recovery and error_in_blocks:
        confirmed = False
        for block in reversed(efuses.blocks):
            if block.fail or block.num_errors > 0:
                if not block.get_bitstring().all(False):
                    block.save(block.get_bitstring().bytes[::-1])
                    if not confirmed:
                        confirmed = True
                        efuses.confirm(
                            "Recovery of block coding errors", args.do_not_confirm
                        )
                    block.burn()
        if confirmed:
            efuses.update_efuses()
        error_in_blocks = get_error_summary(efuses)
    if error_in_blocks:
        raise esptool.FatalError("Error(s) were detected in eFuses")
    print("No errors detected")
