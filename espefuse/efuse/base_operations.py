# This file includes the common operations with eFuses for chips
#
# SPDX-FileCopyrightText: 2020-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import json
import sys
from typing import Any, Callable

import rich_click as click

from bitstring import BitStream

import esptool

from . import base_fields
from . import util


class EfuseValuePairArg(click.Argument):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def make_metavar(self) -> str:
        return f"[{super().make_metavar()}] ..."

    def type_cast_value(self, ctx: click.Context, value: list[str]):
        return self.type.convert(value, None, ctx)


class EfuseValuePairType(click.ParamType):
    name = "efuse-value-pair"

    def __init__(self, efuse_choices, efuses):
        self.efuse_choices = efuse_choices
        self.efuses = efuses

    def convert(self, value: str, param: click.Parameter | None, ctx: click.Context):
        def check_efuse_name(efuse_name: str):
            if efuse_name not in self.efuse_choices:
                raise click.BadParameter(
                    f"Invalid eFuse name '{efuse_name}'. "
                    f"Available eFuse names: {self.efuse_choices}"
                )
            return efuse_name

        # Handle single value case (eFuse name only)
        efuse_value_pairs = {}
        if len(value) > 1:
            if len(value) % 2:
                raise click.BadParameter(
                    f"The list does not have a valid pair (name value) {value}"
                )
            for i in range(0, len(value), 2):
                efuse_name: str = value[i]
                new_value: str = value[i + 1]
                efuse_name = check_efuse_name(efuse_name)
                check_arg = base_fields.CheckArgValue(self.efuses, efuse_name)
                efuse_value_pairs[efuse_name] = check_arg(new_value)

        else:
            # For the case of compatibility, when only the efuse_name is given
            # Fields with 'bitcount' and 'bool' types can be without new_value arg
            efuse_name = value[0]
            check_efuse_name(efuse_name)
            check_arg = base_fields.CheckArgValue(self.efuses, efuse_name)
            efuse_value_pairs[efuse_name] = check_arg(None)

        return efuse_value_pairs


class CustomMACType(click.ParamType):
    name = "custom_mac"

    def convert(self, value: str, param: click.Parameter | None, ctx: click.Context):
        return base_fields.CheckArgValue(ctx.obj["efuses"], "CUSTOM_MAC")(value)


class TupleParameter(click.Argument):
    def __init__(self, *args, **kwargs):
        self.max_arity = kwargs.pop("max_arity", None)
        super().__init__(*args, **kwargs)

    def make_metavar(self) -> str:
        if self.nargs == 1:
            return super().make_metavar()  # type: ignore
        if self.max_arity is None:
            return f"[{super().make_metavar()}] ..."
        return f"[{super().make_metavar()}] ... (max {self.max_arity} groups)"

    def type_cast_value(self, ctx: click.Context, value: list[str]) -> tuple[Any, ...]:
        # This is by default eating all options, so we need to check for help option
        if any(v in ctx.help_option_names for v in value):
            # show help
            click.echo(ctx.get_help())
            ctx.exit()

        # Check if we have more values than allowed by max_arity
        if len(value) > self.max_arity * self.type.arity:
            raise click.BadParameter(
                f"Expected at most {self.max_arity} groups ({self.type.arity} values "
                f"each), got {len(value)} (values: {value})"
            )

        # check that the number of values is a multiple of self.type.arity
        if len(value) % self.type.arity != 0:
            raise click.BadParameter(
                f"Expected multiple of {self.type.arity} values, got {len(value)} "
                f"(values: {value})"
            )

        # split value into groups of self.type.arity and call convert() for each group
        groups = [
            value[i : i + self.type.arity]
            for i in range(0, len(value), self.type.arity)
        ]
        return tuple(self.type.convert(group, None, ctx) for group in groups)


class NonCompositeTuple(click.Tuple):
    is_composite = False  # Hack to work around click's default nargs=1

    def __init__(self, types):
        super().__init__(types)


def add_force_write_always(function: Callable):
    def callback(ctx: click.Context, param: click.Parameter, value: str):
        ctx.ensure_object(dict)
        if ctx.obj.get("commands", None) is not None:
            ctx.obj["commands"].efuses.force_write_always = value

    return click.option(
        "--force-write-always",
        help="Write the eFuse even if it looks like it's already been written, "
        "or is write protected. Note that this option can't disable write protection, "
        "or clear any bit which has already been set.",
        is_flag=True,
        callback=callback,
    )(function)


def add_show_sensitive_info_option(function: Callable):
    # TODO: originally this parameter worked for all commands even if it was
    # specified for a one of them
    def callback(ctx: click.Context, param: click.Parameter, value: bool):
        if value or ctx.obj.get("debug"):
            value = True
        else:
            print("Sensitive data will be hidden (see --show-sensitive-info)")
        return value

    return click.option(
        "--show-sensitive-info",
        help="Show data to be burned (may expose sensitive data). "
        "Enabled if --debug is used.",
        is_flag=True,
        callback=callback,
    )(function)


def protect_options(function: Callable):
    function = click.option(
        "--no-write-protect",
        help="Disable write-protecting of the key. The key remains writable. "
        "(The keys use the RS coding scheme that does not support "
        "post-write data changes. Forced write can damage RS encoding bits.) "
        "The write-protecting of keypurposes does not depend on the option, "
        "it will be set anyway.",
        is_flag=True,
    )(function)
    function = click.option(
        "--no-read-protect",
        help="Disable read-protecting of the key. The key remains readable software.",
        is_flag=True,
    )(function)
    return function


class BaseCommands:
    def __init__(self) -> None:
        self._efuses: base_fields.EspEfusesBase | None = None

    @property
    def efuses(self):
        if self._efuses is None:
            raise ValueError("Make sure that efuses property is set.")
        return self._efuses

    @efuses.setter
    def efuses(self, efuses: base_fields.EspEfusesBase):
        self._efuses = efuses

    ################################# CLI definitions #################################

    def add_cli_commands(self, cli: click.Group):
        efuses: list[base_fields.EfuseFieldBase] = getattr(self.efuses, "efuses", [])

        @cli.command(
            "burn-efuse",
            help="Burn the eFuse with the specified name.\n\n"
            f"Allowed options for EFUSE_NAME: [{', '.join([e.name for e in efuses])}].",
        )
        @click.argument(
            "name_value_pairs",
            cls=EfuseValuePairArg,
            metavar="<EFUSE_NAME> <VALUE>",
            required=True,
            nargs=-1,
            type=EfuseValuePairType(
                [e.name for e in efuses]
                + [name for e in efuses for name in e.alt_names if name != ""],
                self.efuses,
            ),
        )
        @click.option("--force", is_flag=True, help="Suppress an error to burn eFuses")
        @click.pass_context
        def burn_efuse_cli(ctx, name_value_pairs, force):
            self.burn_efuse(ctx.obj["esp"], name_value_pairs, force)

        @cli.command(
            "read-protect-efuse",
            help="Disable readback for the eFuse with the specified name",
            short_help="Disable readback for the eFuse.",
        )
        @click.argument("efuse_name", nargs=-1, required=True)
        @click.pass_context
        def read_protect_efuse_cli(ctx, efuse_name):
            self.read_protect_efuse(ctx.obj["esp"], efuse_name)

        @cli.command(
            "write-protect-efuse",
            help="Disable writing to the eFuse with the specified name",
            short_help="Disable writing to the eFuse.",
        )
        @click.argument("efuse_name", nargs=-1, required=True)
        def write_protect_efuse_cli(efuse_name):
            """Disable writing to the eFuse with the specified name"""
            self.write_protect_efuse(efuse_name)

        @cli.command(
            "burn-block-data",
            help="Burn non-key data to EFUSE blocks. "
            "(Don't use this command to burn key data for Flash Encryption or ESP32 "
            "Secure Boot V1, as the byte order of keys is swapped (use burn_key)).\n\n"
            "Allowed options for BLOCK: "
            f"[{', '.join(self.efuses.BURN_BLOCK_DATA_NAMES)}].",
        )
        @click.argument(
            "block_datafile",
            cls=TupleParameter,
            metavar="<BLOCK> <DATAFILE>",
            required=True,
            nargs=-1,
            max_arity=len(self.efuses.BURN_BLOCK_DATA_NAMES),
            type=NonCompositeTuple(
                [
                    click.Choice(self.efuses.BURN_BLOCK_DATA_NAMES),
                    click.File("rb"),
                ]
            ),
        )
        # help="File containing data to burn into the eFuse block"
        @click.option(
            "--offset", "-o", type=int, default=0, help="Byte offset in the eFuse block"
        )
        @add_force_write_always
        def burn_block_data_cli(block_datafile, offset, **kwargs):
            block, datafile = zip(*block_datafile)
            self.burn_block_data(block, datafile, offset)

        @cli.command("burn-bit")
        @click.argument("block", required=True)
        @click.argument(
            "bit_number",
            nargs=-1,
            type=int,
            required=True,
        )
        @add_force_write_always
        def burn_bit_cli(block, bit_number, **kwargs):
            """Burn bit in the eFuse block."""
            self.burn_bit(block, bit_number)

        @cli.command("dump")
        @click.option(
            "--format",
            type=click.Choice(["default", "split", "joint"]),
            default="default",
            help="Select the dump format: default - usual console eFuse dump; "
            "joint - all eFuse blocks are stored in one file; "
            "split - each eFuse block is placed into its own file.",
        )
        @click.option(
            "--file_name",
            type=click.Path(exists=True, writable=True),
            default=sys.stdout,
            help="The path to the file in which to save the dump, if not specified, "
            "output to the console.",
        )
        def dump_cli(format, file_name):
            """Dump raw hex values of all eFuses."""
            file = file_name.name if file_name != sys.stdout else file_name
            self.dump(format, file)

        @cli.command("summary")
        @click.argument(
            "efuses_to_show", nargs=-1, required=False
        )  # help="The efuses to show. If not provided, all efuses will be shown."
        @click.option(
            "--format",
            type=click.Choice(["summary", "json", "value_only"]),
            default="summary",
            help="Select the summary format",
        )
        @click.option(
            "--file",
            type=click.File("w"),
            default=sys.stdout,
            help="File to save the eFuse summary",
        )
        def summary_cli(format, file, efuses_to_show=[]):
            """Print human-readable summary of eFuse values."""
            self.summary(efuses_to_show, format, file)

        @cli.command("execute-scripts")
        @click.argument(
            "scripts", nargs=-1, type=click.File("r"), required=True
        )  # help="The special format of python scripts."
        @click.option(
            "--index",
            type=int,
            help="integer index. It allows to retrieve unique data per chip "
            "from configfiles and then burn them (ex. CUSTOM_MAC, UNIQUE_ID).",
        )
        @click.option(
            "--configfiles",
            type=click.File("r"),
            multiple=True,
            help="List of configfiles with data",
        )
        @click.pass_context
        def execute_scripts_cli(ctx, scripts, index, configfiles):
            """Executes scripts to burn at one time."""
            self.execute_scripts(scripts, ctx.obj["debug"], configfiles, index)

        @cli.command("check-error")
        @click.option(
            "--recovery", is_flag=True, help="Recovery of BLOCKs after encoding errors"
        )
        @click.pass_context
        def check_error_cli(ctx, recovery):
            """Checks eFuse errors."""
            self.check_error(recovery, ctx.obj["do_not_confirm"])

        @cli.command(
            "adc-info",
            short_help="Display information about ADC calibration data "
            "stored in eFuse.",
            help="Display information about ADC calibration data stored in eFuse.",
        )
        def adc_info_cli():
            self.adc_info()

        @cli.command(
            "burn-custom-mac",
            short_help="Burn a 48-bit Custom MAC Address.",
            help="Burn a 48-bit Custom MAC Address to EFUSE "
            f"BLOCK{self.efuses['CUSTOM_MAC'].block}. "
            "Mac address should be given in hexadecimal format with bytes separated "
            "by colons (e.g. AA:CD:EF:01:02:03).",
        )
        @click.argument(
            "mac",
            type=CustomMACType(),
        )
        @add_force_write_always
        def burn_custom_mac_cli(mac, **kwargs):
            self.burn_custom_mac(mac)

        @cli.command("get-custom-mac")
        def get_custom_mac_cli():
            """Get the 48-bit Custom MAC Address."""
            self.get_custom_mac()

    ##################################### Commands ####################################

    def summary(self, efuses_to_show, format, file):
        """Print a human-readable or json summary of eFuse contents"""
        ROW_FORMAT = "%-50s %-50s%s = %s %s %s"
        human_output = format in ["summary", "value_only"]
        value_only = format == "value_only"
        if value_only and len(efuses_to_show) != 1:
            raise esptool.FatalError(
                "The 'value_only' format can be used exactly for one eFuse."
            )
        do_filtering = bool(efuses_to_show)
        json_efuse = {}
        summary_efuse = []
        if file != sys.stdout:
            print("Saving eFuse values to " + file.name)
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
        for category in sorted(
            set(e.category for e in self.efuses), key=lambda c: c.title()
        ):
            if human_output and not value_only:
                summary_efuse.append(f"{category.title()} fuses:")
            for e in (e for e in self.efuses if e.category == category):
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
                    and (not do_filtering or e.name in efuses_to_show)
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
                elif human_output and value_only and e.name in efuses_to_show:
                    summary_efuse.append(f"{value}")
                elif format == "json" and (
                    not do_filtering or e.name in efuses_to_show
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
                # Remove empty category when filtered efuses have none to show
                if do_filtering and summary_efuse[-1] == f"{category.title()} fuses:":
                    summary_efuse.pop()
                else:
                    summary_efuse.append("")
        if human_output and not value_only:
            summary_efuse.append(self.efuses.summary())
            warnings = self.efuses.get_coding_scheme_warnings()
            if warnings:
                summary_efuse.append(
                    "WARNING: Coding scheme has encoding bit error warnings"
                )
        if human_output:
            for line in summary_efuse:
                print(line, file=file)
            if file != sys.stdout:
                file.close()
                print("Done")
        elif format == "json":
            json.dump(json_efuse, file, sort_keys=True, indent=4)
            print("")

    def dump(self, format, file_name):
        """Dump raw eFuse data registers"""
        dump_file = file_name
        to_console = file_name == sys.stdout

        def output_block_to_file(block, f, to_console):
            block_dump = BitStream(block.get_bitstring())
            block_dump.byteswap()
            if to_console:
                f.write(block_dump.hex + "\n")
            else:
                block_dump.tofile(f)

        if format == "default":
            if to_console:
                # for "espefuse.py dump" cmd
                for block in self.efuses.blocks:
                    block.print_block(block.get_bitstring(), "dump", debug=True)
                return
            else:
                # for back compatibility to support
                # "espefuse.py dump --file_name dump.bin"
                format = "split"

        if format == "split":
            # each eFuse block is placed into its own file
            for block in self.efuses.blocks:
                if not to_console:
                    file_dump_name = file_name
                    fname, fextension = os.path.splitext(file_dump_name)
                    file_dump_name = f"{fname}{block.id}{fextension}"
                    print(f"Dump eFuse block{block.id} -> {file_dump_name}")
                    dump_file = open(file_dump_name, "wb")
                output_block_to_file(block, dump_file, to_console)
                if not to_console:
                    dump_file.close()
        elif format == "joint":
            # all eFuse blocks are stored in one file
            if not to_console:
                print(f"Dump eFuse blocks -> {file_name}")
                dump_file = open(file_name, "wb")
            for block in self.efuses.blocks:
                output_block_to_file(block, dump_file, to_console)
            if not to_console:
                dump_file.close()

    def burn_efuse(self, esp, name_value_pairs, force):
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

        efuse_name_list = [name for name in name_value_pairs.keys()]
        burn_efuses_list = [self.efuses[name] for name in efuse_name_list]
        old_value_list = [self.efuses[name].get_raw() for name in efuse_name_list]
        new_value_list = [value for value in name_value_pairs.values()]
        util.check_duplicate_name_in_list(efuse_name_list)

        attention = ""
        print("The efuses to burn:")
        for block in self.efuses.blocks:
            burn_list_a_block = [e for e in burn_efuses_list if e.block == block.id]
            if len(burn_list_a_block):
                print("  from BLOCK%d" % (block.id))
                for field in burn_list_a_block:
                    print("     - %s" % (field.name))
                    if (
                        self.efuses.blocks[field.block].get_coding_scheme()
                        != self.efuses.REGS.CODING_SCHEME_NONE
                    ):
                        using_the_same_block_names = [
                            e.name for e in self.efuses if e.block == field.block
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
                "DIS_DOWNLOAD_MODE -> 1: eFuses will not be read back for confirmation "
                "because this mode disables any communication with the chip."
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

        if self.efuses.is_efuses_incompatible_for_burn():
            if force:
                print("Ignore incompatible eFuse settings.")
            else:
                raise esptool.FatalError(
                    "Incompatible eFuse settings detected, abort. "
                    "(use --force flag to skip it)."
                )

        if not self.efuses.burn_all(check_batch_mode=True):
            return

        print("Checking efuses...")
        raise_error = False
        for efuse, old_value, new_value in zip(
            burn_efuses_list, old_value_list, new_value_list
        ):
            if not efuse.is_readable():
                print(
                    f"Efuse {efuse.name} is read-protected. "
                    "Read back the burn value is not possible."
                )
            else:
                new_value = efuse.convert_to_bitstring(new_value)
                burned_value = efuse.get_bitstring()
                if burned_value != new_value:
                    print(
                        burned_value,
                        "->",
                        new_value,
                        f"Efuse {efuse.name} failed to burn. Protected?",
                    )
                    raise_error = True
        if raise_error:
            raise esptool.FatalError("The burn was not successful.")
        else:
            print("Successful")

    def read_protect_efuse(self, esp, efuse_names):
        util.check_duplicate_name_in_list(efuse_names)

        for efuse_name in efuse_names:
            efuse = self.efuses[efuse_name]
            if not efuse.is_readable():
                print("Efuse %s is already read protected" % efuse.name)
            else:
                if esp.CHIP_NAME == "ESP32":
                    if (
                        efuse_name == "BLOCK2"
                        and not self.efuses["ABS_DONE_0"].get()
                        and esp.get_chip_revision() >= 300
                    ):
                        if self.efuses["ABS_DONE_1"].get():
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
                        not self.efuses["XTS_KEY_LENGTH_256"].get()
                        and efuse_name == "BLOCK_KEY0"
                    )
                    error |= self.efuses["SECURE_BOOT_EN"].get() and efuse_name in [
                        "BLOCK_KEY0",
                        "BLOCK_KEY0_HI_128",
                    ]
                    if error:
                        raise esptool.FatalError(
                            "%s must be readable, stop this operation!" % efuse_name
                        )
                else:
                    for block in self.efuses.Blocks.BLOCKS:
                        block = self.efuses.Blocks.get(block)
                        if block.name == efuse_name and block.key_purpose is not None:
                            if not self.efuses[block.key_purpose].need_rd_protect(
                                self.efuses[block.key_purpose].get()
                            ):
                                raise esptool.FatalError(
                                    "%s must be readable, stop this operation!"
                                    % efuse_name
                                )
                            break
                # make full list of which efuses will be disabled
                # (ie share a read disable bit)
                all_disabling = [
                    e
                    for e in self.efuses
                    if e.read_disable_bit == efuse.read_disable_bit
                ]
                names = ", ".join(e.name for e in all_disabling)
                print(
                    "Permanently read-disabling eFuse%s %s"
                    % ("s" if len(all_disabling) > 1 else "", names)
                )
                efuse.disable_read()

        if not self.efuses.burn_all(check_batch_mode=True):
            return

        print("Checking efuses...")
        raise_error = False
        for efuse_name in efuse_names:
            efuse = self.efuses[efuse_name]
            if efuse.is_readable():
                print("Efuse %s is not read-protected." % efuse.name)
                raise_error = True
        if raise_error:
            raise esptool.FatalError("The burn was not successful.")
        else:
            print("Successful")

    def write_protect_efuse(self, efuse_names):
        util.check_duplicate_name_in_list(efuse_names)
        for efuse_name in efuse_names:
            efuse = self.efuses[efuse_name]
            if not efuse.is_writeable():
                print("Efuse %s is already write protected" % efuse.name)
            else:
                # make full list of which efuses will be disabled
                # (ie share a write disable bit)
                all_disabling = [
                    e
                    for e in self.efuses
                    if e.write_disable_bit == efuse.write_disable_bit
                ]
                names = ", ".join(e.name for e in all_disabling)
                print(
                    "Permanently write-disabling eFuse%s %s"
                    % ("s" if len(all_disabling) > 1 else "", names)
                )
                efuse.disable_write()

        if not self.efuses.burn_all(check_batch_mode=True):
            return

        print("Checking efuses...")
        raise_error = False
        for efuse_name in efuse_names:
            efuse = self.efuses[efuse_name]
            if efuse.is_writeable():
                print("Efuse %s is not write-protected." % efuse.name)
                raise_error = True
        if raise_error:
            raise esptool.FatalError("The burn was not successful.")
        else:
            print("Successful")

    def burn_block_data(self, block_names, datafiles, offset):
        block_name_list = block_names[
            0 : len([name for name in block_names if name is not None]) :
        ]
        datafile_list = datafiles[
            0 : len([name for name in datafiles if name is not None]) :
        ]

        util.check_duplicate_name_in_list(block_name_list)
        if offset and len(block_name_list) > 1:
            raise esptool.FatalError(
                "The 'offset' option is not applicable when a few blocks are passed. "
                "With 'offset', should only one block be used."
            )
        else:
            if offset:
                num_block = self.efuses.get_index_block_by_name(block_name_list[0])
                block = self.efuses.blocks[num_block]
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
            num_block = self.efuses.get_index_block_by_name(block_name)
            block = self.efuses.blocks[num_block]
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

        if not self.efuses.burn_all(check_batch_mode=True):
            return
        print("Successful")

    def burn_bit(self, block, bit_number):
        num_block = self.efuses.get_index_block_by_name(block)
        block = self.efuses.blocks[num_block]
        data_block = BitStream(block.get_block_len() * 8)
        data_block.set(0)
        try:
            data_block.set(True, bit_number)
        except IndexError:
            raise esptool.FatalError(
                "%s has bit_number in [0..%d]" % (block, data_block.len - 1)
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

        if not self.efuses.burn_all(check_batch_mode=True):
            return
        print("Successful")

    def get_error_summary(self):
        self.efuses.get_coding_scheme_warnings()
        error_in_blocks = any(
            blk.fail or blk.num_errors != 0 for blk in self.efuses.blocks
        )
        if not error_in_blocks:
            return False
        writable = True
        for blk in self.efuses.blocks:
            if blk.fail or blk.num_errors:
                if blk.id == 0:
                    for field in self.efuses:
                        if field.block == blk.id and (field.fail or field.num_errors):
                            wr = "writable" if field.is_writeable() else "not writable"
                            writable &= wr == "writable"
                            name = field.name
                            val = field.get()
                            print(
                                f"BLOCK{field.block:<2}: {name:<40} = {val:<8} ({wr})"
                            )
                else:
                    wr = "writable" if blk.is_writeable() else "not writable"
                    writable &= wr == "writable"
                    name = f"{blk.name} [ERRORS:{blk.num_errors} FAIL:{int(blk.fail)}]"
                    val = str(blk.get_bitstring())
                    print(f"BLOCK{blk.id:<2}: {name:<40} = {val:<8} ({wr})")
        if not writable and error_in_blocks:
            print(
                "Not all errors can be fixed because some fields are write-protected!"
            )
        return True

    def check_error(self, recovery, do_not_confirm):
        error_in_blocks = self.get_error_summary()
        if recovery and error_in_blocks:
            confirmed = False
            for block in reversed(self.efuses.blocks):
                if block.fail or block.num_errors > 0:
                    if not block.get_bitstring().all(False):
                        block.save(block.get_bitstring().bytes[::-1])
                        if not confirmed:
                            confirmed = True
                            self.efuses.confirm(
                                "Recovery of block coding errors", do_not_confirm
                            )
                        block.burn()
            if confirmed:
                self.efuses.update_efuses()
            error_in_blocks = self.get_error_summary()
        if error_in_blocks:
            raise esptool.FatalError("Error(s) were detected in eFuses")
        print("No errors detected")

    def execute_scripts(self, scripts, debug, configfiles, index):
        raise NotImplementedError("execute_scripts is not implemented")

    def burn_custom_mac(self, mac):
        self.efuses["CUSTOM_MAC"].save(mac)
        if not self.efuses.burn_all(check_batch_mode=True):
            return
        self.get_custom_mac()
        print("Successful")

    def get_custom_mac(self):
        print(f"Custom MAC Address: {self.efuses['CUSTOM_MAC'].get()}")

    def set_flash_voltage(self, voltage):
        raise esptool.FatalError("set_flash_voltage is not supported for this chip")

    def adc_info(self):
        raise NotImplementedError("adc_info is not implemented for this chip")
