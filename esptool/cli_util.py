# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later


import rich_click as click

from esptool.bin_image import ESPLoader, intel_hex_to_bin
from esptool.cmds import detect_flash_size
from esptool.util import FatalError, flash_size_bytes, strip_chip_name
from esptool.logger import log
from typing import Any

################################ Custom types #################################


class ChipType(click.Choice):
    """Custom type to accept chip names in any case and with or without hyphen"""

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> Any:
        value = strip_chip_name(value)
        return super().convert(value, param, ctx)


class AnyIntType(click.ParamType):
    """Custom type to parse any integer value - decimal, hex, octal, or binary"""

    name = "integer"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> int:
        if isinstance(value, int):  # default value is already an int
            return value
        try:
            return arg_auto_int(value)
        except ValueError:
            raise click.BadParameter(f"{value!r} is not a valid integer")


class AutoSizeType(AnyIntType):
    """Similar to AnyIntType but allows 'all' as a value to e.g. read whole flash"""

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> Any:
        if value.lower() == "all":
            return value
        return super().convert(value, param, ctx)


class AutoChunkSizeType(AnyIntType):
    """Custom type for chunk size that must be 4-byte aligned"""

    name = "integer"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> int:
        num = super().convert(value, param, ctx)
        if num & 3 != 0:
            raise click.BadParameter("Chunk size should be a 4-byte aligned number")
        return num


class SpiConnectionType(click.ParamType):
    """
    Custom type to parse 'spi connection' override.
    Values are SPI, HSPI, or a sequence of 5 pin numbers separated by commas.
    """

    name = "spi-connection"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> str | tuple[int, int, int, int, int]:
        if value.upper() in ["SPI", "HSPI"]:
            return value.upper()
        elif "," in value:
            values = value.split(",")
            if len(values) != 5:
                raise click.BadParameter(
                    f"{value} is not a valid list of comma-separated pin numbers. "
                    "Must be 5 numbers - CLK,Q,D,HD,CS.",
                )
            try:
                return tuple(arg_auto_int(v) for v in values)  # type: ignore
            except ValueError:
                raise click.BadParameter(
                    f"{values} is not a valid argument. "
                    "All pins must be numeric values",
                )
        else:
            raise click.BadParameter(
                f"{value} is not a valid spi-connection value. "
                "Values are SPI, HSPI, or a sequence of 5 pin numbers - CLK,Q,D,HD,CS.",
            )


class AutoHex2BinType(click.Path):
    """Custom type for auto conversion of input files from hex to bin"""

    def __init__(self, exists=True):
        super().__init__(exists=exists)

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> str:
        try:
            with open(value, "rb") as f:
                # if hex file was detected replace hex file with converted temp bin
                # otherwise keep the original file
                return intel_hex_to_bin(f).name
        except IOError as e:
            raise click.BadParameter(str(e))


class AddrFilenamePairType(click.Path):
    """Custom type for the address/filename pairs passed as arguments"""

    name = "addr-filename-pair"

    def get_metavar(self, param):
        return "<address> <filename>"

    def convert(
        self,
        value: list[str],
        param: click.Parameter | None,
        ctx: click.Context,
    ):
        if len(value) % 2 != 0:
            raise click.BadParameter(
                "Must be pairs of an address and the binary filename to write there",
            )
        if len(value) == 0:
            return value

        pairs = []
        for i in range(0, len(value), 2):
            try:
                address = arg_auto_int(value[i])
            except ValueError:
                raise click.BadParameter(f'Address "{value[i]}" must be a number')
            try:
                # Store file handle in context for later cleanup
                if not hasattr(ctx, "_open_files"):
                    ctx._open_files = []
                argfile_f = open(value[i + 1], "rb")
                ctx._open_files.append(argfile_f)
            except IOError as e:
                raise click.BadParameter(str(e))
            # check for intel hex files and convert them to bin
            argfile = intel_hex_to_bin(argfile_f, address)
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
                raise click.BadParameter(
                    f"Detected overlap at address: "
                    f"{address:#x} for file: {argfile.name}",
                )
            end = sector_end
        return pairs


########################### Custom option/argument ############################


class Group(click.RichGroup):
    def __call__(self, esp: ESPLoader | None = None, *args, **kwargs):
        self._esp = esp  # store the external esp object in the group
        return super().__call__(*args, **kwargs)

    def parse_args(self, ctx: click.Context, args: list[str]):
        """Set a flag if --help is used to skip the main"""
        ctx.esp = self._esp
        ctx._commands_list = self.list_commands(ctx)  # used for EatAllOptions
        return super().parse_args(ctx, args)


class AddrFilenameArg(click.Argument):
    """Parse arguments as list instead of each value individually"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = AddrFilenamePairType()

    def type_cast_value(self, ctx: click.Context, value: list[str]):
        return self.type.convert(value, None, ctx)


class OptionEatAll(click.Option):
    """Grab all arguments up to the next option/command.
    Imitates argparse nargs='*' for options."""

    def __init__(self, *args, **kwargs):
        super(OptionEatAll, self).__init__(*args, **kwargs)
        self._previous_parser_process = None
        self._eat_all_parser = None
        # Set the metavar dynamically based on the type's metavar
        if self.type and hasattr(self.type, "name"):
            self.metavar = f"[{self.type.get_metavar(None) or self.type.name.upper()}]"

    def add_to_parser(self, parser, ctx):
        def parser_process(value, state):
            # Method to hook into the parser.process
            done = False
            value = [value]
            # Grab everything up to the next option/command
            while state.rargs and not done:
                for prefix in self._eat_all_parser.prefixes:
                    if state.rargs[0].startswith(prefix):
                        done = True
                        break
                if state.rargs[0] in self._commands_list:
                    done = True
                if not done:
                    value.append(state.rargs.pop(0))

            # Call the original parser process method on the rest of the arguments
            self._previous_parser_process(value, state)

        retval = super(OptionEatAll, self).add_to_parser(parser, ctx)
        for name in self.opts:
            # Get the parser for the current option
            current_parser = parser._long_opt.get(name) or parser._short_opt.get(name)
            if current_parser:
                # Replace the parser.process with our hook
                self._eat_all_parser = current_parser
                self._previous_parser_process = current_parser.process
                current_parser.process = parser_process
                # Avoid reading commands as arguments if this class was used before cmd
                self._commands_list = getattr(ctx, "_commands_list", [])
                break
        return retval


class MutuallyExclusiveOption(click.Option):
    """Custom option class to enforce mutually exclusive options in click.
    Similar to argparse function `add_mutually_exclusive_group`.

    This class ensures that certain options cannot be used together by raising
    a UsageError if mutually exclusive options are provided.

    For example, `--compress` and `--no-compress` are mutually exclusive options.
    """

    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop("exclusive_with", []))
        if self.mutually_exclusive:
            ex_str = ", ".join(
                [self._to_option_name(opt) for opt in self.mutually_exclusive]
            )
            kwargs["help"] = (
                f"{kwargs.get('help', '')} NOTE: This argument is mutually exclusive "
                f"with arguments: {ex_str}."
            )
        super(MutuallyExclusiveOption, self).__init__(*args, **kwargs)

    def _to_option_name(self, name: str) -> str:
        """Convert dictionary entry for option ('my_name') to click option name
        ('--my-name'). Add '--' prefix and replace '_' with '-'. This is assuming
        options don't use '_'."""
        return f"--{name.replace('_', '-')}"

    def handle_parse_result(self, ctx, opts, args):
        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            options = ", ".join(
                [self._to_option_name(opt) for opt in self.mutually_exclusive]
            )
            raise click.UsageError(
                f"Illegal usage: {self._to_option_name(self.name)} is mutually "
                f"exclusive with arguments: {options}."
            )
        return super(MutuallyExclusiveOption, self).handle_parse_result(ctx, opts, args)


############################## Helper functions ###############################


def arg_auto_int(x: str) -> int:
    """Parse an integer value in any base"""
    return int(x, 0)


def parse_port_filters(
    value: list[str],
) -> tuple[list[int], list[int], list[str], list[str]]:
    """Parse port filter arguments into separate lists for each filter type"""
    filterVids = []
    filterPids = []
    filterNames = []
    filterSerials = []
    for f in value:
        kvp = f.split("=")
        if len(kvp) != 2:
            FatalError("Option --port-filter argument must consist of key=value")
        if kvp[0] == "vid":
            filterVids.append(arg_auto_int(kvp[1]))
        elif kvp[0] == "pid":
            filterPids.append(arg_auto_int(kvp[1]))
        elif kvp[0] == "name":
            filterNames.append(kvp[1])
        elif kvp[0] == "serial":
            filterSerials.append(kvp[1])
        else:
            raise FatalError("Option --port-filter argument key not recognized")
    return filterVids, filterPids, filterNames, filterSerials


def parse_size_arg(esp: ESPLoader, size: int | str) -> int:
    """Parse the flash size argument and return the size in bytes"""
    if isinstance(size, int):
        return size
    if size.lower() != "all":
        raise FatalError(f"Invalid size value: {size}. Use an integer or 'all'.")
    if esp.secure_download_mode:
        raise FatalError(
            "Detecting flash size is not supported in secure download mode. "
            "Set an exact size value.",
        )
    size_str = detect_flash_size(esp)
    if size_str is None:
        raise FatalError("Detecting flash size failed. Set an exact size value.")
    log.print(f"Detected flash size: {size_str}")
    return flash_size_bytes(size_str)  # type: ignore # size_str is not None
