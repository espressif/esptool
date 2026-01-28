# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later


import os
import sys
import rich_click as click

from esptool.bin_image import ESPLoader, intel_hex_to_bin
from esptool.cmds import detect_flash_size
from esptool.util import FatalError, flash_size_bytes, strip_chip_name
from esptool.logger import log
from esptool.loader import list_ports, ListPortInfo
from typing import IO, Any

from click.shell_completion import CompletionItem

################################ Custom types #################################


class ChipType(click.Choice):
    """Custom type to accept chip names in any case and with or without hyphen"""

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> Any:
        value = strip_chip_name(value)
        return super().convert(value, param, ctx)


class ResetModeType(click.Choice):
    """Custom type to accept reset mode names with underscores as separators
    for compatibility with v4"""

    def convert(self, value: str, param: click.Parameter, ctx: click.Context) -> Any:
        if "_" in value:
            new_value = value.replace("_", "-")
            if new_value not in self.choices:
                raise click.BadParameter(f"{value} is not a valid reset mode.")
            log.warning(
                f"Deprecated: Choice '{value}' for option '--{param.name}' is "
                f"deprecated. Use '{new_value}' instead."
            )
            return new_value
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
            raise click.BadParameter(f"{value!r} is not a valid integer.")


class AutoSizeType(AnyIntType):
    """Similar to AnyIntType but allows 'k', 'M' suffixes for kilo(1024), Mega(1024^2)
    and 'all' as a value to e.g. read whole flash"""

    def __init__(self, allow_all: bool = True):
        self.allow_all = allow_all
        super().__init__()

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> Any:
        if self.allow_all and value.lower() == "all":
            return value
        # Handle suffixes like 'k', 'M' for kilo, mega
        if value[-1] in ("k", "M"):
            try:
                num = arg_auto_int(value[:-1])
            except ValueError:
                raise click.BadParameter(f"{value!r} is not a valid integer")
            if value[-1] == "k":
                num *= 1024
            elif value[-1] == "M":
                num *= 1024 * 1024
            return num
        return super().convert(value, param, ctx)


class AutoChunkSizeType(AnyIntType):
    """Custom type for chunk size that must be 4-byte aligned"""

    name = "integer"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> int:
        num = super().convert(value, param, ctx)
        if num & 3 != 0:
            raise click.BadParameter("Chunk size should be a 4-byte aligned number.")
        return num


class SerialPortType(click.ParamType):
    """
    Custom type for serial port with autocomplete support.
    Provides shell completion for available serial ports.
    """

    name = "serial-port"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> str:
        # Just return the value as-is, validation happens elsewhere
        return value

    def shell_complete(
        self, ctx: click.Context, param: click.Parameter, incomplete: str
    ) -> list[CompletionItem]:
        """Provide shell completion suggestions for serial ports"""
        available_ports = _get_port_list()
        # Filter ports that match the incomplete string (case-insensitive)
        incomplete_lower = incomplete.lower()
        return [
            CompletionItem(
                port.device,
                help=f"Description: {port.description}, "
                f"VID: {port.vid}, PID: {port.pid}"
                # Avoid printing None values
                if port.vid is not None
                else None,
            )
            for port in reversed(available_ports)
            if port.device.lower().startswith(incomplete_lower)
        ]


class BaudRateType(click.ParamType):
    """Custom type for baud rate with autocomplete support"""

    name = "baud-rate"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context
    ) -> int:
        return int(value)

    def shell_complete(
        self, ctx: click.Context, param: click.Parameter, incomplete: str
    ) -> list[CompletionItem]:
        """Provide shell completion suggestions for common baud rates"""
        available_baud_rates = [9600, 115200, 230400, 460800, 576000, 921600]
        return [CompletionItem(str(baud)) for baud in available_baud_rates]


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
                    "All pins must be numeric values.",
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
    ) -> list[tuple[int | None, IO[bytes]]]:
        try:
            with open(value, "rb") as f:
                # if hex file was detected replace hex file with converted temp bin
                # otherwise keep the original file
                return intel_hex_to_bin(f)
        except OSError as e:
            raise click.BadParameter(str(e))


class AddrFilenamePairType(click.Path):
    """Custom type for the address/filename pairs passed as arguments"""

    name = "addr-filename-pair"

    def get_metavar(
        self, param: click.Parameter | None, ctx: click.Context | None = None
    ):
        return "<address> <filename>"

    def convert(
        self,
        value: list[str],
        param: click.Parameter | None,
        ctx: click.Context,
    ):
        if len(value) % 2 != 0:
            raise click.BadParameter(
                "Must be pairs of an address and the binary filename to write there.",
            )
        if len(value) == 0:
            return value

        pairs: list[tuple[int, IO[bytes]]] = []
        for i in range(0, len(value), 2):
            try:
                address = arg_auto_int(value[i])
            except ValueError:
                raise click.BadParameter(f'Address "{value[i]}" must be a number.')
            try:
                # Store file handle in context for later cleanup
                if not hasattr(ctx, "_open_files"):
                    ctx._open_files = []
                argfile_f = open(value[i + 1], "rb")
                ctx._open_files.append(argfile_f)
            except OSError as e:
                raise click.BadParameter(str(e))
            # check for intel hex files and convert them to bin
            argfile_list = intel_hex_to_bin(argfile_f, address)
            pairs.extend(argfile_list)  # type: ignore

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
                    f"{address:#x} for file: {argfile.name}.",
                )
            end = sector_end
        return pairs


class DiffWithType(click.Path):
    """Custom type for --diff-with parameter that accepts file paths (binary or HEX),
    or "skip", and returns a file handle or None. When used with multiple=True, Click
    will collect the results into a list. HEX files are automatically split into
    multiple binary files (one per continuous region), allowing a single HEX file
    to match multiple files being flashed.
    """

    name = "diff-with-file"

    def get_metavar(
        self, param: click.Parameter | None, ctx: click.Context | None = None
    ):
        return "<filename(s)> or 'skip'"

    def convert(
        self,
        value: str,
        param: click.Parameter | None,
        ctx: click.Context,
    ) -> IO[bytes] | None:
        # Handle special "skip" string
        if value.lower() == "skip":
            # Check if a file with this name actually exists
            if os.path.exists(value):
                raise click.BadParameter(
                    f"File named '{value}' exists, but this filename is not supported "
                    "as it conflicts with the 'skip' keyword. Please rename the file."
                )
            return None

        # Validate path using parent class
        validated_path = super().convert(value, param, ctx)
        # Open file and store handle in context for cleanup
        if not hasattr(ctx, "_open_files"):
            ctx._open_files = []
        # Initialize dict to map HEX file first split to all splits
        if not hasattr(ctx, "_diff_with_hex_splits"):
            ctx._diff_with_hex_splits = {}
        try:
            file_handle = open(validated_path, "rb")
            # Use intel_hex_to_bin to handle HEX file conversion and splitting
            hex_converted = intel_hex_to_bin(file_handle)
            # intel_hex_to_bin returns list[tuple[int | None, IO[bytes]]]
            # Extract just the file handles
            split_files = [f for _, f in hex_converted]
            # Store all file handles for cleanup
            for f in split_files:
                ctx._open_files.append(f)
            # If HEX file was split into multiple files, store mapping for expansion
            if len(split_files) > 1:
                ctx._diff_with_hex_splits[split_files[0]] = split_files
            # Return first file (or only file if binary)
            return split_files[0] if split_files else None
        except OSError as e:
            raise click.BadParameter(str(e))


########################### Custom option/argument ############################


class Group(click.RichGroup):
    DEPRECATED_OPTIONS = {
        "--flash_size": "--flash-size",
        "--flash_freq": "--flash-freq",
        "--flash_mode": "--flash-mode",
        "--use_segments": "--use-segments",
        "--ignore_flash_encryption_efuse_setting": "--ignore-flash-enc-efuse",
        "--fill-flash-size": "--pad-to-size",
    }

    def __call__(self, esp: ESPLoader | None = None, *args, **kwargs):
        self._esp = esp  # store the external esp object in the group
        return super().__call__(*args, **kwargs)

    def _replace_deprecated_args(self, args: list[str]) -> list[str]:
        new_args = []
        for arg in args:
            # In case of arguments with values we need to check the key without value
            arg, value = arg.split("=", 1) if "=" in arg else (arg, None)
            if arg in self.DEPRECATED_OPTIONS.keys():
                # Replace underscores with hyphens in option names
                new_name = self.DEPRECATED_OPTIONS[arg]
                if new_name != arg:
                    log.warning(
                        f"Deprecated: Option '{arg}' is deprecated. "
                        f"Use '{new_name}' instead."
                    )
                    arg = new_name
            if value is not None:
                arg += f"={value}"
            new_args.append(arg)
        return new_args

    def parse_args(self, ctx: click.Context, args: list[str]):
        """Set a flag if --help is used to skip the main"""
        ctx.esp = self._esp
        ctx._commands_list = self.list_commands(ctx)  # used for EatAllOptions
        args = self._replace_deprecated_args(args)
        return super().parse_args(ctx, args)

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """Allow dash and underscore for commands for compatibility with v4"""
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        for cmd in self.list_commands(ctx):
            cmd_alias = cmd.replace("-", "_")
            if cmd_alias == cmd_name:
                log.warning(
                    f"Deprecated: Command '{cmd_name}' is deprecated. "
                    f"Use '{cmd}' instead."
                )
                return click.Group.get_command(self, ctx, cmd)
        return None

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        # always return the full command name
        _, cmd, args = super().resolve_command(ctx, args)
        if cmd is None:
            return None, None, args
        return cmd.name, cmd, args


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
        super().__init__(*args, **kwargs)
        self._previous_parser_process = None
        self._eat_all_parser = None
        # Set the metavar dynamically based on the type's metavar
        if self.type and hasattr(self.type, "name"):
            self.metavar = f"[{self._get_metavar() or self.type.name.upper()}]"

    def _get_metavar(self):
        """Get the metavar for the option. Wrapper for compatibility reasons.
        In Click 8.2.0+, the `get_metavar` requires new parameter `ctx`.
        """
        try:
            ctx = click.get_current_context(silent=True)
            return self.type.get_metavar(None, ctx)
        except TypeError:
            return self.type.get_metavar(None)

    def add_to_parser(self, parser, ctx):
        def parser_process(value, state):
            # Method to hook into the parser.process
            done = False
            values = [value]
            # Grab everything up to the next option/command
            while state.rargs and not done:
                for prefix in self._eat_all_parser.prefixes:
                    if state.rargs[0].startswith(prefix):
                        done = True
                        break
                if state.rargs[0] in self._commands_list:
                    done = True
                if not done:
                    values.append(state.rargs.pop(0))

            # Call the original parser process method on the rest of the arguments
            if self.multiple:
                # If multiple options can be used, Click does not support extending the
                # value; as the 'value' is list, we need to process each item separately
                for v in values:
                    self._previous_parser_process(v, state)
            else:
                self._previous_parser_process(values, state)

        retval = super().add_to_parser(parser, ctx)
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
        super().__init__(*args, **kwargs)

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
        return super().handle_parse_result(ctx, opts, args)


############################## Helper functions ###############################


def arg_auto_int(x: str) -> int:
    """Parse an integer value in any base"""
    return int(x, 0)


def get_port_list(
    vids: list[str] = [],
    pids: list[str] = [],
    names: list[str] = [],
    serials: list[str] = [],
) -> list[str]:
    """Get the list of serial ports names with optional filters.

    For backwards compatibility, this function returns a list of port names.
    """
    return [port.device for port in _get_port_list(vids, pids, names, serials)]


def _get_port_list(
    vids: list[str] = [],
    pids: list[str] = [],
    names: list[str] = [],
    serials: list[str] = [],
) -> list[ListPortInfo]:
    if list_ports is None:
        raise FatalError(
            "Listing all serial ports is currently not available. "
            "Please try to specify the port when running esptool or update "
            "the pyserial package to the latest version."
        )
    ports = []
    for port in list_ports.comports():
        if sys.platform == "darwin" and port.device.endswith(
            ("Bluetooth-Incoming-Port", "wlan-debug", "cu.debug-console")
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
        ports.append(port)

    # Constants for sorting optimization
    ESPRESSIF_VID = 0x303A
    LINUX_DEVICE_PATTERNS = ("ttyUSB", "ttyACM")
    MACOS_DEVICE_PATTERNS = ("usbserial", "usbmodem")

    def _port_sort_key_linux(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (3, port_info.device)

        if any(pattern in port_info.device for pattern in LINUX_DEVICE_PATTERNS):
            return (2, port_info.device)

        return (1, port_info.device)

    def _port_sort_key_macos(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (3, port_info.device)

        if any(pattern in port_info.device for pattern in MACOS_DEVICE_PATTERNS):
            return (2, port_info.device)

        return (1, port_info.device)

    def _port_sort_key_windows(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (2, port_info.device)

        return (1, port_info.device)

    if sys.platform == "win32":
        key_func = _port_sort_key_windows
    elif sys.platform == "darwin":
        key_func = _port_sort_key_macos
    else:
        key_func = _port_sort_key_linux

    sorted_port_info = sorted(ports, key=key_func)
    return sorted_port_info


def parse_port_filters(
    value: tuple[str],
) -> tuple[list[int], list[int], list[str], list[str]]:
    """Parse port filter arguments into separate lists for each filter type"""
    filterVids = []
    filterPids = []
    filterNames = []
    filterSerials = []
    for f in value:
        kvp = f.split("=")
        if len(kvp) != 2:
            raise FatalError("Option --port-filter argument must consist of key=value.")
        if kvp[0] == "vid":
            filterVids.append(arg_auto_int(kvp[1]))
        elif kvp[0] == "pid":
            filterPids.append(arg_auto_int(kvp[1]))
        elif kvp[0] == "name":
            filterNames.append(kvp[1])
        elif kvp[0] == "serial":
            filterSerials.append(kvp[1])
        else:
            raise FatalError("Option --port-filter argument key not recognized.")
    return filterVids, filterPids, filterNames, filterSerials


def parse_size_arg(esp: ESPLoader, size: int | str) -> int:
    """Parse the flash size argument and return the size in bytes"""
    if isinstance(size, int):
        if not esp.secure_download_mode:
            detected_size = flash_size_bytes(detect_flash_size(esp))
            if detected_size and size > detected_size:
                raise FatalError(
                    f"Specified size {size:#x} is greater than detected flash size "
                    f"{detected_size:#x}.",
                )
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
