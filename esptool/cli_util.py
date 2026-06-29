# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
from typing import IO, Any, cast

import rich_click as click
from esp_pylib.cli_options import EspRichGroup
from esp_pylib.cli_types import AnyIntType, arg_auto_int

from esptool.bin_image import ESPLoader, intel_hex_to_bin
from esptool.cmds import detect_flash_size
from esptool.logger import log
from esptool.util import FatalError, flash_size_bytes, strip_chip_name

################################ Custom types #################################


class EsptoolContext(click.RichContext):
    """Click context extended with esptool-specific attributes."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._open_files: list[IO[bytes]] = []
        self._diff_with_hex_splits: dict[IO[bytes], list[IO[bytes]]] = {}
        self.esp: ESPLoader | None = None


class ChipType(click.Choice):
    """Custom type to accept chip names in any case and with or without hyphen"""

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context | None
    ) -> Any:
        value = strip_chip_name(value)
        return super().convert(value, param, ctx)


class ResetModeType(click.Choice):
    """Custom type to accept reset mode names with underscores as separators
    for compatibility with v4"""

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context | None
    ) -> Any:
        if "_" in value:
            new_value = value.replace("_", "-")
            if new_value not in self.choices:
                raise click.BadParameter(f"{value} is not a valid reset mode.")
            log.warn(
                f"Deprecated: Choice '{value}' for option "
                f"'--{param.name if param else 'unknown'}' is "
                f"deprecated. Use '{new_value}' instead."
            )
            return new_value
        return super().convert(value, param, ctx)


class AutoChunkSizeType(AnyIntType):
    """Custom type for chunk size that must be 4-byte aligned"""

    name = "integer"

    def convert(
        self, value: str | int, param: click.Parameter | None, ctx: click.Context | None
    ) -> int:
        num = cast(int, super().convert(value, param, ctx))
        if num & 3 != 0:
            raise click.BadParameter("Chunk size should be a 4-byte aligned number.")
        return num


class SpiConnectionType(click.ParamType):
    """
    Custom type to parse 'spi connection' override.
    Values are SPI, HSPI, or a sequence of 5 pin numbers separated by commas.
    """

    name = "spi-connection"

    def convert(
        self, value: str, param: click.Parameter | None, ctx: click.Context | None
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

    def convert(  # type: ignore[override]
        self,
        value: str | os.PathLike[str],
        param: click.Parameter | None,
        ctx: click.Context | None,
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

    def convert(  # type: ignore[override]
        self,
        value: list[str],
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> list[tuple[int, IO[bytes]]]:
        if len(value) % 2 != 0:
            raise click.BadParameter(
                "Must be pairs of an address and the binary filename to write there.",
            )
        if len(value) == 0:
            return []

        if ctx is None:
            raise click.BadParameter("Internal error: missing click context.")

        esptool_ctx = cast(EsptoolContext, ctx)
        pairs: list[tuple[int, IO[bytes]]] = []
        for i in range(0, len(value), 2):
            try:
                address = arg_auto_int(value[i])
            except ValueError:
                raise click.BadParameter(f'Address "{value[i]}" must be a number.')
            try:
                # Store file handle in context for later cleanup
                argfile_f = open(value[i + 1], "rb")
                esptool_ctx._open_files.append(argfile_f)
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

    def convert(  # type: ignore[override]
        self,
        value: str,
        param: click.Parameter | None,
        ctx: click.Context | None,
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

        if ctx is None:
            raise click.BadParameter("Internal error: missing click context.")

        esptool_ctx = cast(EsptoolContext, ctx)
        # Validate path using parent class
        validated_path = super().convert(value, param, ctx)
        # Open file and store handle in context for cleanup
        try:
            file_handle = open(validated_path, "rb")
            # Use intel_hex_to_bin to handle HEX file conversion and splitting
            hex_converted = intel_hex_to_bin(file_handle)
            # intel_hex_to_bin returns list[tuple[int | None, IO[bytes]]]
            # Extract just the file handles
            split_files = [f for _, f in hex_converted]
            # Store all file handles for cleanup
            for f in split_files:
                esptool_ctx._open_files.append(f)
            # If HEX file was split into multiple files, store mapping for expansion
            if len(split_files) > 1:
                esptool_ctx._diff_with_hex_splits[split_files[0]] = split_files
            # Return first file (or only file if binary)
            return split_files[0] if split_files else None
        except OSError as e:
            raise click.BadParameter(str(e))


########################### Custom option/argument ############################


class EsptoolCommand(click.RichCommand):
    """Subcommand class that uses EsptoolContext for argument parsing."""

    context_class = EsptoolContext


class EsptoolGroup(EspRichGroup):
    context_class = EsptoolContext
    command_class = EsptoolCommand

    DEPRECATED_OPTIONS = {
        "--flash_size": "--flash-size",
        "--flash_freq": "--flash-freq",
        "--flash_mode": "--flash-mode",
        "--use_segments": "--use-segments",
        "--ignore_flash_encryption_efuse_setting": "--ignore-flash-enc-efuse",
        "--fill-flash-size": "--pad-to-size",
        "--no-diff-verify": "--trust-flash-content",
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
                    log.warn(
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
        cast(EsptoolContext, ctx).esp = self._esp
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
                log.warn(
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


############################## Helper functions ###############################


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
