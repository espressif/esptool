# SPDX-FileCopyrightText: 2016-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys

import rich_click as click

import esptool
from esptool.cli_util import ChipType, ResetModeType
from esptool.logger import log

from espefuse.cli_util import Group
from espefuse.efuse.base_operations import BaseCommands
from espefuse.efuse_interface import (
    DEPRECATED_COMMANDS,
    get_esp,
    init_commands,
    SUPPORTED_COMMANDS,
    SUPPORTED_BURN_COMMANDS,
    SUPPORTED_READ_COMMANDS,
    SUPPORTED_CHIPS,
)
from esptool.util import check_deprecated_py_suffix

__all__ = [
    "get_esp",
    "init_commands",
    "BaseCommands",
    "SUPPORTED_COMMANDS",
    "SUPPORTED_CHIPS",
    "SUPPORTED_BURN_COMMANDS",
    "SUPPORTED_READ_COMMANDS",
]


@click.group(
    cls=Group,
    chain=True,  # allow using multiple commands in a single run
    no_args_is_help=True,
    context_settings=dict(help_option_names=["-h", "--help"], max_content_width=120),
    help=f"espefuse v{esptool.__version__} - "
    "Utility for eFuse configuration in Espressif SoCs.",
)
@click.option(
    "--chip",
    "-c",
    type=ChipType(choices=["auto"] + list(SUPPORTED_CHIPS.keys())),
    default="auto",
    envvar="ESPTOOL_CHIP",
    help="Target chip type.",
)
@click.option(
    "--baud",
    "-b",
    type=int,
    default=esptool.ESPLoader.ESP_ROM_BAUD,
    envvar="ESPTOOL_BAUD",
    help="Serial port baud rate used when flashing/reading.",
)
@click.option(
    "--port",
    "-p",
    envvar="ESPTOOL_PORT",
    type=click.Path(),
    help="Serial port device.",
)
@click.option(
    "--before",
    type=ResetModeType(
        choices=["default-reset", "usb-reset", "no-reset", "no-reset-no-sync"]
    ),
    default="default-reset",
    help="Which reset to perform before connecting to the chip.",
)
@click.option(
    "--debug", "-d", is_flag=True, help="Show debugging information (loglevel=DEBUG)."
)
@click.option(
    "--virt",
    is_flag=True,
    help="For host tests, work in virtual mode (no chip connection).",
)
@click.option(
    "--path-efuse-file",
    type=click.Path(),
    help="For host tests, save eFuse memory to file.",
)
@click.option(
    "--do-not-confirm",
    is_flag=True,
    help="Do not pause for confirmation before permanently writing eFuses. "
    "Use with caution!",
)
@click.option(
    "--postpone",
    is_flag=True,
    help="Postpone burning some eFuses from BLOCK0 at the end.",
)
@click.option(
    "--extend-efuse-table",
    type=click.File("r"),
    help="CSV file from ESP-IDF (esp_efuse_custom_table.csv).",
)
@click.pass_context
def cli(
    ctx,
    chip,
    baud,
    port,
    before,
    debug,
    virt,
    path_efuse_file,
    do_not_confirm,
    postpone,
    extend_efuse_table,
):
    log.print(f"espefuse v{esptool.__version__}")

    ctx.ensure_object(dict)
    esp = ctx.obj.get("esp", None)
    external_esp = esp is not None
    is_help = ctx.obj.get("is_help", False)
    used_cmds = ctx.obj.get("used_cmds", [])

    if any(cmd.replace("_", "-") in DEPRECATED_COMMANDS for cmd in used_cmds):
        return  # do not connect to ESP if any command is deprecated

    if not port and not external_esp and not is_help and not virt:
        raise click.BadOptionUsage(
            "--port", "Missing required argument. Please specify the --port option."
        )

    if not esp:
        try:
            esp = get_esp(
                port, baud, before, chip, is_help, virt, debug, path_efuse_file
            )
        except esptool.FatalError as e:
            raise esptool.FatalError(
                f"{e}\nPlease make sure you specified the right port with --port."
            )

    def close_port():
        if not external_esp and not virt and esp._port:
            esp._port.close()

    ctx.call_on_close(close_port)

    # handle chip auto
    if chip == "auto":
        if ctx.obj.get("is_help", False):
            log.note(
                "Chip not specified, showing commands for ESP32 by default. "
                "Specify the --chip option to get chip-specific help."
            )
        chip = esp.CHIP_NAME.lower()

    commands = init_commands(
        esp=esp,
        skip_connect=is_help,
        debug=debug,
        do_not_confirm=do_not_confirm,
        extend_efuse_table=extend_efuse_table,
    )
    commands.efuses.postpone = postpone
    commands.add_cli_commands(cli)

    multiple_burn_commands = (
        sum(cmd.replace("_", "-") in SUPPORTED_BURN_COMMANDS for cmd in used_cmds) > 1
    )
    if multiple_burn_commands:
        commands.use_batch_mode()

    # Add the objects to the context
    ctx.obj["debug"] = debug
    ctx.obj["commands"] = commands
    ctx.obj["efuses"] = commands.efuses
    ctx.obj["do_not_confirm"] = do_not_confirm

    @cli.result_callback()
    def process_result(result, *args, **kwargs):
        if multiple_burn_commands:
            if not commands.burn_all(check_batch_mode=True):
                raise esptool.FatalError("BURN was not done.")
            log.print("Successful.")


@cli.command("execute-scripts", hidden=True)
@click.argument("scripts", nargs=-1, type=click.UNPROCESSED)
@click.option("--index", type=click.UNPROCESSED)
@click.option("--configfiles", type=click.UNPROCESSED)
def execute_scripts_cli(scripts, index, configfiles):
    """REMOVED: See Migration guide in documentation for details."""
    log.error(
        "REMOVED: `execute_scripts` was replaced with the public API in v5. "
        "Please see Migration Guide in documentation for details: "
        "https://docs.espressif.com/projects/esptool/en/latest/migration-guide.html#espefuse-py-v5-migration-guide"
    )
    sys.exit(2)


def main(argv: list[str] | None = None, esp: esptool.ESPLoader | None = None):
    """
    Main function for espefuse

    argv - Optional override for default arguments parsing
    (that uses sys.argv), can be a list of custom arguments as strings.
    Arguments and their values need to be added as individual items to the list
    e.g. "--port /dev/ttyUSB1" thus becomes ['--port', '/dev/ttyUSB1'].

    esp - Optional override of the connected device previously
    returned by esptool.get_default_connected_device()
    """
    args = esptool.expand_file_arguments(argv or sys.argv[1:])
    try:
        cli(args=args, esp=esp)
    except SystemExit as e:
        if e.code != 0:
            raise


def _main():
    check_deprecated_py_suffix(__name__)
    try:
        main()
    except esptool.FatalError as e:
        log.error(f"\nA fatal error occurred: {e}")
        sys.exit(2)
    except KeyboardInterrupt:
        log.error("KeyboardInterrupt: Run cancelled by user.")
        sys.exit(2)


if __name__ == "__main__":
    _main()
