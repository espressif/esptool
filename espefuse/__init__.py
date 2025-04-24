# SPDX-FileCopyrightText: 2016-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
from io import StringIO

import rich_click as click

import esptool
from esptool.cli_util import ChipType, ResetModeType
from esptool.logger import log

from espefuse.cli_util import (
    SUPPORTED_BURN_COMMANDS,
    SUPPORTED_CHIPS,
    SUPPORTED_COMMANDS,
    Group,
    get_command_class,
)


def get_esp(
    port,
    baud,
    before="default-reset",
    chip="auto",
    skip_connect=False,
    virt=False,
    debug=False,
    virt_efuse_file=None,
):
    if chip not in ["auto"] + list(SUPPORTED_CHIPS.keys()):
        raise esptool.FatalError(f"get_esp: Unsupported chip ({chip})")
    if virt:
        efuse = SUPPORTED_CHIPS.get(chip, SUPPORTED_CHIPS["esp32"]).efuse_lib
        esp = efuse.EmulateEfuseController(virt_efuse_file, debug)
    else:
        if chip == "auto" and not skip_connect:
            esp = esptool.detect_chip(port, baud, before)
        else:
            esp = SUPPORTED_CHIPS.get(chip, SUPPORTED_CHIPS["esp32"]).chip_class(
                port if not skip_connect else StringIO(), baud
            )
            if not skip_connect:
                esp.connect(before)
                if esp.sync_stub_detected:
                    esp = esp.STUB_CLASS(esp)
    return esp


def get_efuses(
    esp,
    skip_connect=False,
    debug_mode=False,
    do_not_confirm=False,
    extend_efuse_table=None,
):
    for name in SUPPORTED_CHIPS:
        if SUPPORTED_CHIPS[name].chip_name == esp.CHIP_NAME:
            return SUPPORTED_CHIPS[name].efuse_lib.EspEfuses(
                esp, skip_connect, debug_mode, do_not_confirm, extend_efuse_table
            )
    else:
        raise esptool.FatalError("get_efuses: Unsupported chip (%s)" % esp.CHIP_NAME)


@click.group(
    cls=Group,
    # chain=True,  # allow using multiple commands in a single run
    no_args_is_help=True,
    context_settings=dict(help_option_names=["-h", "--help"], max_content_width=120),
    help=f"espefuse.py v{esptool.__version__} - ESP32xx eFuse get/set tool",
)
@click.option(
    "--chip",
    "-c",
    type=ChipType(choices=["auto"] + list(SUPPORTED_CHIPS.keys())),
    default="auto",
    envvar="ESPTOOL_CHIP",
    help="Target chip type",
)
@click.option(
    "--baud",
    "-b",
    type=int,
    default=esptool.ESPLoader.ESP_ROM_BAUD,
    envvar="ESPTOOL_BAUD",
    help="Serial port baud rate used when flashing/reading",
)
@click.option(
    "--port",
    "-p",
    envvar="ESPTOOL_PORT",
    help="Serial port device",
)
@click.option(
    "--before",
    type=ResetModeType(
        choices=["default-reset", "usb-reset", "no-reset", "no-reset-no-sync"]
    ),
    default="default-reset",
    help="What to do before connecting to the chip",
)
@click.option(
    "--debug", "-d", is_flag=True, help="Show debugging information (loglevel=DEBUG)"
)
@click.option(
    "--virt",
    is_flag=True,
    help="For host tests, work in virtual mode (no chip connection)",
)
@click.option(
    "--path-efuse-file",
    type=click.Path(),
    help="For host tests, saves efuse memory to file",
)
@click.option(
    "--do-not-confirm",
    is_flag=True,
    help="Do not pause for confirmation before permanently writing efuses. "
    "Use with caution.",
)
@click.option(
    "--postpone",
    is_flag=True,
    help="Postpone burning some efuses from BLOCK0 at the end",
)
@click.option(
    "--extend-efuse-table",
    type=click.File("r"),
    help="CSV file from ESP-IDF (esp_efuse_custom_table.csv)",
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
    print(f"espefuse.py v{esptool.__version__}")

    ctx.ensure_object(dict)
    esp = ctx.obj.get("esp", None)
    external_esp = esp is not None
    is_help = ctx.obj.get("is_help", False)

    if not port and not external_esp and not is_help and not virt:
        raise click.BadOptionUsage(
            "--port", "Missing required argument. Please specify the --port option"
        )

    if not esp:
        try:
            esp = get_esp(
                port, baud, before, chip, is_help, virt, debug, path_efuse_file
            )
        except esptool.FatalError as e:
            raise esptool.FatalError(
                f"{e}\nPlease make sure you specified the right port with --port"
            )

    def close_port():
        if not external_esp and not virt and esp._port:
            esp._port.close()

    ctx.call_on_close(close_port)

    efuses = get_efuses(esp, is_help, debug, do_not_confirm, extend_efuse_table)
    efuses.postpone = postpone

    # handle chip auto
    if chip == "auto":
        if ctx.obj.get("is_help", False):
            log.note(
                "Chip not specified, showing commands for ESP32 by default. "
                "Specify the --chip option to get chip-specific help."
            )
        chip = esp.CHIP_NAME.lower()

    ctx.obj["commands"] = get_command_class(chip)
    ctx.obj["commands"].efuses = efuses
    ctx.obj["commands"].add_cli_commands(cli)

    used_cmds = ctx.obj["used_cmds"]
    there_are_multiple_burn_commands_in_args = (
        sum(cmd.replace("_", "-") in SUPPORTED_BURN_COMMANDS for cmd in used_cmds) > 1
    )
    if there_are_multiple_burn_commands_in_args:
        efuses.batch_mode_cnt += 1

    # Add the objects to the context
    ctx.obj["esp"] = esp
    ctx.obj["debug"] = debug
    ctx.obj["efuses"] = efuses
    ctx.obj["do_not_confirm"] = do_not_confirm

    @cli.result_callback()
    def process_result(result, *args, **kwargs):
        if there_are_multiple_burn_commands_in_args:
            efuses.batch_mode_cnt -= 1
            if not efuses.burn_all(check_batch_mode=True):
                raise esptool.FatalError("BURN was not done")
            print("Successful")


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
    cli(args=argv, esp=esp)


def _main():
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
