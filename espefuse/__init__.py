# SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os
import sys
from collections import namedtuple
from io import StringIO

import espefuse.efuse.esp32 as esp32_efuse
import espefuse.efuse.esp32c2 as esp32c2_efuse
import espefuse.efuse.esp32c3 as esp32c3_efuse
import espefuse.efuse.esp32c5beta3 as esp32c5beta3_efuse
import espefuse.efuse.esp32c6 as esp32c6_efuse
import espefuse.efuse.esp32h2 as esp32h2_efuse
import espefuse.efuse.esp32h2beta1 as esp32h2beta1_efuse
import espefuse.efuse.esp32p4 as esp32p4_efuse
import espefuse.efuse.esp32s2 as esp32s2_efuse
import espefuse.efuse.esp32s3 as esp32s3_efuse
import espefuse.efuse.esp32s3beta2 as esp32s3beta2_efuse

import esptool

DefChip = namedtuple("DefChip", ["chip_name", "efuse_lib", "chip_class"])

SUPPORTED_BURN_COMMANDS = [
    "read_protect_efuse",
    "write_protect_efuse",
    "burn_efuse",
    "burn_block_data",
    "burn_bit",
    "burn_key",
    "burn_key_digest",
    "burn_custom_mac",
    "set_flash_voltage",
    "execute_scripts",
]

SUPPORTED_COMMANDS = [
    "summary",
    "dump",
    "get_custom_mac",
    "adc_info",
    "check_error",
] + SUPPORTED_BURN_COMMANDS

SUPPORTED_CHIPS = {
    "esp32": DefChip("ESP32", esp32_efuse, esptool.targets.ESP32ROM),
    "esp32c2": DefChip("ESP32-C2", esp32c2_efuse, esptool.targets.ESP32C2ROM),
    "esp32c3": DefChip("ESP32-C3", esp32c3_efuse, esptool.targets.ESP32C3ROM),
    "esp32c6": DefChip("ESP32-C6", esp32c6_efuse, esptool.targets.ESP32C6ROM),
    "esp32c5beta3": DefChip(
        "ESP32-C5(beta3)", esp32c5beta3_efuse, esptool.targets.ESP32C5BETA3ROM
    ),
    "esp32h2": DefChip("ESP32-H2", esp32h2_efuse, esptool.targets.ESP32H2ROM),
    "esp32p4": DefChip("ESP32-P4", esp32p4_efuse, esptool.targets.ESP32P4ROM),
    "esp32h2beta1": DefChip(
        "ESP32-H2(beta1)", esp32h2beta1_efuse, esptool.targets.ESP32H2BETA1ROM
    ),
    "esp32s2": DefChip("ESP32-S2", esp32s2_efuse, esptool.targets.ESP32S2ROM),
    "esp32s3": DefChip("ESP32-S3", esp32s3_efuse, esptool.targets.ESP32S3ROM),
    "esp32s3beta2": DefChip(
        "ESP32-S3(beta2)", esp32s3beta2_efuse, esptool.targets.ESP32S3BETA2ROM
    ),
}


def get_esp(
    port,
    baud,
    connect_mode,
    chip="auto",
    skip_connect=False,
    virt=False,
    debug=False,
    virt_efuse_file=None,
):
    if chip not in ["auto"] + list(SUPPORTED_CHIPS.keys()):
        raise esptool.FatalError("get_esp: Unsupported chip (%s)" % chip)
    if virt:
        efuse = SUPPORTED_CHIPS.get(chip, SUPPORTED_CHIPS["esp32"]).efuse_lib
        esp = efuse.EmulateEfuseController(virt_efuse_file, debug)
    else:
        if chip == "auto" and not skip_connect:
            esp = esptool.cmds.detect_chip(port, baud, connect_mode)
        else:
            esp = SUPPORTED_CHIPS.get(chip, SUPPORTED_CHIPS["esp32"]).chip_class(
                port if not skip_connect else StringIO(), baud
            )
            if not skip_connect:
                esp.connect(connect_mode)
    return esp


def get_efuses(esp, skip_connect=False, debug_mode=False, do_not_confirm=False):
    for name in SUPPORTED_CHIPS:
        if SUPPORTED_CHIPS[name].chip_name == esp.CHIP_NAME:
            efuse = SUPPORTED_CHIPS[name].efuse_lib
            return (
                efuse.EspEfuses(esp, skip_connect, debug_mode, do_not_confirm),
                efuse.operations,
            )
    else:
        raise esptool.FatalError("get_efuses: Unsupported chip (%s)" % esp.CHIP_NAME)


def split_on_groups(all_args):
    """
    This function splits the all_args list into groups,
    where each item is a cmd with all its args.

    Example:
    all_args:
    ['burn_key_digest', 'secure_images/ecdsa256_secure_boot_signing_key_v2.pem',
     'burn_key', 'BLOCK_KEY0', 'images/efuse/128bit_key',
     'XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS']

    used_cmds: ['burn_key_digest', 'burn_key']
    groups:
    [['burn_key_digest', 'secure_images/ecdsa256_secure_boot_signing_key_v2.pem'],
     ['burn_key', 'BLOCK_KEY0', 'images/efuse/128bit_key',
      'XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS']]
    """

    groups = []
    cmd = []
    used_cmds = []
    for item in all_args:
        if item in SUPPORTED_COMMANDS:
            used_cmds.append(item)
            if cmd != []:
                groups.append(cmd)
            cmd = []
        cmd.append(item)
    if cmd:
        groups.append(cmd)
    return groups, used_cmds


def main(custom_commandline=None, esp=None):
    """
    Main function for espefuse

    custom_commandline - Optional override for default arguments parsing
    (that uses sys.argv), can be a list of custom arguments as strings.
    Arguments and their values need to be added as individual items to the list
    e.g. "--port /dev/ttyUSB1" thus becomes ['--port', '/dev/ttyUSB1'].

    esp - Optional override of the connected device previously
    returned by esptool.get_default_connected_device()
    """

    external_esp = esp is not None

    init_parser = argparse.ArgumentParser(
        description="espefuse.py v%s - [ESP32xx] efuse get/set tool"
        % esptool.__version__,
        prog="espefuse",
        add_help=False,
    )

    init_parser.add_argument(
        "--chip",
        "-c",
        help="Target chip type",
        choices=["auto"] + list(SUPPORTED_CHIPS.keys()),
        default=os.environ.get("ESPTOOL_CHIP", "auto"),
    )

    init_parser.add_argument(
        "--baud",
        "-b",
        help="Serial port baud rate used when flashing/reading",
        type=esptool.arg_auto_int,
        default=os.environ.get("ESPTOOL_BAUD", esptool.loader.ESPLoader.ESP_ROM_BAUD),
    )

    init_parser.add_argument(
        "--port",
        "-p",
        help="Serial port device",
        default=os.environ.get("ESPTOOL_PORT", esptool.loader.ESPLoader.DEFAULT_PORT),
    )

    init_parser.add_argument(
        "--before",
        help="What to do before connecting to the chip",
        choices=["default_reset", "usb_reset", "no_reset", "no_reset_no_sync"],
        default="default_reset",
    )

    init_parser.add_argument(
        "--debug",
        "-d",
        help="Show debugging information (loglevel=DEBUG)",
        action="store_true",
    )
    init_parser.add_argument(
        "--virt",
        help="For host tests, the tool will work in the virtual mode "
        "(without connecting to a chip).",
        action="store_true",
    )
    init_parser.add_argument(
        "--path-efuse-file",
        help="For host tests, saves efuse memory to file.",
        type=str,
        default=None,
    )
    init_parser.add_argument(
        "--do-not-confirm",
        help="Do not pause for confirmation before permanently writing efuses. "
        "Use with caution.",
        action="store_true",
    )
    init_parser.add_argument(
        "--postpone",
        help="Postpone burning some efuses from BLOCK0 at the end, "
        "(efuses which disable access to blocks or chip).",
        action="store_true",
    )

    common_args, remaining_args = init_parser.parse_known_args(custom_commandline)
    debug_mode = common_args.debug or ("dump" in remaining_args)
    just_print_help = [
        True for arg in remaining_args if arg in ["--help", "-h"]
    ] or remaining_args == []

    print("espefuse.py v{}".format(esptool.__version__))

    if not external_esp:
        try:
            esp = get_esp(
                common_args.port,
                common_args.baud,
                common_args.before,
                common_args.chip,
                just_print_help,
                common_args.virt,
                common_args.debug,
                common_args.path_efuse_file,
            )
        except esptool.FatalError as e:
            raise esptool.FatalError(
                f"{e}\nPlease make sure that you have specified "
                "the right port with the --port argument"
            )
            # TODO: Require the --port argument in the next major release, ESPTOOL-490

    efuses, efuse_operations = get_efuses(
        esp, just_print_help, debug_mode, common_args.do_not_confirm
    )

    parser = argparse.ArgumentParser(parents=[init_parser])
    subparsers = parser.add_subparsers(
        dest="operation", help="Run espefuse.py {command} -h for additional help"
    )

    efuse_operations.add_commands(subparsers, efuses)

    grouped_remaining_args, used_cmds = split_on_groups(remaining_args)
    if len(grouped_remaining_args) == 0:
        parser.print_help()
        parser.exit(1)
    there_are_multiple_burn_commands_in_args = (
        sum(cmd in SUPPORTED_BURN_COMMANDS for cmd in used_cmds) > 1
    )
    if there_are_multiple_burn_commands_in_args:
        efuses.batch_mode_cnt += 1

    efuses.postpone = common_args.postpone

    try:
        for rem_args in grouped_remaining_args:
            args, unused_args = parser.parse_known_args(rem_args, namespace=common_args)
            if args.operation is None:
                parser.print_help()
                parser.exit(1)
            assert (
                len(unused_args) == 0
            ), 'Not all commands were recognized "{}"'.format(unused_args)

            operation_func = vars(efuse_operations)[args.operation]
            # each 'operation' is a module-level function of the same name
            print('\n=== Run "{}" command ==='.format(args.operation))

            if hasattr(args, "show_sensitive_info"):
                if args.show_sensitive_info or args.debug:
                    args.show_sensitive_info = True
                else:
                    print("Sensitive data will be hidden (see --show-sensitive-info)")

            operation_func(esp, efuses, args)

        if there_are_multiple_burn_commands_in_args:
            efuses.batch_mode_cnt -= 1
            if not efuses.burn_all(check_batch_mode=True):
                raise esptool.FatalError("BURN was not done")
            print("Successful")
    finally:
        if not external_esp and not common_args.virt and esp._port:
            esp._port.close()


def _main():
    try:
        main()
    except esptool.FatalError as e:
        print("\nA fatal error occurred: %s" % e)
        sys.exit(2)


if __name__ == "__main__":
    _main()
