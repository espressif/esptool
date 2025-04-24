# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from collections import namedtuple
from io import StringIO

import rich_click as click
from espefuse.efuse.base_operations import BaseCommands
import esptool
from esptool.cli_util import Group as EsptoolGroup
from esptool.logger import log

import espefuse.efuse.esp32 as esp32_efuse
import espefuse.efuse.esp32c2 as esp32c2_efuse
import espefuse.efuse.esp32c3 as esp32c3_efuse
import espefuse.efuse.esp32c5 as esp32c5_efuse
import espefuse.efuse.esp32c6 as esp32c6_efuse
import espefuse.efuse.esp32c61 as esp32c61_efuse
import espefuse.efuse.esp32h2 as esp32h2_efuse
import espefuse.efuse.esp32h21 as esp32h21_efuse
import espefuse.efuse.esp32h4 as esp32h4_efuse
import espefuse.efuse.esp32p4 as esp32p4_efuse
import espefuse.efuse.esp32s2 as esp32s2_efuse
import espefuse.efuse.esp32s3 as esp32s3_efuse


DefChip = namedtuple("DefChip", ["chip_name", "efuse_lib", "chip_class"])

SUPPORTED_BURN_COMMANDS = [
    "read-protect-efuse",
    "write-protect-efuse",
    "burn-efuse",
    "burn-block-data",
    "burn-bit",
    "burn-key",
    "burn-key-digest",
    "burn-custom-mac",
    "set-flash-voltage",
    "execute-scripts",
]

SUPPORTED_READ_COMMANDS = [
    "summary",
    "dump",
    "get-custom-mac",
    "adc-info",
    "check-error",
]

SUPPORTED_COMMANDS = SUPPORTED_READ_COMMANDS + SUPPORTED_BURN_COMMANDS

SUPPORTED_CHIPS = {
    "esp32": DefChip("ESP32", esp32_efuse, esptool.targets.ESP32ROM),
    "esp32c2": DefChip("ESP32-C2", esp32c2_efuse, esptool.targets.ESP32C2ROM),
    "esp32c3": DefChip("ESP32-C3", esp32c3_efuse, esptool.targets.ESP32C3ROM),
    "esp32c6": DefChip("ESP32-C6", esp32c6_efuse, esptool.targets.ESP32C6ROM),
    "esp32c61": DefChip("ESP32-C61", esp32c61_efuse, esptool.targets.ESP32C61ROM),
    "esp32c5": DefChip("ESP32-C5", esp32c5_efuse, esptool.targets.ESP32C5ROM),
    "esp32h2": DefChip("ESP32-H2", esp32h2_efuse, esptool.targets.ESP32H2ROM),
    "esp32h21": DefChip("ESP32-H21", esp32h21_efuse, esptool.targets.ESP32H21ROM),
    "esp32h4": DefChip("ESP32-H4", esp32h4_efuse, esptool.targets.ESP32H4ROM),
    "esp32p4": DefChip("ESP32-P4", esp32p4_efuse, esptool.targets.ESP32P4ROM),
    "esp32s2": DefChip("ESP32-S2", esp32s2_efuse, esptool.targets.ESP32S2ROM),
    "esp32s3": DefChip("ESP32-S3", esp32s3_efuse, esptool.targets.ESP32S3ROM),
}


def get_command_class(chip_name: str) -> BaseCommands:
    return SUPPORTED_CHIPS[chip_name].efuse_lib.commands()  # type: ignore


click.rich_click.USE_CLICK_SHORT_HELP = True
click.rich_click.COMMAND_GROUPS = {
    "espefuse.py": [
        {
            "name": "Burn commands",
            "commands": SUPPORTED_BURN_COMMANDS,
        },
        {
            "name": "Read commands",
            "commands": SUPPORTED_READ_COMMANDS,
        },
    ]
}


class Group(EsptoolGroup):
    DEPRECATED_OPTIONS = {
        "--file_name": "--file-name",
    }

    @staticmethod
    def _split_to_groups(args: list[str]) -> tuple[list[list[str]], list[str]]:
        """
        This function splits the args list into groups,
        where each item is a cmd with all its args.

        Example:
        all_args:
        ['burn-key-digest', 'secure_images/ecdsa256_secure_boot_signing_key_v2.pem',
         'burn-key', 'BLOCK_KEY0', 'images/efuse/128bit_key',
         'XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS']

        used_cmds: ['burn-key-digest', 'burn-key']
        groups:
        [['burn-key-digest', 'secure_images/ecdsa256_secure_boot_signing_key_v2.pem'],
         ['burn-key', 'BLOCK_KEY0', 'images/efuse/128bit_key',
          'XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS']]
        """
        groups: list[list[str]] = []
        args_group: list[str] = []
        used_cmds: list[str] = []
        for arg in args:
            if arg.replace("_", "-") in SUPPORTED_COMMANDS:
                groups.append(args_group)
                used_cmds.append(arg)
                args_group = [arg]
            else:
                args_group.append(arg)
        groups.append(args_group)
        return groups, used_cmds

    def parse_args(self, ctx: click.Context, args: list[str]):
        ctx.ensure_object(dict)
        ctx.obj["is_help"] = any(help_arg in args for help_arg in ctx.help_option_names)
        idx = (
            args.index("--chip")
            if "--chip" in args
            else (args.index("-c") if "-c" in args else -1)
        )
        ctx.obj["chip"] = args[idx + 1] if idx != -1 and idx + 1 < len(args) else "auto"
        # override the default behavior of EsptoolGroup, because we don't need
        # support for parameters with nargs=-1
        args = self._replace_deprecated_args(args)
        _, used_cmds = self._split_to_groups(args)

        if len(used_cmds) == 0:
            self.get_help(ctx)
            ctx.exit()

        ctx.obj["used_cmds"] = used_cmds
        ctx.obj["args"] = args
        return super(click.RichGroup, self).parse_args(ctx, args)

    def get_help(self, ctx: click.Context) -> str:
        # help was called without any commands, so we need to add the commands for the
        # default chip
        if not self.list_commands(ctx):
            chip = ctx.obj["chip"]
            if chip == "auto":
                log.note(
                    "Chip not specified, showing commands for ESP32 by default. "
                    "Specify the --chip option to get chip-specific help."
                )
                chip = "esp32"
            # TODO: this is a hack to get the full list of commands, we need to find
            # a better way to do this
            commands = get_command_class(chip)
            esp = SUPPORTED_CHIPS[chip].chip_class(port=StringIO(), baud=115200)
            commands.efuses = SUPPORTED_CHIPS[chip].efuse_lib.EspEfuses(esp, True)  # type: ignore
            commands.add_cli_commands(self)
        return super().get_help(ctx)  # type: ignore
