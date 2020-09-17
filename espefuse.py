#!/usr/bin/env python
# efuse get/set utility
# https://github.com/themadinventor/esptool
#
# Copyright (C) 2016 Espressif Systems (Shanghai) PTE LTD
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.
from __future__ import division, print_function

import argparse
import os
import sys
from io import StringIO

import espressif.efuse.esp32 as esp32_efuse
import espressif.efuse.esp32c3 as esp32c3_efuse
import espressif.efuse.esp32s2 as esp32s2_efuse
import espressif.efuse.esp32s3beta2 as esp32s3beta2_efuse

import esptool


def get_esp(port, baud, connect_mode, chip='auto', skip_connect=False, virt=False, debug=False, virt_efuse_file=None):
    if chip not in ['auto', 'esp32', 'esp32s2', 'esp32s3beta2', 'esp32c3']:
        raise esptool.FatalError("get_esp: Unsupported chip (%s)" % chip)
    if virt:
        esp = {
            'esp32': esp32_efuse,
            'esp32s2': esp32s2_efuse,
            'esp32s3beta2': esp32s3beta2_efuse,
            'esp32c3': esp32c3_efuse,
        }.get(chip, esp32_efuse).EmulateEfuseController(virt_efuse_file, debug)
    else:
        if chip == 'auto' and not skip_connect:
            esp = esptool.ESPLoader.detect_chip(port, baud, connect_mode)
        else:
            esp = {
                'esp32': esptool.ESP32ROM,
                'esp32s2': esptool.ESP32S2ROM,
                'esp32s3beta2': esptool.ESP32S3BETA2ROM,
                'esp32c3': esptool.ESP32C3ROM,
            }.get(chip, esptool.ESP32ROM)(port if not skip_connect else StringIO(), baud)
            if not skip_connect:
                esp.connect(connect_mode)
    return esp


def get_efuses(esp, skip_connect=False, debug_mode=False, do_not_confirm=False):
    try:
        efuse = {
            'ESP32': esp32_efuse,
            'ESP32-S2': esp32s2_efuse,
            'ESP32-S3(beta2)': esp32s3beta2_efuse,
            'ESP32-C3': esp32c3_efuse,
        }[esp.CHIP_NAME]
    except KeyError:
        raise esptool.FatalError("get_efuses: Unsupported chip (%s)" % esp.CHIP_NAME)
    # dict mapping register name to its efuse object
    return (efuse.EspEfuses(esp, skip_connect, debug_mode, do_not_confirm), efuse.operations)


def main():
    init_parser = argparse.ArgumentParser(description='espefuse.py v%s - [ESP32/S2/S3BETA2/C3] efuse get/set tool' % esptool.__version__, prog='espefuse',
                                          add_help=False)

    init_parser.add_argument('--chip', '-c',
                             help='Target chip type',
                             choices=['auto', 'esp32', 'esp32s2', 'esp32s3beta2', 'esp32c3'],
                             default=os.environ.get('ESPTOOL_CHIP', 'auto'))

    init_parser.add_argument('--baud', '-b',
                             help='Serial port baud rate used when flashing/reading',
                             type=esptool.arg_auto_int,
                             default=os.environ.get('ESPTOOL_BAUD', esptool.ESPLoader.ESP_ROM_BAUD))

    init_parser.add_argument('--port', '-p',
                             help='Serial port device',
                             default=os.environ.get('ESPTOOL_PORT', esptool.ESPLoader.DEFAULT_PORT))

    init_parser.add_argument('--before',
                             help='What to do before connecting to the chip',
                             choices=['default_reset', 'no_reset', 'esp32r1', 'no_reset_no_sync'],
                             default='default_reset')

    init_parser.add_argument('--debug', "-d", help='Show debugging information (loglevel=DEBUG)', action='store_true')
    init_parser.add_argument('--virt', help='For host tests, the tool will work in the virtual mode (without connecting to a chip).', action='store_true')
    init_parser.add_argument('--path-efuse-file', help='For host tests, saves efuse memory to file.', type=str, default=None)
    init_parser.add_argument('--do-not-confirm', help='Do not pause for confirmation before permanently writing efuses. Use with caution.', action='store_true')

    args1, remaining_args = init_parser.parse_known_args()
    debug_mode = args1.debug or ("dump" in remaining_args)
    just_print_help = [True for arg in remaining_args if arg in ["--help", "-h"]] or remaining_args == []
    esp = get_esp(args1.port, args1.baud, args1.before, args1.chip, just_print_help, args1.virt, args1.debug, args1.path_efuse_file)
    efuses, efuse_operations = get_efuses(esp, just_print_help, debug_mode, args1.do_not_confirm)

    parser = argparse.ArgumentParser(parents=[init_parser])
    subparsers = parser.add_subparsers(dest='operation', help='Run espefuse.py {command} -h for additional help')

    efuse_operations.add_commands(subparsers, efuses)

    args = parser.parse_args(remaining_args)
    print('espefuse.py v%s' % esptool.__version__)
    if args.operation is None:
        parser.print_help()
        parser.exit(1)
    operation_func = vars(efuse_operations)[args.operation]

    # each 'operation' is a module-level function of the same name
    operation_func(esp, efuses, args)


def _main():
    try:
        main()
    except esptool.FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)


if __name__ == '__main__':
    _main()
