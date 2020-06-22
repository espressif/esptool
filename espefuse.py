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
import esptool
import json
import os
import sys
import espressif.efuse.esp32 as esp32_efuse
import espressif.efuse.esp32s2 as esp32s2_efuse


def summary(esp, efuses, args):
    """ Print a human-readable summary of efuse contents """
    ROW_FORMAT = "%-40s %-50s%s = %s %s %s"
    human_output = (args.format == 'summary')
    json_efuse = {}
    if args.file != sys.stdout:
        print("Saving efuse values to " + args.file.name)
    if human_output:
        print(ROW_FORMAT.replace("-50", "-12") % ("EFUSE_NAME (Block)", "Description", "", "[Meaningful Value]", "[Readable/Writeable]", "(Hex Value)"),
              file=args.file)
        print("-" * 88,file=args.file)
    for category in sorted(set(e.category for e in efuses), key=lambda c: c.title()):
        if human_output:
            print("%s fuses:" % category.title(),file=args.file)
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
                value = value.replace("0", "?")
            if human_output:
                print(ROW_FORMAT % (e.get_info(), e.description[:50], "\n  " if len(value) > 20 else "", value, perms, raw), file=args.file)
                desc_len = len(e.description[50:])
                if desc_len:
                    desc_len += 50
                    for i in range(50, desc_len, 50):
                        print("%-40s %-50s" % ("", e.description[i:(50 + i)]), file=args.file)
            if args.format == 'json':
                json_efuse[e.name] = {
                    'value': base_value if readable else value,
                    'readable':readable,
                    'writeable':writeable}
        if human_output:
            print("",file=args.file)
    if human_output:
        print(efuses.summary(), file=args.file)
        warnings = efuses.get_coding_scheme_warnings()
        if warnings:
            print("WARNING: Coding scheme has encoding bit error warnings (0x%x)" % warnings,file=args.file)
        if args.file != sys.stdout:
            args.file.close()
            print("Done")
    if args.format == 'json':
        json.dump(json_efuse,args.file,sort_keys=True,indent=4)
        print("")


def get_esp(port, baud, connect_mode, chip='auto'):
    if chip == 'auto':
        esp = esptool.ESPLoader.detect_chip(port, baud=baud, connect_mode=connect_mode)
    else:
        chip_class = {
            'esp32':    esptool.ESP32ROM,
            'esp32s2':  esptool.ESP32S2ROM,
        }[chip]
        esp = chip_class(port, baud=baud)
        esp.connect(connect_mode)
    return esp


def get_efuses(esp=None, chip="", skip_connect=False, debug_mode=False, do_not_confirm=False):
    if chip == "esp32" or type(esp) is esptool.ESP32ROM:
        efuse = esp32_efuse
    elif chip == "esp32s2" or type(esp) is esptool.ESP32S2ROM:
        efuse = esp32s2_efuse
    else:
        efuse = esp32_efuse
    # dict mapping register name to its efuse object
    return (efuse.EspEfuses(esp, skip_connect=skip_connect, debug=debug_mode, do_not_confirm=do_not_confirm), efuse.operations)


def main():
    init_parser = argparse.ArgumentParser(description='espefuse.py v%s - [ESP32, ESP32S2] efuse get/set tool' % esptool.__version__, prog='espefuse',
                                          add_help=False)

    init_parser.add_argument('--chip', '-c',
                             help='Target chip type',
                             choices=['auto', 'esp32', 'esp32s2'],
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
    init_parser.add_argument('--do-not-confirm', help='Do not pause for confirmation before permanently writing efuses. Use with caution.', action='store_true')

    args1, remaining_args = init_parser.parse_known_args()
    debug_mode = args1.debug or ("dump" in remaining_args)
    just_print_help = [True for arg in remaining_args if arg in ["--help", "-h"]] or remaining_args == []
    if just_print_help:
        esp = None
    else:
        esp = get_esp(args1.port, args1.baud, args1.before, chip=args1.chip,)
    efuses, efuse_operations = get_efuses(esp, args1.chip, just_print_help, debug_mode, args1.do_not_confirm)

    parser = argparse.ArgumentParser(parents=[init_parser])
    subparsers = parser.add_subparsers(dest='operation', help='Run espefuse.py {command} -h for additional help')

    dump_cmd = subparsers.add_parser('dump', help='Dump raw hex values of all efuses')
    dump_cmd.add_argument('--file_name', help='Saves dump for each block into separate file. Provide the common path name /path/blk.bin,'
                          ' it will create: blk0.bin, blk1.bin ... blkN.bin. Use burn_block_data to write it back to another chip.')

    summary_cmd = subparsers.add_parser('summary', help='Print human-readable summary of efuse values')
    summary_cmd.add_argument('--format', help='Select the summary format', choices=['summary','json'], default='summary')
    summary_cmd.add_argument('--file', help='File to save the efuse summary', type=argparse.FileType('wb'), default=sys.stdout)

    efuse_operations.add_commands(subparsers, efuses)

    args = parser.parse_args(remaining_args)
    print('espefuse.py v%s' % esptool.__version__)
    if args.operation is None:
        parser.print_help()
        parser.exit(1)
    try:
        operation_func = globals()[args.operation]
    except KeyError:
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
