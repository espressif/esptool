#!/usr/bin/env python
#
# This file consists of the common useful functions for eFuse
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function

import esptool


def hexify(bitstring, separator=""):
    as_bytes = tuple(b for b in bitstring)
    return separator.join(("%02x" % b) for b in as_bytes)


def popcnt(b):
    """Return number of "1" bits set in 'b'"""
    return len([x for x in bin(b) if x == "1"])


def check_duplicate_name_in_list(name_list):
    duples_name = [name for i, name in enumerate(name_list) if name in name_list[:i]]
    if duples_name != []:
        raise esptool.FatalError(
            "Found repeated {} in the name list".format(duples_name)
        )


class SdkConfig(object):
    def __init__(self, path_to_file):
        self.sdkconfig = dict()
        if path_to_file is None:
            return
        with open(path_to_file, "r") as file:
            for line in file.readlines():
                if line.startswith("#"):
                    continue
                config = line.strip().split("=", 1)
                if len(config) == 2:
                    self.sdkconfig[config[0]] = (
                        True if config[1] == "y" else config[1].strip('"')
                    )

    def __getitem__(self, config_name):
        try:
            return self.sdkconfig[config_name]
        except KeyError:
            return False
