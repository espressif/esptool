#!/usr/bin/env python
# This file consists of the common useful functions for eFuse
#
# Copyright (C) 2020 Espressif Systems (Shanghai) PTE LTD
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
from __future__ import print_function

import esptool


def hexify(bitstring, separator=""):
    try:
        as_bytes = tuple(ord(b) for b in bitstring)
    except TypeError:  # python 3, items in bitstring already ints
        as_bytes = tuple(b for b in bitstring)
    return separator.join(("%02x" % b) for b in as_bytes)


def popcnt(b):
    """ Return number of "1" bits set in 'b' """
    return len([x for x in bin(b) if x == "1"])


def check_duplicate_name_in_list(name_list):
    duples_name = [name for i, name in enumerate(name_list) if name in name_list[:i]]
    if duples_name != []:
        raise esptool.FatalError("Found repeated {} in the name list".format(duples_name))
