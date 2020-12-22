#!/usr/bin/env python
# This file describes eFuses fields and registers for ESP32 chip
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
from __future__ import division, print_function

from collections import namedtuple


class EfuseRegistersBase(object):
    # Coding Scheme values
    CODING_SCHEME_NONE          = 0
    CODING_SCHEME_34            = 1
    CODING_SCHEME_REPEAT        = 2
    CODING_SCHEME_NONE_RECOVERY = 3
    CODING_SCHEME_RS            = 4

    EFUSE_BURN_TIMEOUT = 0.250  # seconds


class EfuseBlocksBase(object):

    BLOCKS = None
    NamedtupleBlock = namedtuple('Block', 'name alias id rd_addr wr_addr write_disable_bit read_disable_bit len key_purpose')

    @staticmethod
    def get(tuple_block):
        return EfuseBlocksBase.NamedtupleBlock._make(tuple_block)

    def get_blocks_for_keys(self):
        list_of_names = []
        for block in self.BLOCKS:
            blk = self.get(block)
            if blk.id > 0:
                if blk.name:
                    list_of_names.append(blk.name)
                if blk.alias:
                    for alias in blk.alias:
                        list_of_names.append(alias)
        return list_of_names


class EfuseFieldsBase(object):

    NamedtupleField = namedtuple('Efuse', 'name category block word pos type write_disable_bit read_disable_bit class_type description dictionary')

    @staticmethod
    def get(tuple_field):
        return EfuseFieldsBase.NamedtupleField._make(tuple_field)
