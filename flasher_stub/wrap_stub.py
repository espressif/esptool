#!/usr/bin/env python
#
# Copyright (c) 2016 Cesanta Software Limited
# All rights reserved
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

import json
import os
import sys

sys.path.append('..')
import esptool


if __name__ == '__main__':
    e = esptool.ELFFile(sys.argv[1])
    entry = 'stub_main'

    text_section = e.get_section('.text')
    try:
        data_section = e.get_section('.data')
    except ValueError:
        data_section = None
    stub = {
        'text': text_section.data,
        'text_start': text_section.addr,
        'entry': e.entrypoint,
    }
    if data_section is not None:
        stub['data'] = data_section.data
        stub['data_start'] = data_section.addr

    # Pad text with NOPs to mod 4.
    if len(stub['text']) % 4 != 0:
        stub['text'] += (4 - (len(stub['text']) % 4)) * '\0'

    print >>sys.stderr, (
        'Stub text: %d @ 0x%08x, data: %d @ 0x%08x, entry: %s @ 0x%x' % (
            len(stub['text']), stub['text_start'],
            len(stub.get('data', '')), stub.get('data_start', 0),
            entry, stub['entry']))

    jstub = dict(stub)
    jstub['text'] = esptool.hexify(stub['text'])
    if 'data' in stub:
        jstub['data'] = esptool.hexify(stub['data'])
    json.dump(jstub, open(sys.argv[2], 'w'))
