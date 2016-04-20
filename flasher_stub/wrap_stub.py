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

    stub = {
        'params_start': e.get_symbol_addr('_params_start'),
        'code': e.load_section('.code'),
        'code_start': e.get_symbol_addr('_code_start'),
        'entry': e.get_symbol_addr(entry),
    }
    data = e.load_section('.data')
    if len(data) > 0:
        stub['data'] = data
        stub['data_start'] = e.get_symbol_addr('_data_start')
    params_len = e.get_symbol_addr('_params_end') - stub['params_start']
    if params_len % 4 != 0:
        raise FatalError('Params must be dwords')
    stub['num_params'] = params_len / 4

    # Pad code with NOPs to mod 4.
    if len(stub['code']) % 4 != 0:
        stub['code'] += (4 - (len(stub['code']) % 4)) * '\0'

    print >>sys.stderr, (
        'Stub params: %d @ 0x%08x, code: %d @ 0x%08x, data: %d @ 0x%08x, entry: %s @ 0x%x' % (
            params_len, stub['params_start'],
            len(stub['code']), stub['code_start'],
            len(stub.get('data', '')), stub.get('data_start', 0),
            entry, stub['entry']))

    jstub = dict(stub)
    jstub['code'] = esptool.hexify(stub['code'])
    if 'data' in stub:
        jstub['data'] = esptool.hexify(stub['data'])
    json.dump(jstub, open(sys.argv[2], 'w'))
