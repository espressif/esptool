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
import os.path
import sys

sys.path.append('..')
import esptool

def wrap_stub(elf_file):
    """ Wrap an ELF file into a stub 'dict' """
    print 'Wrapping ELF file %s...' % elf_file
    e = esptool.ELFFile(elf_file)
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

    stub['code'] = esptool.hexify(stub['code'])
    if 'data' in stub:
        stub['data'] = esptool.hexify(stub['data'])
    return stub

def stub_name(filename):
    """ Return a dictionary key for the stub with filename 'filename' """
    return os.path.splitext(os.path.basename(filename))[0]

if __name__ == '__main__':
    stubs = dict( (stub_name(elf_file),wrap_stub(elf_file)) for elf_file in sys.argv[1:-1] )
    print 'Dumping to JSON file %s.' % sys.argv[-1]

    as_json = json.dumps(stubs)
    # split into 110 character lines
    LINE_LEN = 110
    lines = [as_json[i:i+LINE_LEN] for i in xrange(0, len(as_json), LINE_LEN)]
    with open(sys.argv[-1], 'w') as f:
        for line in lines:
            f.write(line)
            f.write('\\\n')
