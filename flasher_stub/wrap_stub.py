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

    stub['text'] = esptool.hexify(stub['text'])
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
    with open(sys.argv[-1], 'w') as f:
        f.write(as_json)
