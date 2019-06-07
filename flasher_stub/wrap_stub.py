#!/usr/bin/env python3
#
# Stub has to be generated via Python 3, for correct repr() output
#
# Copyright (c) 2016 Cesanta Software Limited & Copyright (c) 2016-2019 Espressif Systems (Shanghai) PTE LTD
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

import base64
import os
import os.path
import sys
import zlib

sys.path.append('..')
import esptool

def wrap_stub(elf_file):
    """ Wrap an ELF file into a stub 'dict' """
    print('Wrapping ELF file %s...' % elf_file)
    e = esptool.ELFFile(elf_file)

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

    print('Stub text: %d @ 0x%08x, data: %d @ 0x%08x, entry @ 0x%x' % (
        len(stub['text']), stub['text_start'],
        len(stub.get('data', '')), stub.get('data_start', 0),
        stub['entry']), file=sys.stderr)
    return stub

PYTHON_TEMPLATE = """\
ESP%sROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b\"\"\"
%s\"\"\")))
"""

def write_python_snippet(stubs):
    with open(sys.argv[-1], 'w') as f:
        f.write("# Binary stub code (see flasher_stub dir for source & details)\n")
        for key in "8266", "32", "32S2":
            stub_data = stubs["stub_flasher_%s" % key.lower()]
            encoded = base64.b64encode(zlib.compress(repr(stub_data).encode("utf-8"), 9)).decode("utf-8")
            in_lines = ""
            # split encoded data into 160 character lines
            LINE_LEN=160
            for c in range(0, len(encoded), LINE_LEN):
                in_lines += encoded[c:c+LINE_LEN] + "\\\n"
            f.write(PYTHON_TEMPLATE % (key, in_lines))
        print("Python snippet is %d bytes" % f.tell())

def stub_name(filename):
    """ Return a dictionary key for the stub with filename 'filename' """
    return os.path.splitext(os.path.basename(filename))[0]

if __name__ == '__main__':
    stubs = dict( (stub_name(elf_file),wrap_stub(elf_file)) for elf_file in sys.argv[1:-1] )
    print('Dumping to Python snippet file %s.' % sys.argv[-1])
    write_python_snippet(stubs)
