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
import re
import argparse

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

ESPTOOL_PY = "../esptool.py"


def write_python_snippet_to_file(stub_name, stub_data, out_file):
    print("writing %s stub" % stub_name)
    encoded = base64.b64encode(zlib.compress(repr(stub_data).encode("utf-8"), 9)).decode("utf-8")
    in_lines = ""
    # split encoded data into 160 character lines
    LINE_LEN=160
    for c in range(0, len(encoded), LINE_LEN):
        in_lines += encoded[c:c+LINE_LEN] + "\\\n"
    out_file.write(PYTHON_TEMPLATE % (stub_name, in_lines))


def write_python_snippets(stub_dict, out_file):
    for name, stub_data in stub_dict.items():
        m = re.match(r"stub_flasher_([a-z0-9_]+)", name)
        key = m.group(1).upper()
        write_python_snippet_to_file(key, stub_data, out_file)


def embed_python_snippets(stubs):
    with open(ESPTOOL_PY, 'r') as f:
        lines = [line for line in f]

    with open(ESPTOOL_PY, "w") as f:
        skip_until = None
        for line in lines:
            if skip_until is not None:
                if skip_until in line:
                    skip_until = None
                continue

            m = re.search(r"ESP([A-Z0-9]+)ROM.STUB_CODE = eval", line)
            if not m:
                f.write(line)
                continue

            key = m.group(1)
            stub_data = stubs.get("stub_flasher_%s" % key.lower(), None)
            if not stub_data:
                f.write(line)
                continue

            write_python_snippet_to_file(key, stub_data, f)
            skip_until = r'""")))'


def stub_name(filename):
    """ Return a dictionary key for the stub with filename 'filename' """
    return os.path.splitext(os.path.basename(filename))[0]

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-file", required=False, type=argparse.FileType('w'),
                        help="Output file name. If not specified, stubs are embedded into esptool.py.")
    parser.add_argument("elf_files", nargs="+", help="Stub ELF files to convert")
    args = parser.parse_args()

    stubs = dict((stub_name(elf_file), wrap_stub(elf_file)) for elf_file in args.elf_files)
    if args.out_file:
        print('Dumping to Python snippet file %s.' % args.out_file.name)
        write_python_snippets(stubs, args.out_file)
    else:
        print('Embeddeding Python snippets into esptool.py')
        embed_python_snippets(stubs)
