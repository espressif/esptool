#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2016 Cesanta Software Limited
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD

import argparse
import base64
import json
import os
import os.path
import sys

sys.path.append("..")
import esptool  # noqa: E402

THIS_DIR = os.path.dirname(__file__)
BUILD_DIR = os.path.join(THIS_DIR, "./build/")
STUBS_DIR = os.path.join(THIS_DIR, "../esptool/targets/stub_flasher/")


def wrap_stub(elf_file):
    """Wrap an ELF file into a stub JSON dict"""
    print("Wrapping ELF file %s..." % elf_file)

    e = esptool.bin_image.ELFFile(elf_file)

    text_section = e.get_section(".text")
    stub = {
        "entry": e.entrypoint,
        "text": text_section.data,
        "text_start": text_section.addr,
    }
    try:
        data_section = e.get_section(".data")
        stub["data"] = data_section.data
        stub["data_start"] = data_section.addr
    except ValueError:
        pass

    # Pad text with NOPs to mod 4.
    if len(stub["text"]) % 4 != 0:
        stub["text"] += (4 - (len(stub["text"]) % 4)) * "\0"

    print(
        "Stub text: %d @ 0x%08x, data: %d @ 0x%08x, entry @ 0x%x"
        % (
            len(stub["text"]),
            stub["text_start"],
            len(stub.get("data", "")),
            stub.get("data_start", 0),
            stub["entry"],
        ),
        file=sys.stderr,
    )

    return stub


def write_json_files(stubs_dict):
    class BytesEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, bytes):
                return base64.b64encode(obj).decode("ascii")
            return json.JSONEncoder.default(self, obj)

    for filename, stub_data in stubs_dict.items():
        DIR = STUBS_DIR if args.embed else BUILD_DIR
        with open(DIR + filename, "w") as outfile:
            json.dump(stub_data, outfile, cls=BytesEncoder, indent=4)


def stub_name(filename):
    """Return a dictionary key for the stub with filename 'filename'"""
    return os.path.splitext(os.path.basename(filename))[0] + ".json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--embed", help="Embed stub json files into esptool.py", action="store_true"
    )
    parser.add_argument("elf_files", nargs="+", help="Stub ELF files to convert")
    args = parser.parse_args()

    stubs = dict(
        (stub_name(elf_file), wrap_stub(elf_file)) for elf_file in args.elf_files
    )
    write_json_files(stubs)
