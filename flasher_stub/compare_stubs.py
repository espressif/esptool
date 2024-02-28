#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import sys

import esptool

# Compare the esptool stub loaders to freshly built ones in the build directory
#
# (Used by CI to verify the stubs are up to date.)

THIS_SCRIPT_DIR = os.path.dirname(__file__)
STUB_DIR = "../esptool/targets/stub_flasher/"
BUILD_DIR = "build/"
JSON_NAME = "stub_flasher_{}.json"


def diff(path_to_new, path_to_old):
    output = ""
    new = esptool.loader.StubFlasher(path_to_new)
    old = esptool.loader.StubFlasher(path_to_old)

    if new.data_start != old.data_start:
        output += "  Data start: New {:#x}, old {:#x} \n".format(
            new.data_start, old.data_start
        )
    if new.text_start != old.text_start:
        output += "  Text start: New {:#x}, old {:#x} \n".format(
            new.text_start, old.text_start
        )
    if new.entry != old.entry:
        output += "  Entrypoint: New {:#x}, old {:#x} \n".format(new.entry, old.entry)

    # data
    if new.data != old.data:
        if len(new.data) == len(old.data):
            for i, (new_b, old_b) in enumerate(zip(new.data, old.data)):
                if new_b != old_b:
                    output += "  Data byte {:#x}: new {:#04x} old {:#04x} \n".format(
                        i, new_b, old_b
                    )
        else:
            output += "  Data length: New {} bytes, old {} bytes \n".format(
                len(new.data), len(old.data)
            )

    # text
    if new.text != old.text:
        if len(new.text) == len(old.text):
            for i, (new_b, old_b) in enumerate(zip(new.text, old.text)):
                if new_b != old_b:
                    output += "  Text byte {:#x}: new {:#04x} old {:#04x} \n".format(
                        i, new_b, old_b
                    )
        else:
            output += "  Text length: New {} bytes, old {} bytes \n".format(
                len(new.text), len(old.text)
            )
    return output


if __name__ == "__main__":
    same = True
    for chip in esptool.CHIP_LIST:
        print("Comparing {} stub: ".format(chip), end="")
        # TODO: [ESP32C5] ESPTOOL-825 remove when supported stub flasher
        # TODO: [ESP32C61] IDF-9241 remove when supported stub flasher
        if chip in ["esp32c5", "esp32c61"]:
            print(f"{chip} has not supported stub yet, skipping...")
            continue

        chip = chip.replace("esp", "")
        old = os.path.join(THIS_SCRIPT_DIR, STUB_DIR, JSON_NAME.format(chip))
        new = os.path.join(THIS_SCRIPT_DIR, BUILD_DIR, JSON_NAME.format(chip))

        output = diff(new, old)
        if output != "":
            same = False
            print("FAIL")
            print(
                "  Mismatch: {} json file in esptool/targets/stub_flasher/ differs "
                "from the just-built stub".format("esp" + chip)
            )
            print(output)
        else:
            print("OK")

    if not same:
        sys.exit(1)
    else:
        print("Stub flasher json files are the same")
        sys.exit(0)
