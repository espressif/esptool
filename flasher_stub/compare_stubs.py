#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys

# Compare the esptool stub loaders to freshly built ones
# in the build directory
#
# (Used by CI to verify the stubs are up to date.)


def verbose_diff(new, old):
    for k in ["data_start", "text_start"]:
        if new[k] != old[k]:
            print("New %s 0x%x old 0%x" % (k, new[k], old[k]))

    for k in ["data", "text"]:
        if len(new[k]) != len(old[k]):
            print(
                "New %s %d bytes, old stub code %d bytes"
                % (k, len(new[k]), len(old[k]))
            )
        if new[k] != old[k]:
            print("%s is different" % k)
            if len(new[k]) == len(old[k]):
                for b in range(len(new[k])):
                    if new[k][b] != old[k][b]:
                        print(
                            "  Byte 0x%x: new 0x%02x old 0x%02x"
                            % (b, ord(new[k][b]), ord(old[k][b]))
                        )


if __name__ == "__main__":
    same = True
    sys.path.append("..")
    import esptool
    import esptool.stub_flasher  # old version in esptool module

    sys.path.append("build")
    import stub_flasher_snippet  # new version in build directory

    chip_list = [chip_name.upper() for chip_name in esptool.CHIP_LIST]

    for chip in chip_list:
        key = "%sStubCode" % chip  # name of the binary variable in each module
        old = esptool.stub_flasher.__dict__[key]
        new = stub_flasher_snippet.__dict__[key]

        if old != new:
            print(
                "{} stub code in esptool.stub_flasher is different "
                "to just-built stub.".format(chip)
            )
            verbose_diff(new, old)
            same = False

    if same:
        print("Stub flasher codes are the same")

    sys.exit(0 if same else 1)
