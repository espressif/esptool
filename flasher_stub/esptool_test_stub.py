#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Trivial wrapper program to run esptool.py using the just-compiled
# flasher stub in the build/ subdirectory
#
# For use when developing new flasher_stubs, not important otherwise.

import os.path
import sys

THIS_DIR = os.path.dirname(__file__)
STUBS_BUILD_DIR = os.path.join(THIS_DIR, "build/")

sys.path.append("..")
import esptool  # noqa: E402

# Python hackiness: change the path to stub json files in the context of the esptool
# module, so it edits the esptool's global variables
exec(
    "loader.STUBS_DIR = '{}'".format(STUBS_BUILD_DIR),
    esptool.__dict__,
    esptool.__dict__,
)


if __name__ == "__main__":
    try:
        esptool.main()
    except esptool.FatalError as e:
        print("\nA fatal error occurred: %s" % e)
        sys.exit(2)
