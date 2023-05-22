#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

# This executable script is a thin wrapper around the main functionality
# in the esptool Python package

# When updating this script, please also update espefuse.py and espsecure.py

import contextlib
import os
import sys

if os.name != "nt":
    # Linux/macOS: remove current script directory to avoid importing this file
    # as a module; we want to import the installed esptool module instead
    with contextlib.suppress(ValueError):
        executable_dir = os.path.dirname(sys.executable)
        sys.path = [
            path
            for path in sys.path
            if not path.endswith(("/bin", "/sbin")) and path != executable_dir
        ]

    # Linux/macOS: delete imported module entry to force Python to load
    # the module from scratch; this enables importing esptool module in
    # other Python scripts
    with contextlib.suppress(KeyError):
        del sys.modules["esptool"]

import esptool

if __name__ == "__main__":
    esptool._main()
