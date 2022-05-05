#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

# This executable script is a thin wrapper around the main functionality
# in the esptool Python package
#
# If esptool is installed via setup.py or pip then this file is not used at all,
# it's compatibility for the older "run from source dir" esptool approach.

# Linux/macOS: remove current script directory to avoid importing this file
# as a module; we want to import the installed esptool module instead
import contextlib
import os
import sys

with contextlib.suppress(ValueError):
    if os.name != "nt":
        sys.path.remove(os.path.dirname(sys.executable))

import esptool

if __name__ == "__main__":
    esptool._main()
