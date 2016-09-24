#!/usr/bin/env python
#
# Trivial wrapper program to run esptool.py using the just-compiled
# flasher stub in the build/ subdirectory
#
# For use when developing new flasher_stubs, not important otherwise.
#
# Copyright (C) 2014-2016 Fredrik Ahlberg, Angus Gratton, other contributors as noted.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
import sys

if __name__ == "__main__":
    sys.path.append("..")
    import esptool
    with open("build/stub_flasher.json") as f:
        stub = f.read().replace("\\\n","")
    esptool._CESANTA_FLASHER_STUB = stub
    esptool.main()


