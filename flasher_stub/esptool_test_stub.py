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
import sys, os.path, json

THIS_DIR=os.path.dirname(sys.argv[0])

if __name__ == "__main__":
    sys.path.append("..")
    import esptool
    with open("%s/build/stub_flasher.json" % THIS_DIR) as f:
        stub = f.read()
    esptool.ESP8266ROM.STUB_CODE = json.loads(stub)
    esptool.main()


