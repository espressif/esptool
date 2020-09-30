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
from __future__ import division, print_function

import os.path
import sys

THIS_DIR = os.path.dirname(sys.argv[0])

sys.path.append("..")
import esptool  # noqa: E402


# Python hackiness: evaluate the snippet in the context of the esptool module, so it
# edits the esptool's global variables
exec(open("%s/build/stub_flasher_snippet.py" % THIS_DIR).read(), esptool.__dict__, esptool.__dict__)


if __name__ == "__main__":
    try:
        esptool.main()
    except esptool.FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)
