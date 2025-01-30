#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2014-2024 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: BSD-3-Clause

# This executable script is a thin wrapper around the main functionality
# in the esp_rfc2217_server Python package

# When updating this script, please also update esptool.py, espefuse.py and espsecure.py

###################################################################################
# Redirect data from a TCP/IP connection to a serial port and vice versa using RFC 2217.
#
# This is a modified version of rfc2217_server.py provided by the pyserial package
# (pythonhosted.org/pyserial/examples.html#single-port-tcp-ip-serial-bridge-rfc-2217).
# It uses a custom PortManager to properly apply the RTS & DTR signals
# for resetting ESP chips.
#
# Run the following command on the server side to make
# connection between /dev/ttyUSB1 and TCP port 4000:
#
#   python esp_rfc2217_server.py -p 4000 /dev/ttyUSB1
#
# Esptool can connect to the ESP device through that server as it is
# demonstrated in the following example:
#
#   esptool.py --port rfc2217://localhost:4000?ign_set_control flash_id
#

import contextlib
import os
import sys

if os.name != "nt":
    # Linux/macOS: remove current script directory to avoid importing this file
    # as a module; we want to import the installed esp_rfc2217_server module instead
    with contextlib.suppress(ValueError):
        executable_dir = os.path.dirname(sys.executable)
        sys.path = [
            path
            for path in sys.path
            if not path.endswith(("/bin", "/sbin")) and path != executable_dir
        ]

    # Linux/macOS: delete imported module entry to force Python to load
    # the module from scratch; this enables importing esp_rfc2217_server module in
    # other Python scripts
    with contextlib.suppress(KeyError):
        del sys.modules["esp_rfc2217_server"]

import esp_rfc2217_server

if __name__ == "__main__":
    esp_rfc2217_server.main()
