#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

# This executable script is a thin wrapper around the main functionality in the espefuse Python package
#
# If esptool (with espefuse and espsecure) is installed via setup.py or pip then this file is not used at all,
# it's compatibility for the older "run from source dir" esptool approach.

import espefuse

if __name__ == '__main__':
    espefuse._main()
