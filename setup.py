# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later
import importlib.util
import os

import setuptools

# Python 3.7 and 3.8 cannot install setuptools 77, the first version that
# accepts license_expression. setuptools 77 and newer can only use it when
# packaging 24.2 or newer is importable.
major = setuptools.__version__.split(".")[0]
if (
    major.isdigit()
    and int(major) >= 77
    and importlib.util.find_spec("packaging.licenses")
):
    license_kwargs = {"license_expression": "GPL-2.0-or-later"}
else:
    license_kwargs = {"license": "GPL-2.0-or-later"}

if os.name != "nt":
    scripts = ["esptool.py", "espefuse.py", "espsecure.py", "esp_rfc2217_server.py"]
    entry_points = {}
else:
    scripts = []
    entry_points = {
        "console_scripts": [
            "esptool.py=esptool.__init__:_main",
            "espsecure.py=espsecure.__init__:_main",
            "espefuse.py=espefuse.__init__:_main",
            "esp_rfc2217_server.py=esp_rfc2217_server.__init__:main",
        ],
    }

setuptools.setup(
    scripts=scripts,
    entry_points=entry_points,
    **license_kwargs,
)
