import os
from setuptools import setup

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

setup(
    scripts=scripts,
    entry_points=entry_points,
)
