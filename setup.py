import os
from setuptools import setup

if os.name != "nt":
    # For backward compatibility with py suffix
    scripts = ["esptool.py", "espefuse.py", "espsecure.py", "esp_rfc2217_server.py"]
    entry_points = {
        "console_scripts": [
            "esptool=esptool.__init__:_main",
            "espsecure=espsecure.__init__:_main",
            "espefuse=espefuse.__init__:_main",
            "esp_rfc2217_server=esp_rfc2217_server.__init__:main",
        ],
    }
else:
    scripts = []
    entry_points = {
        "console_scripts": [
            "esptool=esptool.__init__:_main",
            "espsecure=espsecure.__init__:_main",
            "espefuse=espefuse.__init__:_main",
            "esp_rfc2217_server=esp_rfc2217_server.__init__:main",
            # For backward compatibility with py suffix
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
