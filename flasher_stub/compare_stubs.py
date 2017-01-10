#!/usr/bin/env python
import sys, os.path, json

# Compare the esptool stub loaders to freshly built ones
# in the build directory
#
# (Used by Travis to verify the stubs are up to date.)

if __name__ == "__main__":
    same = True
    sys.path.append("..")
    import esptool

    old_8266_stub = esptool.ESP8266ROM.STUB_CODE
    old_32_stub = esptool.ESP32ROM.STUB_CODE

    # hackiness: importing this module edits the esptool module
    import esptool_test_stub

    if esptool.ESP8266ROM.STUB_CODE != old_8266_stub:
        print("ESP8266 stub code in esptool.py is different to just-built stub")
        same = False
    if esptool.ESP32ROM.STUB_CODE != old_32_stub:
        print("ESP32 stub code in esptool.py is different to just-built stub.")
        same = False
    if same:
        print("Stub code is the same")

    sys.exit(0 if same else 1)
