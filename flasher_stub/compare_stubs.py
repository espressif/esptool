#!/usr/bin/env python
import sys

# Compare the esptool stub loaders to freshly built ones
# in the build directory
#
# (Used by Travis to verify the stubs are up to date.)

def verbose_diff(new, old):
    for k in [ "data_start", "text_start"]:
        if new[k] != old[k]:
            print("New %s 0x%x old %s 0%x" % (k, new[k], old[k]))

    for k in [ "data", "text" ]:
        if len(new[k]) != len(old[k]):
            print("New %s %d bytes, old stub code %d bytes" % (k, len(new[k]), len(old)[k]))
        if new[k] != old[k]:
            print("%s is different" % k)
            if len(new[k]) == len(old[k]):
                for b in range(len(new[k])):
                    if new[k][b] != old[k][b]:
                        print("  Byte 0x%x: new 0x%02x old 0x%02x" % (b, ord(new[k][b]), ord(old[k][b])))

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
        verbose_diff(esptool.ESP8266ROM.STUB_CODE, old_8266_stub)
        same = False
    if esptool.ESP32ROM.STUB_CODE != old_32_stub:
        print("ESP32 stub code in esptool.py is different to just-built stub.")
        verbose_diff(esptool.ESP32ROM.STUB_CODE, old_32_stub)
        same = False
    if same:
        print("Stub code is the same")

    sys.exit(0 if same else 1)
