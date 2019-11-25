---
name: ESP chip operation fails (can't flash, can't connect, etc)
about: Report a problem working with attached hardware
title: ''
labels: operation-failure
assignees: ''

---

----------------------------- Delete below -----------------------------

Most failures to connect, flash, etc. are problems with the hardware.

Please check any guide that came with your hardware, and also check these troubleshooting steps:

https://github.com/espressif/esptool/#troubleshooting

If still experiencing the issue, please delete the text in this box and then provide as many details as possible below about your hardware and computer setup.

----------------------------- Delete above -----------------------------


# Operating system

# Python version

Can run `python -V` to check this.


# What Chip

(For example: ESP8266, ESP32-PICO-D4, ESP32-WROOM32 module, etc)


# What development board or other hardware is the chip attached to

(For example: DevKitC, NodeMCU board, plain module on breadboard, etc)

If your hardware is custom or unusual, please attach a photo to the issue.


# Is anything else attached to the development board, except for the serial flasher connections?

Example: GPIO 18 & 19 are connected to I2C devices.


# Are you running esptool.py from an IDE such as Arduino or Eclipse?

Example: No IDE, Windows command prompt

Example 2: Arduino ESP8266 IDE version 2.5.77


# Full esptool.py command line that was run:

esptool.py -p COM999 write_flash 0x0 bootloader.bin


# Full output from esptool.py

(Please copy and paste all lines of output here)


# Do you have any other information from investigating this?

Example: The command succeeds 1 in every 3 tries


# Is there any other information you can think of which will help us reproduce this problem?

Example: I also have a Windows 95 PC, esptool command works correctly on this PC.
