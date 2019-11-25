---
name: Operation with ESP chip fails (can't flash, can't connect, etc)
about: esptool.py doesn't work as expected when talking to connected ESP chip
title: ''
labels: operation-failure
assignees: ''

---

----------------------------- Delete below -----------------------------

Most failures to connect, flash, etc. turn out to be problems with the hardware setup.

Please check any guide that came with your hardware, and also check these troubleshooting steps:

https://github.com/espressif/esptool/#troubleshooting

If nothing here helps with the issue, please delete this text then provide as many details as possible about your hardware and computer setup.

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

# Are you running esptool.py from an IDE such as Arduino or Eclipse? If yes, please provide full details including versions

Example: Arduino IDE v2.5.77

# Full esptool.py command line that was run:

esptool.py -p COM9 write_flash 0x0 bootloader.bin

# Full output from esptool.py

 (please copy and paste all lines of output here)

# Do you have any other information from investigating this?

Example: Only fails 1 in every 3 times.

# Is there any other information you can think of which will help us reproduce this problem?

Example: If I shut my eyes, the problem goes away.
