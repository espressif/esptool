## BTC MicroMiner using ESP32 NodeMCU WiFi CP2102 
#### example of operation "Ubuntu 24.04 LTS"
<img src="https://github.com/universalbit-dev/esptool/blob/master/images/serial_monitor_arduino-1.8.19.png" width=auto></img>


* [esptool.py](https://github.com/espressif/esptool)
A Python-based, open-source, platform-independent utility to communicate with the ROM bootloader in Espressif chips.
* [nerdminer_v2](https://github.com/BitMaker-hub/NerdMiner_v2)
This is a free and open source project that let you try to reach a bitcoin block with a small piece of hardware.

[![Test esptool](https://github.com/espressif/esptool/actions/workflows/test_esptool.yml/badge.svg?branch=master)](https://github.com/espressif/esptool/actions/workflows/test_esptool.yml) [![Build esptool](https://github.com/espressif/esptool/actions/workflows/build_esptool.yml/badge.svg?branch=master)](https://github.com/espressif/esptool/actions/workflows/build_esptool.yml)

installation and dependencies
[esptool-installation](https://docs.espressif.com/projects/esptool/en/latest/esp32/installation.html)

##### required:
```bash
sudo add-apt-repository universe
sudo apt install libfuse2
python3 setup.py install
```

#### Flashing Firmware ESP32 NodeMCU WiFi CP2102
##### hardware:
[ESP32](https://www.az-delivery.de/products/esp32-developmentboard)
##### firmware:
[bin ESP32-devKit- no pass](https://github.com/BitMaker-hub/NerdMiner_v2/tree/dev/bin/bin%20ESP32-devKit-%20no%20pass)

## Contribute
If you're interested in contributing to esptool.py, please check the [contributions guide](https://docs.espressif.com/projects/esptool/en/latest/contributing.html).

#### ESP32 nodeMCU Flashing Firmware ...all the steps

use esptool commands to flash files(nerdminer_v2 project)
* [erase_flash](#erase_flash)
* [bootloader](#bootloader)
* [firmware](#firmware)
* [partitions](#partitions)
* [boot_app](#boot_app)

##### python3 and esptool installation was successful...then

##### erase_flash
```bash
python3 esptool.py erase_flash
```

```bash
esptool.py v4.8.0
Found 33 serial ports
Serial port /dev/ttyUSB0
Connecting.....
Detecting chip type... Unsupported detection protocol, switching and trying again...
Connecting.....
Detecting chip type... ESP32
Chip is ESP32-D0WD (revision v1.0)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC: 94:3c:c6:38:83:c8
Uploading stub...
Running stub...
Stub running...
Erasing flash (this may take a while)...
Chip erase completed successfully in 13.5s
Hard resetting via RTS pin...
```
##### bootloader
```bash
python3 esptool.py write_flash 0x1000 0x1000_bootloader.bin
```
```bash
esptool.py v4.8.0
Found 33 serial ports
Serial port /dev/ttyUSB0
Connecting....
Detecting chip type... Unsupported detection protocol, switching and trying again...
Connecting....
Detecting chip type... ESP32
Chip is ESP32-D0WD (revision v1.0)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC:
Uploading stub...
Running stub...
Stub running...
Configuring flash size...
Flash will be erased from 0x00001000 to 0x00005fff...
Compressed 17488 bytes to 12168...
Wrote 17488 bytes (12168 compressed) at 0x00001000 in 1.3 seconds (effective 109.6 kbit/s)...
Hash of data verified.

Leaving...
Hard resetting via RTS pin...
```
##### firmware
```bash
python3 esptool.py write_flash 0x10000 0x10000_firmware.bin 
```
```bash
esptool.py v4.8.0
Found 33 serial ports
Serial port /dev/ttyUSB0
Connecting.....
Detecting chip type... Unsupported detection protocol, switching and trying again...
Connecting....
Detecting chip type... ESP32
Chip is ESP32-D0WD (revision v1.0)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC:
Uploading stub...
Running stub...
Stub running...
Configuring flash size...
Flash will be erased from 0x00010000 to 0x000fcfff...
Compressed 968736 bytes to 612509...
Wrote 968736 bytes (612509 compressed) at 0x00010000 in 54.2 seconds (effective 143.0 kbit/s)...
Hash of data verified.

Leaving...
Hard resetting via RTS pin...
```
##### partitions
```bash
python3 esptool.py write_flash 0x8000 0x8000_partitions.bin 
```
```bash
esptool.py v4.8.0
Found 33 serial ports
Serial port /dev/ttyUSB0
Connecting....
Detecting chip type... Unsupported detection protocol, switching and trying again...
Connecting.....
Detecting chip type... ESP32
Chip is ESP32-D0WD (revision v1.0)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC:
Uploading stub...
Running stub...
Stub running...
Configuring flash size...
Flash will be erased from 0x00008000 to 0x00008fff...
Compressed 3072 bytes to 137...
Wrote 3072 bytes (137 compressed) at 0x00008000 in 0.1 seconds (effective 310.2 kbit/s)...
Hash of data verified.
```

##### boot_app
```bash
python3 esptool.py write_flash 0xe000 0xe000_boot_app0.bin 
```
```bash
esptool.py v4.8.0
Found 33 serial ports
Serial port /dev/ttyUSB0
Connecting.....
Detecting chip type... Unsupported detection protocol, switching and trying again...
Connecting.......
Detecting chip type... ESP32
Chip is ESP32-D0WD (revision v1.0)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC: 
Uploading stub...
Running stub...
Stub running...
Configuring flash size...
Flash will be erased from 0x0000e000 to 0x0000ffff...
Compressed 8192 bytes to 47...
Wrote 8192 bytes (47 compressed) at 0x0000e000 in 0.2 seconds (effective 430.8 kbit/s)...
Hash of data verified.
```

* [SetupWifi AP and BTC Address](https://github.com/universalbit-dev/esptool/tree/master/images)
* [nerdminer_v2 supported-boards](https://github.com/BitMaker-hub/NerdMiner_v2?tab=readme-ov-file#current-supported-boards)



## About esptool
esptool.py was initially created by Fredrik Ahlberg (@[themadinventor](https://github.com/themadinventor/)), and later maintained by Angus Gratton (@[projectgus](https://github.com/projectgus/)). It is now supported by Espressif Systems. It has also received improvements from many members of the community.


## esptool License
This document and the attached source code are released as Free Software under GNU General Public License Version 2 or later. See the accompanying [LICENSE file](https://github.com/espressif/esptool/blob/master/LICENSE) for a copy.

#### esptool documentation
Visit the [documentation](https://docs.espressif.com/projects/esptool/) or run `esptool.py -h`.

#### Resources:
[esptool-flashing-firmware](https://docs.espressif.com/projects/esptool/en/latest/esp32/esptool/flashing-firmware.html)
