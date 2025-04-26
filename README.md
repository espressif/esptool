# BTC MicroMiner using ESP32 NodeMCU WiFi CP2102

![esptool](https://github.com/universalbit-dev/esptool/blob/master/images/serial_monitor_arduino-1.8.19.png)

## Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Flashing Firmware](#flashing-firmware)
5. [Commands Overview](#commands-overview)
6. [Additional Resources](#additional-resources)
7. [Contribute](#contribute)
8. [About esptool](#about-esptool)
9. [License](#license)

---

## Introduction

The **BTC MicroMiner** project uses the ESP32 NodeMCU WiFi CP2102 to create a lightweight Bitcoin mining setup. This repository provides tools and detailed steps to flash firmware, configure, and operate the ESP32 for mining.

This project utilizes:
- [esptool.py](https://github.com/espressif/esptool): A Python-based utility for interacting with Espressif chips.
- [nerdminer_v2](https://github.com/BitMaker-hub/NerdMiner_v2): An open-source project for Bitcoin mining on small hardware.

---

## Prerequisites

Before proceeding, ensure you have:
- A Linux-based operating system (e.g., Ubuntu 24.04 LTS).
- Python 3 and pip installed.
- An ESP32 NodeMCU development board.

---

## Installation

### Step 1: Install Dependencies
Run the following commands to set up the environment:
```bash
sudo add-apt-repository universe
sudo apt install libfuse2
python3 setup.py install
```

### Step 2: Clone the Repository
```bash
git clone https://github.com/universalbit-dev/esptool.git
cd esptool
```

---

## Flashing Firmware

### Required Hardware
- [ESP32 NodeMCU WiFi CP2102](https://www.az-delivery.de/products/esp32-developmentboard)  
![ESP32 NodeMCU](https://github.com/universalbit-dev/esptool/blob/master/ESP32_NodeMCU_Module%20.png)

### Firmware Source
- [ESP32-devKit Firmware](https://github.com/BitMaker-hub/NerdMiner_v2/tree/dev/bin/bin%20ESP32-devKit-%20no%20pass)

### Flashing Steps
1. **Erase Flash**
    ```bash
    python3 esptool.py erase_flash
    ```
2. **Write Bootloader**
    ```bash
    python3 esptool.py write_flash 0x1000 0x1000_bootloader.bin
    ```
3. **Write Firmware**
    ```bash
    python3 esptool.py write_flash 0x10000 0x10000_firmware.bin
    ```
4. **Write Partitions**
    ```bash
    python3 esptool.py write_flash 0x8000 0x8000_partitions.bin
    ```
5. **Write Boot App**
    ```bash
    python3 esptool.py write_flash 0xe000 0xe000_boot_app0.bin
    ```

---

## Commands Overview

Below is a summary of the key `esptool` commands used in this project:

1. **Erase Flash**
    - Clears all existing firmware data.
    - Example:
      ```bash
      python3 esptool.py erase_flash
      ```

2. **Write Bootloader**
    - Installs the bootloader at memory address `0x1000`.
    - Example:
      ```bash
      python3 esptool.py write_flash 0x1000 0x1000_bootloader.bin
      ```

3. **Write Firmware**
    - Loads the main firmware into the ESP32.
    - Example:
      ```bash
      python3 esptool.py write_flash 0x10000 0x10000_firmware.bin
      ```

4. **Write Partitions**
    - Writes partition table data into the ESP32.
    - Example:
      ```bash
      python3 esptool.py write_flash 0x8000 0x8000_partitions.bin
      ```

5. **Write Boot App**
    - Updates the bootloader application.
    - Example:
      ```bash
      python3 esptool.py write_flash 0xe000 0xe000_boot_app0.bin
      ```

---

## Additional Resources

- [esptool-flashing-firmware Documentation](https://docs.espressif.com/projects/esptool/en/latest/esp32/esptool/flashing-firmware.html)
- [Setup WiFi AP and BTC Address](https://github.com/universalbit-dev/esptool/tree/master/images)
- [Supported Boards](https://github.com/BitMaker-hub/NerdMiner_v2?tab=readme-ov-file#current-supported-boards)
- [NerdMiner_v2 Project](https://github.com/BitMaker-hub/NerdMiner_v2)

---

## Contribute

We welcome contributions to improve **esptool.py** and this project.

---

## About esptool

`esptool.py` is a Python-based utility created by Fredrik Ahlberg ([@themadinventor](https://github.com/themadinventor)) and maintained by Angus Gratton ([@projectgus](https://github.com/projectgus)). It is widely used for bootloading and firmware flashing of Espressif chips.

For detailed documentation, visit the [official esptool documentation](https://docs.espressif.com/projects/esptool/).

---

## License

This project and its source code are licensed under the GNU General Public License Version 2 or later. See the [LICENSE file](https://github.com/espressif/esptool/blob/master/LICENSE) for details.

---
