#!/bin/bash

set -exuo pipefail

ESP8266_TOOLCHAIN_URL="https://dl.espressif.com/dl/xtensa-lx106-elf-linux64-1.22.0-92-g8facf4c-5.2.0.tar.gz"
ESP32_TOOLCHAIN_URL="https://github.com/espressif/crosstool-NG/releases/download/esp-2022r1/xtensa-esp32-elf-gcc11_2_0-esp-2022r1-linux-amd64.tar.xz"
ESP32S2_TOOLCHAIN_URL="https://github.com/espressif/crosstool-NG/releases/download/esp-2022r1/xtensa-esp32s2-elf-gcc11_2_0-esp-2022r1-linux-amd64.tar.xz"
ESP32S3_TOOLCHAIN_URL="https://github.com/espressif/crosstool-NG/releases/download/esp-2022r1/xtensa-esp32s3-elf-gcc11_2_0-esp-2022r1-linux-amd64.tar.xz"
ESP32C3_TOOLCHAIN_URL="https://github.com/espressif/crosstool-NG/releases/download/esp-2022r1/riscv32-esp-elf-gcc11_2_0-esp-2022r1-linux-amd64.tar.xz"

# Setup shell script to download & configure ESP8266 & ESP32 toolchains
# for building the flasher stub program

mkdir -p ${TOOLCHAIN_DIR}
cd ${TOOLCHAIN_DIR}

if ! [ -d ${ESP8266_BINDIR} ]; then
    wget --continue --no-verbose "${ESP8266_TOOLCHAIN_URL}"
    tar zxf $(basename ${ESP8266_TOOLCHAIN_URL})
fi

if ! [ -d ${ESP32_BINDIR} ]; then
    # gitlab CI image may already have this file
    wget --continue --no-verbose "${ESP32_TOOLCHAIN_URL}"
    tar Jxf $(basename ${ESP32_TOOLCHAIN_URL})
fi

if ! [ -d ${ESP32S2_BINDIR} ]; then
    # gitlab CI image may already have this file
    wget --continue --no-verbose "${ESP32S2_TOOLCHAIN_URL}"
    tar Jxf $(basename ${ESP32S2_TOOLCHAIN_URL})
fi

if ! [ -d ${ESP32S3_BINDIR} ]; then
    # gitlab CI image may already have this file
    wget --continue --no-verbose "${ESP32S3_TOOLCHAIN_URL}"
    tar Jxf $(basename ${ESP32S3_TOOLCHAIN_URL})
fi

if ! [ -d ${ESP32C3_BINDIR} ]; then
    # gitlab CI image may already have this file
    wget --continue --no-verbose "${ESP32C3_TOOLCHAIN_URL}"
    tar Jxf $(basename ${ESP32C3_TOOLCHAIN_URL})
fi
