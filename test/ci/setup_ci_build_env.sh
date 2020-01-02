#!/bin/bash

set -exuo pipefail

BASE_URL="https://dl.espressif.com/dl/"

ESP8266_TOOLCHAIN_DIST="xtensa-lx106-elf-linux64-1.22.0-92-g8facf4c-5.2.0.tar.gz"
ESP32_TOOLCHAIN_DIST="xtensa-esp32-elf-gcc8_2_0-esp-2019r2-linux-amd64.tar.gz"
ESP32S2_TOOLCHAIN_DIST="xtensa-esp32s2-elf-gcc8_2_0-esp-2019r2-linux-amd64.tar.gz"

# Setup shell script to download & configure ESP8266 & ESP32 toolchains
# for building the flasher stub program

mkdir -p ${TOOLCHAIN_DIR}
cd ${TOOLCHAIN_DIR}

if ! [ -d ${ESP8266_BINDIR} ]; then
    wget --continue --no-verbose "${BASE_URL}${ESP8266_TOOLCHAIN_DIST}"
    tar zxf ${ESP8266_TOOLCHAIN_DIST}
fi

if ! [ -d ${ESP32_BINDIR} ]; then
    # gitlab CI image may already have this file
    wget --continue --no-verbose "${BASE_URL}${ESP32_TOOLCHAIN_DIST}"
    tar zxf ${ESP32_TOOLCHAIN_DIST}
fi

if ! [ -d ${ESP32S2_BINDIR} ]; then
    # gitlab CI image may already have this file
    wget --continue --no-verbose "${BASE_URL}${ESP32S2_TOOLCHAIN_DIST}"
    tar zxf ${ESP32S2_TOOLCHAIN_DIST}
fi
