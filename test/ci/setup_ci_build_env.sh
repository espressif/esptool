#!/bin/bash

set -exuo pipefail

BASE_URL="https://dl.espressif.com/dl/"

ESP8266_TOOLCHAIN_DIST="xtensa-lx106-elf-linux64-1.22.0-92-g8facf4c-5.2.0.tar.gz"
ESP32_TOOLCHAIN_DIST="xtensa-esp32-elf-gcc8_4_0-esp-2020r3-linux-amd64.tar.gz"
ESP32S2_TOOLCHAIN_DIST="xtensa-esp32s2-elf-gcc8_4_0-esp-2020r3-linux-amd64.tar.gz"
ESP32S3_TOOLCHAIN_DIST="xtensa-esp32s3-elf-gcc8_4_0-esp-2020r3-linux-amd64.tar.gz"
ESP32C3_TOOLCHAIN_DIST="riscv32-esp-elf-gcc8_2_0-crosstool-ng-1.24.0-126-g9fe0ac2-linux-amd64.tar.gz"

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

if ! [ -d ${ESP32S3_BINDIR} ]; then
    # gitlab CI image may already have this file
    wget --continue --no-verbose "${BASE_URL}${ESP32S3_TOOLCHAIN_DIST}"
    tar zxf ${ESP32S3_TOOLCHAIN_DIST}
fi

if ! [ -d ${ESP32C3_BINDIR} ]; then
    # gitlab CI image may already have this file
    wget --continue --no-verbose "${BASE_URL}toolchains/preview/c3/${ESP32C3_TOOLCHAIN_DIST}"
    tar zxf ${ESP32C3_TOOLCHAIN_DIST}
fi
