#!/bin/sh

set -ex

# Setup shell script to download & configure ESP8266 & ESP32 toolchains
# for building the flasher stub program

mkdir -p ${TOOLCHAIN_DIR}
cd ${TOOLCHAIN_DIR}

if ! [ -d ${ESP8266_BINDIR} ]; then
    wget --no-verbose -O xtensa-lx106-elf.tar.gz "${ESP8266_TOOLCHAIN_URL}"
	tar zxf xtensa-lx106-elf.tar.gz
	rm xtensa-lx106-elf.tar.gz
fi

if ! [ -d ${ESP32_BINDIR} ]; then
	wget --no-verbose -O xtensa-esp32-elf.tar.gz "${ESP32_TOOLCHAIN_URL}"
	tar zxf xtensa-esp32-elf.tar.gz
	rm xtensa-esp32-elf.tar.gz
fi

if ! [ -d ${ESP32S2_BINDIR} ]; then
	wget --no-verbose -O xtensa-esp32s2-elf.tar.gz "${ESP32S2_TOOLCHAIN_URL}"
	tar zxf xtensa-esp32s2-elf.tar.gz
	rm xtensa-esp32s2-elf.tar.gz
fi
