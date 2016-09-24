# Makefile to compile the flasher stub program
#
# Note that YOU DO NOT NEED TO COMPILE THIS IN ORDER TO JUST USE
# esptool.py - a precompiled version is embedded in esptool.py,
# so if you don't want to modify the stub code then you are good to go.
#
# See the comments in the top of the Makefile for parameters that
# you probably want to override.
#
# Copyright (c) 2016 Cesanta Software Limited & Angus Gratton
# All rights reserved
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Adapted from Cesanta's original Makefile at
# https://github.com/cesanta/fnc/tree/master/common/platforms/esp8266/stubs

# Override these variables on the command line

# Prefix for ESP8266 & ESP31 cross compilers (can include a directory path)
CROSS_8266 ?= xtensa-lx106-elf-
CROSS_31 ?= xtensa-esp108-elf-

# Python command to invoke wrap_stub.py
WRAP_STUB ?= ./wrap_stub.py

# Pass V=1 to see the commands being executed by make
ifneq ("$(V)","1")
Q = @
endif

# Files to compile
STUB = stub_flasher.c
LIBS = slip.c
LIBS_ESP31 = $(LIBS) md5.c

BUILD_DIR = build

STUB_ELF_8266 = $(BUILD_DIR)/$(patsubst %.c,%_8266.elf,$(STUB))
STUB_ELF_31 = $(BUILD_DIR)/$(patsubst %.c,%_31.elf,$(STUB))
STUB_JSON = $(BUILD_DIR)/$(patsubst %.c,%.json,$(STUB))

.PHONY: all clean

all: $(STUB_JSON)

$(BUILD_DIR):
	$(Q) mkdir $@

CFLAGS = -Iinclude -std=c99 -Wall -Werror -Os \
         -mtext-section-literals -mlongcalls -nostdlib -fno-builtin \
         -Wl,-static

$(STUB_ELF_8266): $(STUB) $(LIBS) $(BUILD_DIR) stub_8266.ld
	@echo "  CC(8266)   $^ -> $@"
	$(Q) $(CROSS_8266)gcc $(CFLAGS) -Tstub_8266.ld -o $@ $(filter %.c, $^)

$(STUB_ELF_31): $(STUB) $(LIBS_ESP31) $(BUILD_DIR) stub_31.ld
	@echo "  CC(31)   $^ -> $@"
	$(Q) $(CROSS_31)gcc $(CFLAGS) -DESP31 -Tstub_31.ld -o $@ $(filter %.c, $^)

$(STUB_JSON): $(STUB_ELF_8266) $(STUB_ELF_31) wrap_stub.py
	@echo "  WRAP $^ -> $@"
	$(Q) $(WRAP_STUB) $(filter %.elf,$^) $@

clean:
	$(Q) rm -rf $(BUILD_DIR)
