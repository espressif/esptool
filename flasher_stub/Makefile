# Makefile to compile the flasher stub program
#
# Note that YOU DO NOT NEED TO COMPILE THIS IN ORDER TO JUST USE
# esptool.py - a precompiled version is embedded in esptool.py,
# so if you don't want to modify the stub code then you are good to go.
#
# See the comments in the top of the Makefile for parameters that
# you probably want to override.
#
# Copyright (c) 2016 Cesanta Software Limited
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

# Path to the Espressif SDK root dir
SDK_DIR ?= ../../esp_iot_sdk_v1.5.1

# Prefix for the cross compiler (can include a directory path)
CROSS ?= xtensa-lx106-elf-

# Python command to invoke wrap_stub.py
WRAP_STUB ?= ./wrap_stub.py

# Pass V=1 to see the commands being executed by make
ifneq ("$(V)","1")
Q = @
endif

# Files to compile
STUB = stub_flasher.c
LIBS = slip.c

BUILD_DIR = build

STUB_ELF = $(BUILD_DIR)/$(patsubst %.c,%.elf,$(STUB))
STUB_JSON = $(BUILD_DIR)/$(patsubst %.c,%.json,$(STUB))

.PHONY: all clean

all: $(STUB_JSON)

$(BUILD_DIR):
	$(Q) mkdir $(BUILD_DIR)

$(STUB_ELF): $(STUB) $(LIBS) | $(BUILD_DIR)
	@echo "  CC   $^ -> $@"
	$(Q) $(CROSS)gcc -I$(SDK_DIR) -std=c99 -Wall -Werror -Os \
         -mtext-section-literals -mlongcalls -nostdlib -fno-builtin \
         -Wl,-static -Tstub.ld -o $@ $^

$(STUB_JSON): $(STUB_ELF) wrap_stub.py
	@echo "  WRAP $< -> $@"
	$(Q) $(WRAP_STUB) $< $@

clean:
	$(Q) rm -rf $(BUILD_DIR)
