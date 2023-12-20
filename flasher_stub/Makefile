# Makefile to compile the flasher stub program
#
# Note that YOU DO NOT NEED TO COMPILE THIS IN ORDER TO JUST USE
# esptool.py - a precompiled version is included in esptool.py,
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
# or set them in a local.mk
-include local.mk

# Prefix for each cross compiler (can include a directory path)
# These can be overriden via environment variables or on the make command line
CROSS_8266 ?= xtensa-lx106-elf-
CROSS_32 ?= xtensa-esp32-elf-
CROSS_32S2 ?= xtensa-esp32s2-elf-
CROSS_32S3 ?= xtensa-esp32s3-elf-
CROSS_ESPRISCV32 ?= riscv32-esp-elf-

# extra CFLAGS to be passed on the compiler, in addition to the stock ones
EXTRA_CFLAGS ?=
EXTRA_CFLAGS_ESPRISCV32 ?=

# Python command to invoke wrap_stub.py
WRAP_STUB ?= ./wrap_stub.py

# Pass V=1 to see the commands being executed by make
ifneq ("$(V)","1")
Q = @
endif

STUB = stub_flasher
SRCS = stub_flasher.c slip.c stub_commands.c stub_write_flash.c stub_io.c
SRCS_8266 = miniz.c

BUILD_DIR = build
ESPTOOL_STUBS_DIR = ../esptool/targets/stub_flasher

STUB_ELF_8266 = $(BUILD_DIR)/$(STUB)_8266.elf
STUB_ELF_32 = $(BUILD_DIR)/$(STUB)_32.elf
STUB_ELF_32S2 = $(BUILD_DIR)/$(STUB)_32s2.elf
STUB_ELF_32S3_BETA_2 = $(BUILD_DIR)/$(STUB)_32s3beta2.elf
STUB_ELF_32S3 = $(BUILD_DIR)/$(STUB)_32s3.elf
STUB_ELF_32C3 = $(BUILD_DIR)/$(STUB)_32c3.elf
STUB_ELF_32C6BETA = $(BUILD_DIR)/$(STUB)_32c6beta.elf
STUB_ELF_32H2_BETA_1 = $(BUILD_DIR)/$(STUB)_32h2beta1.elf
STUB_ELF_32H2_BETA_2 = $(BUILD_DIR)/$(STUB)_32h2beta2.elf
STUB_ELF_32C2 = $(BUILD_DIR)/$(STUB)_32c2.elf
STUB_ELF_32C6 = $(BUILD_DIR)/$(STUB)_32c6.elf
STUB_ELF_32C5_BETA_3 = $(BUILD_DIR)/$(STUB)_32c5beta3.elf
STUB_ELF_32H2 = $(BUILD_DIR)/$(STUB)_32h2.elf
STUB_ELF_32P4 = $(BUILD_DIR)/$(STUB)_32p4.elf

STUBS_ELF =
ifneq ($(WITHOUT_ESP8266),1)
STUBS_ELF += \
  $(STUB_ELF_8266)
endif

ifneq ($(WITHOUT_ESP32_XTENSA),1)
STUBS_ELF += \
  $(STUB_ELF_32) \
  $(STUB_ELF_32S2) \
  $(STUB_ELF_32S3_BETA_2) \
  $(STUB_ELF_32S3)
endif

ifneq ($(WITHOUT_ESP32_RISCV32),1)
STUBS_ELF += \
  $(STUB_ELF_32C3) \
  $(STUB_ELF_32C6BETA) \
  $(STUB_ELF_32H2_BETA_1) \
  $(STUB_ELF_32H2_BETA_2) \
  $(STUB_ELF_32C2) \
  $(STUB_ELF_32C6) \
  $(STUB_ELF_32C5_BETA_3) \
  $(STUB_ELF_32H2) \
  $(STUB_ELF_32P4)
endif

.PHONY: all clean install

all: $(STUBS_ELF:.elf=.json)

install: $(patsubst $(BUILD_DIR)/%.elf,$(ESPTOOL_STUBS_DIR)/%.json,$(STUBS_ELF))

$(BUILD_DIR):
	$(Q) mkdir $@

$(BUILD_DIR)/%.json: $(BUILD_DIR)/%.elf
	@echo "  WRAP $^ -> $(BUILD_DIR)"
	$(Q) $(WRAP_STUB) $^

$(ESPTOOL_STUBS_DIR)/%.json: $(BUILD_DIR)/%.json
	@echo "  INSTALL $^ -> $@"
	$(Q) cp $^ $@

CFLAGS = -std=c99 -Wall -Werror -Os \
         -mtext-section-literals -mlongcalls -nostdlib -fno-builtin -flto \
         -Wl,-static -g -ffunction-sections -Wl,--gc-sections -Iinclude -Lld \
         $(EXTRA_CFLAGS)
CFLAGS_ESPRISCV32 = -std=c99 -Wall -Werror -Os \
		 -march=rv32imc -mabi=ilp32 -msmall-data-limit=0 \
         -nostdlib -fno-builtin -flto \
         -Wl,-static -g -ffunction-sections -Wl,--gc-sections -Iinclude -Lld \
         $(EXTRA_CFLAGS_ESPRISCV32)
LDLIBS = -lgcc

$(STUB_ELF_8266): $(SRCS) $(SRCS_8266) $(BUILD_DIR) ld/stub_8266.ld | Makefile
	@echo "  CC(8266)   $^ -> $@"
	$(Q) $(CROSS_8266)gcc $(CFLAGS) -DESP8266=1 -Tstub_8266.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32): $(SRCS) $(BUILD_DIR) ld/stub_32.ld | Makefile
	@echo "  CC(32)   $^ -> $@"
	$(Q) $(CROSS_32)gcc $(CFLAGS) -DESP32=1 -Tstub_32.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32S2): $(SRCS) $(BUILD_DIR) ld/stub_32s2.ld
	@echo "  CC(32S2)   $^ -> $@"
	$(Q) $(CROSS_32S2)gcc $(CFLAGS) -DESP32S2=1 -Tstub_32s2.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32S3_BETA_2): $(SRCS) $(BUILD_DIR) ld/stub_32s3_beta_2.ld
	@echo "  CC(32S3)   $^ -> $@"
	$(Q) $(CROSS_32S3)gcc $(CFLAGS) -DESP32S3BETA2=1 -Tstub_32s3_beta_2.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32S3): $(SRCS) $(BUILD_DIR) ld/stub_32s3.ld
	@echo "  CC(32S3)   $^ -> $@"
	$(Q) $(CROSS_32S3)gcc $(CFLAGS) -DESP32S3=1 -Tstub_32s3.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32C3): $(SRCS) $(BUILD_DIR) ld/stub_32c3.ld
	@echo "  CC(32C3)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32C3=1 -Tstub_32c3.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32C6BETA): $(SRCS) $(BUILD_DIR) ld/stub_32c6_beta.ld
	@echo "  CC(32C6BETA)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32C6BETA=1 -Tstub_32c6_beta.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32H2_BETA_1): $(SRCS) $(BUILD_DIR) ld/stub_32h2_beta_1.ld
	@echo "  CC(32H2BETA1)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32H2BETA1=1 -Tstub_32h2_beta_1.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32H2_BETA_2): $(SRCS) $(BUILD_DIR) ld/stub_32h2_beta_2.ld
	@echo "  CC(32H2BETA2)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32H2BETA2=1 -Tstub_32h2_beta_2.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32C2): $(SRCS) $(BUILD_DIR) ld/stub_32c2.ld
	@echo "  CC(32C2)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32C2=1 -Tstub_32c2.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32C6): $(SRCS) $(BUILD_DIR) ld/stub_32c6.ld
	@echo "  CC(32C6)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32C6=1 -Tstub_32c6.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32C5_BETA_3): $(SRCS) $(BUILD_DIR) ld/stub_32c5_beta_3.ld
	@echo "  CC(32C5BETA3)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32C5BETA3=1 -Tstub_32c5_beta_3.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32H2): $(SRCS) $(BUILD_DIR) ld/stub_32h2.ld
	@echo "  CC(32H2)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32H2=1 -Tstub_32h2.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_ELF_32P4): $(SRCS) $(BUILD_DIR) ld/stub_32p4.ld
	@echo "  CC(32P4)   $^ -> $@"
	$(Q) $(CROSS_ESPRISCV32)gcc $(CFLAGS_ESPRISCV32) -DESP32P4=1 -Tstub_32p4.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

clean:
	$(Q) rm -rf $(BUILD_DIR)
