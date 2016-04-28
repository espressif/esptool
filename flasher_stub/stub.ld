/*
 * Copyright (c) 2016 Cesanta Software Limited
 * All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

MEMORY {
  iram : org = 0x40100000, len = 0x8000
  dram : org = 0x3FFE8000, len = 0x14000
}

ENTRY(stub_main)

SECTIONS {
  .params 0x40100000 : {
    _params_start = ABSOLUTE(.);
    *(.params)
    _params_end = ABSOLUTE(.);
  } > iram

  .code : ALIGN(4) {
    _code_start = ABSOLUTE(.);
    *(.literal)
    *(.text .text.*)
  } > iram

  .data : {
    _data_start = ABSOLUTE(.);
    *(.bss .data)
    *(.rodata .rodata.*)
  } > dram
}

INCLUDE "eagle.rom.addr.v6.ld"

PROVIDE(SPIFlashModeConfig = 0x40004568);
