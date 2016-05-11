/*
 * Copyright (c) 2016 Cesanta Software Limited & Angus Gratton
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
  iram : org = 0x40040000, len = 0x20000
  dram : org = 0x3FFD8000, len = 0x24000
}

ENTRY(stub_main)

SECTIONS {
  .params 0x40040000 : {
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

/* ROM function addresses, refer to 'pro.rom.addr.ld' in the ESP32
   RTOS SDK
*/
PROVIDE ( SPIEraseSector = 0x40004708 );
PROVIDE ( SPIRead = 0x40004898 );
PROVIDE ( SPIWrite = 0x40004738 );
PROVIDE ( SPI_write_enable = 0x400041bc );
PROVIDE ( SPI_write_status = 0x40003fd0 );
PROVIDE ( SPI_read_status = 0x40003efc );

PROVIDE ( ets_delay_us = 0x40002db4 );

PROVIDE ( memcpy = 0x40006974 );
PROVIDE ( memset = 0x40006be4 );
