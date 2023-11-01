/* Note: stub is deliberately loaded close to the very top
   of available RAM, to reduce change of colliding with anything
   else... */
MEMORY {
  iram : org = 0x400BE000, len = 0x1000
  dram : org = 0x3ffcc000, len = 0x14000
}

ENTRY(stub_main)

SECTIONS {
  .text : ALIGN(4) {
    *(.literal)
    *(.text .text.*)
  } > iram

  .bss : ALIGN(4) {
     _bss_start = ABSOLUTE(.);
    *(.bss)
	_bss_end = ABSOLUTE(.);
  } > dram

  .data : ALIGN(4) {
    *(.data)
    *(.rodata .rodata.*)
  } > dram
}

INCLUDE "rom_32.ld"
