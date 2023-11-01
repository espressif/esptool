MEMORY {
  iram : org = 0x40028000, len = 0x18000
  dram : org = 0x3FFD0000, len = 0x28000
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

INCLUDE "rom_32s2.ld"
