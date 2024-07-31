MEMORY {
  iram : org = 0x40830000, len = 0x100
  dram : org = 0x40830100, len = 0x100
}

ENTRY(ram_main)

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

INCLUDE "../../../../flasher_stub/ld/rom_32c61.ld"
