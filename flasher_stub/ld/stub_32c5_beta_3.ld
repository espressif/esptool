MEMORY {
  iram : org = 0x40800000, len = 0x4000
  dram : org = 0x40840000, len = 0x18000
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

INCLUDE "rom_32c5_beta_3.ld"
