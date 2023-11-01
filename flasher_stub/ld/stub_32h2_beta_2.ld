MEMORY {
  iram : org = 0x40380000, len = 0x4000
  dram : org = 0x3FC84000, len = 0x18000
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

INCLUDE "rom_32h2_beta_2.ld"
