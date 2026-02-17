MEMORY {
  iram : org = 0x4FF60000, len = 0x100
  dram : org = 0x4FF70000, len = 0x100
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

PROVIDE ( ets_printf = 0x4fc00024 );
