/* Note: stub is deliberately loaded close to the very top
   of available RAM, to reduce change of colliding with anything
   else... */
MEMORY {
  iram : org = 0x4010D000, len = 0x2100
  dram : org = 0x3FFE8100, len = 0x13f00
}

ENTRY(stub_main_8266)

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

INCLUDE "rom_8266.ld"

PROVIDE(SPIFlashModeConfig = 0x40004568);
PROVIDE(SPIParamCfg = 0x40004c2c);
