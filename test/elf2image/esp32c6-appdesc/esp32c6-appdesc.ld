MEMORY
{
  /**
   * 0x42000000 is start of flash + 0x20 for image + extended header and segment header 
   * 0x14c is length of esp_app_desc_t structure
  */
  drom_seg (R) : org = 0x42000020, len = 0x14c 
}

SECTIONS
{
  .flash.appdesc :
  {
    KEEP(*(.flash.appdesc))
  } > drom_seg
}