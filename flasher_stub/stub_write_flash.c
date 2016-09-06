/* Command handlers for writing out to flash.
 *
 *  Called from stub_flasher.c
 *
 * Copyright (c) 2016 Cesanta Software Limited & Espressif Systems (Shanghai) PTE LTD.
 * All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later version.
 *
 */
#include "stub_write_flash.h"
#include "stub_flasher.h"
#include "rom_functions.h"

/* local flashing state

   This is wrapped in a structure because gcc 4.8
   generates significantly more code for ESP32
   if they are static variables (literal pool, I think!)
*/
static struct {
  bool in_flash_mode;
  uint32_t next_write;
  int next_erase_sector;
  uint32_t remaining;
  int remaining_erase_sector;
  esp_command_error last_error;
} fs;

bool is_in_flash_mode(void)
{
  return fs.in_flash_mode;
}

esp_command_error handle_flash_begin(uint32_t erase_size, uint32_t num_blocks, uint32_t block_size, uint32_t offset) {
  if (block_size > MAX_WRITE_BLOCK)
	return ESP_BAD_BLOCKSIZE;

  fs.in_flash_mode = true;
  fs.next_write = offset;
  fs.next_erase_sector = offset / FLASH_SECTOR_SIZE;
  fs.remaining = num_blocks * block_size;
  fs.remaining_erase_sector = (fs.remaining + FLASH_SECTOR_SIZE - 1) / FLASH_SECTOR_SIZE;
  fs.last_error = ESP_OK;

  if (SPIUnlock() != 0) {
	return ESP_FAILED_SPI_UNLOCK;
  }

  return ESP_OK;
}

void handle_flash_data(void *data_buf, uint32_t length) {
  /* what sector is this write going to end in?
	 make sure we've erased at least that far.
   */
  int last_sector = (fs.next_write + length + FLASH_SECTOR_SIZE - 1) / FLASH_SECTOR_SIZE;
  while(fs.next_erase_sector < last_sector) {
	if(fs.next_erase_sector % SECTORS_PER_BLOCK == 0
	   && fs.remaining_erase_sector > SECTORS_PER_BLOCK) {
	  SPIEraseBlock(fs.next_erase_sector / SECTORS_PER_BLOCK);
	  fs.next_erase_sector += SECTORS_PER_BLOCK;
	  fs.remaining_erase_sector -= SECTORS_PER_BLOCK;
	} else {
	  SPIEraseSector(fs.next_erase_sector++);
	  fs.remaining_erase_sector--;
	}
  }

  if (SPIWrite(fs.next_write, data_buf, length)) {
	fs.last_error = ESP_FAILED_SPI_OP;
  }
  fs.next_write += length;
  fs.remaining -= length;
}

esp_command_error handle_flash_end(void)
{
  if(!fs.in_flash_mode) {
	return ESP_NOT_IN_FLASH_MODE;
  }

  /* TODO: check bytes written, etc. */

  fs.in_flash_mode = false;
  return fs.last_error;
}
