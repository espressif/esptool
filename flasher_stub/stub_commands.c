/*
 * Copyright (c) 2016-2019 Espressif Systems (Shanghai) PTE LTD
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
#include <stdlib.h>
#include "stub_commands.h"
#include "stub_flasher.h"
#include "rom_functions.h"
#include "slip.h"
#include "soc_support.h"
#include "stub_io.h"

int handle_flash_erase(uint32_t addr, uint32_t len) {
  if (addr % FLASH_SECTOR_SIZE != 0) return 0x32;
  if (len % FLASH_SECTOR_SIZE != 0) return 0x33;
  if (SPIUnlock() != 0) return 0x34;

  while (len > 0 && (addr % FLASH_BLOCK_SIZE != 0)) {
    if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  while (len > FLASH_BLOCK_SIZE) {
    if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
    len -= FLASH_BLOCK_SIZE;
    addr += FLASH_BLOCK_SIZE;
  }

  while (len > 0) {
    if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  return 0;
}

void handle_flash_read(uint32_t addr, uint32_t len, uint32_t block_size,
                  uint32_t max_in_flight) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  uint32_t num_sent = 0, num_acked = 0;

  /* This is one routine where we still do synchronous I/O */
  stub_rx_async_enable(false);

  if (block_size > sizeof(buf)) {
    return;
  }
  MD5Init(&ctx);
  while (num_acked < len && num_acked <= num_sent) {
    while (num_sent < len && num_sent - num_acked < max_in_flight) {
      uint32_t n = len - num_sent;
      if (n > block_size) n = block_size;
      if (SPIRead(addr, (uint32_t *)buf, n) != 0) {
        break;
      }
      SLIP_send(buf, n);
      MD5Update(&ctx, buf, n);
      addr += n;
      num_sent += n;
    }
    int r = SLIP_recv(&num_acked, sizeof(num_acked));
    if (r != 4) {
      break;
    }
  }
  MD5Final(digest, &ctx);
  SLIP_send(digest, sizeof(digest));

  /* Go back to async RX */
  stub_rx_async_enable(true);
}

int handle_flash_get_md5sum(uint32_t addr, uint32_t len) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  MD5Init(&ctx);
  while (len > 0) {
    uint32_t n = len;
    if (n > FLASH_SECTOR_SIZE) {
      n = FLASH_SECTOR_SIZE;
    }
    if (SPIRead(addr, (uint32_t *)buf, n) != 0) {
      return 0x63;
    }
    MD5Update(&ctx, buf, n);
    addr += n;
    len -= n;
  }
  MD5Final(digest, &ctx);
  /* ESP32 ROM sends as hex, but we just send raw bytes - esptool.py can handle either. */
  SLIP_send_frame_data_buf(digest, sizeof(digest));
  return 0;
}

esp_command_error handle_spi_set_params(uint32_t *args, int *status)
{
  *status = SPIParamCfg(args[0], args[1], args[2], args[3], args[4], args[5]);
  return *status ? ESP_FAILED_SPI_OP : ESP_OK;
}

esp_command_error handle_spi_attach(uint32_t hspi_config_arg)
{
#ifdef ESP8266
        /* ESP8266 doesn't yet support SPI flash on HSPI, but could:
         see https://github.com/themadinventor/esptool/issues/98 */
        SelectSpiFunction();
#else
        /* spi_flash_attach calls SelectSpiFunction() and another
           function to initialise SPI flash interface.

           Second argument 'legacy' mode is not currently supported.
        */
        spi_flash_attach(hspi_config_arg, 0);
#endif
        return ESP_OK; /* neither function/attach command takes an arg */
}

static uint32_t *mem_offset;
static uint32_t mem_remaining;

esp_command_error handle_mem_begin(uint32_t size, uint32_t offset)
{
    mem_offset = (uint32_t *)offset;
    mem_remaining = size;
    return ESP_OK;
}

esp_command_error handle_mem_data(void *data, uint32_t length)
{
    uint32_t *data_words = (uint32_t *)data;
    if (mem_offset == NULL && length > 0) {
        return ESP_NOT_IN_FLASH_MODE;
    }
    if (length > mem_remaining) {
        return ESP_TOO_MUCH_DATA;
    }
    if (length % 4 != 0) {
        return ESP_BAD_DATA_LEN;
    }

    for(int i = 0; i < length; i+= 4) {
        *mem_offset++ = *data_words++;
        mem_remaining -= 4;
    }
    return ESP_OK;
}

esp_command_error handle_mem_finish()
{
    esp_command_error res = mem_remaining > 0 ? ESP_NOT_ENOUGH_DATA : ESP_OK;
    mem_remaining = 0;
    mem_offset = NULL;
    return res;
}
