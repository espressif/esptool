/* Declarations for functions in ESP8266 ROM code
 *
 * Copyright (c) 2016-2017 Cesanta Software Limited & Espressif Systems (Shanghai) PTE LTD
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
#pragma once

#include <stdint.h>

int uart_rx_one_char(uint8_t *ch);
uint8_t uart_rx_one_char_block();
int uart_tx_one_char(char ch);
void uart_div_modify(uint32_t uart_no, uint32_t baud_div);

int SendMsg(uint8_t *msg, uint8_t size);
int send_packet(const void *packet, uint32_t size);

void _putc1(char *ch);

void ets_delay_us(uint32_t us);

typedef enum { SPI_FLASH_RESULT_OK = 0,
               SPI_FLASH_RESULT_ERR = 1,
               SPI_FLASH_RESULT_TIMEOUT = 2 } SpiFlashOpResult;

SpiFlashOpResult SPILock();
SpiFlashOpResult SPIUnlock();
SpiFlashOpResult SPIRead(uint32_t addr, void *dst, uint32_t size);
SpiFlashOpResult SPIWrite(uint32_t addr, const uint8_t *src, uint32_t size);
SpiFlashOpResult SPIEraseChip();
SpiFlashOpResult SPIEraseBlock(uint32_t block_num);
SpiFlashOpResult SPIEraseSector(uint32_t sector_num);
uint32_t SPI_read_status();
uint32_t Wait_SPI_Idle();
void spi_flash_attach();

void SelectSpiFunction();
void SPIFlashModeConfig(uint32_t a, uint32_t b);
void SPIReadModeCnfig(uint32_t a);
uint32_t SPIParamCfg(uint32_t deviceId, uint32_t chip_size, uint32_t block_size, uint32_t sector_size, uint32_t page_size, uint32_t status_mask);

void Cache_Read_Disable();

void memset(void *addr, uint8_t c, uint32_t len);

void ets_delay_us(uint32_t delay_micros);

void ets_isr_mask(uint32_t ints);
void ets_isr_unmask(uint32_t ints);
void ets_intr_lock();
void ets_intr_unlock();
void ets_set_user_start(void (*user_start_fn)());

uint32_t rtc_get_reset_reason();
void software_reset();
void rom_phy_reset_req();

void uart_rx_intr_handler(void *arg);

void _ResetVector();

/* Crypto functions are from wpa_supplicant. */
int md5_vector(uint32_t num_msgs, const uint8_t *msgs[],
               const uint32_t *msg_lens, uint8_t *digest);
int sha1_vector(uint32_t num_msgs, const uint8_t *msgs[],
                const uint32_t *msg_lens, uint8_t *digest);

struct MD5Context {
  uint32_t buf[4];
  uint32_t bits[2];
  uint8_t in[64];
};

void MD5Init(struct MD5Context *ctx);
void MD5Update(struct MD5Context *ctx, void *buf, uint32_t len);
void MD5Final(uint8_t digest[16], struct MD5Context *ctx);

typedef struct {
    uint32_t device_id;
    uint32_t chip_size;    // chip size in bytes
    uint32_t block_size;
    uint32_t sector_size;
    uint32_t page_size;
    uint32_t status_mask;
} esp_rom_spiflash_chip_t;

/* Some ESP32-only ROM functions */
#ifdef ESP32
uint32_t ets_get_detected_xtal_freq(void);
void uart_tx_flush(int uart);
uint32_t ets_efuse_get_spiconfig(void);

/* These functions are in ets_sys.h on ESP8266 */
typedef void (*int_handler_t)(void *arg);
int_handler_t ets_isr_attach(uint32_t int_num, int_handler_t handler,
                             void *arg);

/* Note: this is a static function whose first argument was elided by the
   compiler. */
SpiFlashOpResult SPI_read_status_high(uint32_t *status);

SpiFlashOpResult SPI_write_status(esp_rom_spiflash_chip_t *spi, uint32_t status_value);

#endif
