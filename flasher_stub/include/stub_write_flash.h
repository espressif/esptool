/*
 * SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Flasher commands related to writing flash */
#pragma once
#include "stub_flasher.h"
#include <stdbool.h>
#include "rom_functions.h"

bool is_in_flash_mode(void);

esp_command_error get_flash_error(void);

esp_command_error handle_flash_begin(uint32_t total_size, uint32_t offset);

esp_command_error handle_flash_deflated_begin(uint32_t uncompressed_size, uint32_t compressed_size, uint32_t offset);

void handle_flash_data(void *data_buf, uint32_t length);

#if !ESP8266
void handle_flash_encrypt_data(void *data_buf, uint32_t length);
#endif

void handle_flash_deflated_data(void *data_buf, uint32_t length);

/* same command used for deflated or non-deflated mode */
esp_command_error handle_flash_end(void);

/* Enabling 32-bit flash memory addressing for ESP32S3 */
#if defined(ESP32S3)
esp_rom_spiflash_result_t page_program_internal(int spi_num, SpiFlashRdMode mode, uint32_t spi_addr, uint8_t* addr_source, uint32_t byte_length);

esp_rom_spiflash_result_t SPIWrite4B(int spi_num, SpiFlashRdMode mode, uint32_t target, uint8_t *src_addr, int32_t len);
#endif // ESP32S3
