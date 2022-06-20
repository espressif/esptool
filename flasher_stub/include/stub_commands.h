/*
 * SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Flasher command handlers, called from stub_flasher.c

   Commands related to writing flash are in stub_write_flash_xxx.
*/
#pragma once
#include "stub_flasher.h"
#include "rom_functions.h"
#include <stdbool.h>

int handle_flash_erase(uint32_t addr, uint32_t len);

void handle_flash_read(uint32_t addr, uint32_t len, uint32_t block_size, uint32_t max_in_flight);

int handle_flash_get_md5sum(uint32_t addr, uint32_t len);

int handle_flash_read_chip_id();

esp_command_error handle_spi_set_params(uint32_t *args, int *status);

esp_command_error handle_spi_attach(uint32_t hspi_config_arg);

esp_command_error handle_mem_begin(uint32_t size, uint32_t offset);

esp_command_error handle_mem_data(void *data, uint32_t length);

esp_command_error handle_mem_finish(void);

typedef struct {
    uint32_t addr;
    uint32_t value;
    uint32_t mask;
    uint32_t delay_us;
} write_reg_args_t;

esp_command_error handle_write_reg(const write_reg_args_t *cmd_buf, uint32_t num_commands);

/* Enabling 32-bit flash memory addressing for ESP32S3 */
#if defined(ESP32S3)
esp_rom_spiflash_result_t SPIRead4B(int spi_num, SpiFlashRdMode mode, uint32_t flash_addr, uint8_t* buf, int len);
#endif // ESP32S3

/* Get security info command only on ESP32S2 and later */
#if ESP32S2_OR_LATER
esp_command_error handle_get_security_info(void);
#endif // ESP32S2_OR_LATER
