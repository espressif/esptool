/*
 * Copyright (c) 2016-2019 Espressif Systems (Shanghai) PTE LTD
 * All rights reserved
 *
 * This file is part of the esptool.py binary flasher stub.
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

/* Flasher command handlers, called from stub_flasher.c

   Commands related to writing flash are in stub_write_flash_xxx.
*/
#pragma once
#include "stub_flasher.h"
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
