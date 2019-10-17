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
