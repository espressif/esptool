/* Flasher commands related to writing flash */
#pragma once
#include "stub_flasher.h"
#include <stdbool.h>

bool is_in_flash_mode(void);

esp_command_error handle_flash_begin(uint32_t erase_size, uint32_t num_blocks, uint32_t block_size, uint32_t offset);

void handle_flash_data(void *data_buf, uint32_t length);

esp_command_error handle_flash_end(void);
