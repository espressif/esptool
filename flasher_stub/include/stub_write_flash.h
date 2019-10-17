/* Flasher commands related to writing flash */
#pragma once
#include "stub_flasher.h"
#include <stdbool.h>

bool is_in_flash_mode(void);

esp_command_error get_flash_error(void);

esp_command_error handle_flash_begin(uint32_t total_size, uint32_t offset);

esp_command_error handle_flash_deflated_begin(uint32_t uncompressed_size, uint32_t compressed_size, uint32_t offset);

void handle_flash_data(void *data_buf, uint32_t length);

#ifdef ESP32
void handle_flash_encrypt_data(void *data_buf, uint32_t length);
#endif

void handle_flash_deflated_data(void *data_buf, uint32_t length);

/* same command used for deflated or non-deflated mode */
esp_command_error handle_flash_end(void);

