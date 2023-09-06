/*
 * SPDX-FileCopyrightText: 2016 Cesanta Software Limited
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
 */

#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Maximum write block size, used for various buffers. */
#define MAX_WRITE_BLOCK 0x4000

/* Flash geometry constants */
#define FLASH_SECTOR_SIZE 4096
#define FLASH_BLOCK_SIZE 65536
#define FLASH_PAGE_SIZE 256
#define FLASH_STATUS_MASK 0xFFFF
#define SECTORS_PER_BLOCK (FLASH_BLOCK_SIZE / FLASH_SECTOR_SIZE)

/* 32-bit addressing is supported only by ESP32S3 */
#if defined(ESP32S3) && !defined(ESP32S3BETA2)
#define FLASH_MAX_SIZE 64*1024*1024
extern bool large_flash_mode;
#else
#define FLASH_MAX_SIZE 16*1024*1024
#endif

/* Full set of protocol commands */
typedef enum {
  /* Commands supported by the ESP8266 & ESP32 bootloaders */
  ESP_FLASH_BEGIN = 0x02,
  ESP_FLASH_DATA = 0x03,
  ESP_FLASH_END = 0x04,
  ESP_MEM_BEGIN = 0x05,
  ESP_MEM_END = 0x06,
  ESP_MEM_DATA = 0x07,
  ESP_SYNC = 0x08,
  ESP_WRITE_REG = 0x09,
  ESP_READ_REG = 0x0a,

  /* Commands supported by the ESP32 bootloader */
  ESP_SPI_SET_PARAMS = 0x0b,
  ESP_PIN_READ = 0x0c, /* ??? */
  ESP_SPI_ATTACH = 0x0d,
  ESP_SPI_READ = 0x0e,
  ESP_SET_BAUD = 0x0f,
  ESP_FLASH_DEFLATED_BEGIN = 0x10,
  ESP_FLASH_DEFLATED_DATA = 0x11,
  ESP_FLASH_DEFLATED_END = 0x12,
  ESP_FLASH_VERIFY_MD5 = 0x13,

  /* Commands supported by the ESP32S2 and later bootloaders */
  ESP_GET_SECURITY_INFO = 0x14,

  /* Stub-only commands */
  ESP_ERASE_FLASH = 0xD0,
  ESP_ERASE_REGION = 0xD1,
  ESP_READ_FLASH = 0xD2,
  ESP_RUN_USER_CODE = 0xD3,

  /* Flash encryption debug mode supported command */
  ESP_FLASH_ENCRYPT_DATA = 0xD4,
} esp_command;

/* Command request header */
typedef struct __attribute__((packed)) {
  uint8_t zero;
  uint8_t op; /* maps to esp_command enum */
  uint16_t data_len;
  int32_t checksum;
  uint8_t data_buf[32]; /* actually variable length, determined by data_len */
} esp_command_req_t;

/* Command response header */
typedef struct __attribute__((packed)) {
  uint8_t resp; /* should be '1' */
  uint8_t op_ret; /* Should match 'op' */
  uint16_t len_ret; /* Length of result data (can be ignored as SLIP framing helps) */
  int32_t value; /* 32-bit response used by some commands */
} esp_command_response_t;


/* command response has some (optional) data after it, then 2 (or 4 on ESP32 ROM)
   bytes of status.
 */
typedef struct __attribute__((packed)) {
  uint8_t error; /* non-zero = failed */
  uint8_t status; /* status of a failure */
} esp_command_data_status_t;

/* Error codes */
typedef enum {
  ESP_OK = 0,

  ESP_BAD_DATA_LEN = 0xC0,
  ESP_BAD_DATA_CHECKSUM = 0xC1,
  ESP_BAD_BLOCKSIZE = 0xC2,
  ESP_INVALID_COMMAND = 0xC3,
  ESP_FAILED_SPI_OP = 0xC4,
  ESP_FAILED_SPI_UNLOCK = 0xC5,
  ESP_NOT_IN_FLASH_MODE = 0xC6,
  ESP_INFLATE_ERROR = 0xC7,
  ESP_NOT_ENOUGH_DATA = 0xC8,
  ESP_TOO_MUCH_DATA = 0xC9,

  ESP_CMD_NOT_IMPLEMENTED = 0xFF,
} esp_command_error;
