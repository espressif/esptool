/*
 * SPDX-FileCopyrightText: 2016 Cesanta Software Limited
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
 */

/*
 * Main flasher stub logic
 *
 * This stub uses the same SLIP framing and basic command/response structure
 * as the in-ROM flasher program, but with some enhanced
 * functions and also standardizes the flasher features between different chips.
 *
 * Actual command handlers are implemented in stub_commands.c
 */
#include <stdlib.h>
#include "stub_flasher.h"
#include "rom_functions.h"
#include "slip.h"
#include "stub_commands.h"
#include "stub_write_flash.h"
#include "stub_io.h"
#include "soc_support.h"

/* Buffers for reading from UART. Data is read double-buffered, so
   we can read into one buffer while handling data from the other one
   (used for flashing throughput.) */
typedef struct {
  uint8_t buf_a[MAX_WRITE_BLOCK+64];
  uint8_t buf_b[MAX_WRITE_BLOCK+64];
  volatile uint8_t *reading_buf; /* Pointer to buf_a, or buf_b - which are we reading_buf? */
  uint16_t read; /* how many bytes have we read in the frame */
  slip_state_t state;
  esp_command_req_t *command; /* Pointer to buf_a or buf_b as latest command received */
} uart_buf_t;
static volatile uart_buf_t ub;

/* esptool protcol "checksum" is XOR of 0xef and each byte of
   data payload. */
static uint8_t calculate_checksum(uint8_t *buf, int length)
{
  uint8_t res = 0xef;
  for(int i = 0; i < length; i++) {
    res ^= buf[i];
  }
  return res;
}

#if USE_MAX_CPU_FREQ
static bool can_use_max_cpu_freq()
{
  /* Check if any of available USB modes are being used. */
  #if WITH_USB_OTG && !WITH_USB_JTAG_SERIAL
  return stub_uses_usb_otg();
  #elif !WITH_USB_OTG && WITH_USB_JTAG_SERIAL
  return stub_uses_usb_jtag_serial();
  #elif WITH_USB_OTG && WITH_USB_JTAG_SERIAL
  return stub_uses_usb_otg() || stub_uses_usb_jtag_serial();
  #else
  return false;
  #endif
}

#if ESP32C6
static uint32_t pcr_sysclk_conf_reg = 0;
#else
static uint32_t cpu_per_conf_reg = 0;
static uint32_t sysclk_conf_reg = 0;
#endif

static void set_max_cpu_freq()
{
  if (can_use_max_cpu_freq())
  {
    /* Set CPU frequency to max. This also increases SPI speed. */
    #if ESP32C6
    pcr_sysclk_conf_reg = READ_REG(PCR_SYSCLK_CONF_REG);
    WRITE_REG(PCR_SYSCLK_CONF_REG, (pcr_sysclk_conf_reg & ~PCR_SOC_CLK_SEL_M) | (PCR_SOC_CLK_MAX << PCR_SOC_CLK_SEL_S));
    #else
    cpu_per_conf_reg = READ_REG(SYSTEM_CPU_PER_CONF_REG);
    sysclk_conf_reg = READ_REG(SYSTEM_SYSCLK_CONF_REG);
    WRITE_REG(SYSTEM_CPU_PER_CONF_REG, (cpu_per_conf_reg & ~SYSTEM_CPUPERIOD_SEL_M) | (SYSTEM_CPUPERIOD_MAX << SYSTEM_CPUPERIOD_SEL_S));
    WRITE_REG(SYSTEM_SYSCLK_CONF_REG, (sysclk_conf_reg & ~SYSTEM_SOC_CLK_SEL_M) | (SYSTEM_SOC_CLK_MAX << SYSTEM_SOC_CLK_SEL_S));
    #endif
  }
}

static void reset_cpu_freq()
{
  /* Restore saved sysclk_conf and cpu_per_conf registers.
     Use only if set_max_cpu_freq() has been called. */
  #if ESP32C6
  if (can_use_max_cpu_freq() && pcr_sysclk_conf_reg != 0)
  {
    WRITE_REG(PCR_SYSCLK_CONF_REG, (READ_REG(PCR_SYSCLK_CONF_REG) & ~PCR_SOC_CLK_SEL_M) | (pcr_sysclk_conf_reg & PCR_SOC_CLK_SEL_M));
  }
  #else
  if (can_use_max_cpu_freq() && sysclk_conf_reg != 0 && cpu_per_conf_reg != 0)
  {
    WRITE_REG(SYSTEM_CPU_PER_CONF_REG, (READ_REG(SYSTEM_CPU_PER_CONF_REG) & ~SYSTEM_CPUPERIOD_SEL_M) | (cpu_per_conf_reg & SYSTEM_CPUPERIOD_SEL_M));
    WRITE_REG(SYSTEM_SYSCLK_CONF_REG, (READ_REG(SYSTEM_SYSCLK_CONF_REG) & ~SYSTEM_SOC_CLK_SEL_M) | (sysclk_conf_reg & SYSTEM_SOC_CLK_SEL_M));
  }
  #endif
}
#endif // USE_MAX_CPU_FREQ

static void stub_handle_rx_byte(char byte)
{
  int16_t r = SLIP_recv_byte(byte, (slip_state_t *)&ub.state);
  if (r >= 0) {
    ub.reading_buf[ub.read++] = (uint8_t) r;
    if (ub.read == MAX_WRITE_BLOCK+64) {
      /* shouldn't happen unless there are data errors */
      r = SLIP_FINISHED_FRAME;
    }
  }
  if (r == SLIP_FINISHED_FRAME) {
    /* end of frame, set 'command'
       to be processed by main thread */
    if(ub.reading_buf == ub.buf_a) {
      ub.command = (esp_command_req_t *)ub.buf_a;
      ub.reading_buf = ub.buf_b;
    } else {
      ub.command = (esp_command_req_t *)ub.buf_b;
      ub.reading_buf = ub.buf_a;
    }
    ub.read = 0;
  }
}

static esp_command_error verify_data_len(esp_command_req_t *command, uint8_t len)
{
  return (command->data_len == len) ? ESP_OK : ESP_BAD_DATA_LEN;
}

void cmd_loop() {
  while(1) {
    /* Wait for a command */
    while(ub.command == NULL) {
      stub_io_idle_hook();
    }
    esp_command_req_t *command = ub.command;
    ub.command = NULL;
    /* provide easy access for 32-bit data words */
    uint32_t *data_words = (uint32_t *)command->data_buf;

    /* Send command response header */
    esp_command_response_t resp = {
      .resp = 1,
      .op_ret = command->op,
      .len_ret = 2, /* esptool.py checks this length */
      .value = 0,
    };

    /* Some commands need to set resp.len_ret or resp.value before it is sent back */
    switch(command->op) {
    case ESP_READ_REG:
        if (command->data_len == 4) {
            resp.value = READ_REG(data_words[0]);
        }
        break;
    case ESP_FLASH_VERIFY_MD5:
        resp.len_ret = 16 + 2; /* Will sent 16 bytes of data with MD5 value */
        break;
    #if ESP32S2_OR_LATER
    case ESP_GET_SECURITY_INFO:
        resp.len_ret = SECURITY_INFO_BYTES; /* Buffer size varies */
        break;
    #endif // ESP32S2_OR_LATER
    default:
        break;
    }

    /* Send the command response */
    SLIP_send_frame_delimiter();
    SLIP_send_frame_data_buf(&resp, sizeof(esp_command_response_t));

    if(command->data_len > MAX_WRITE_BLOCK+16) {
      SLIP_send_frame_data(ESP_BAD_DATA_LEN);
      SLIP_send_frame_data(0xEE);
      SLIP_send_frame_delimiter();
      continue;
    }

    /* ... ESP_FLASH_VERIFY_MD5 and ESP_GET_SECURITY_INFO will insert
    * in-frame response data between here and when we send the
    * status bytes at the end of the frame */

    esp_command_error error = ESP_CMD_NOT_IMPLEMENTED;
    int status = 0;

    /* First stage of command processing - before sending error/status */
    switch (command->op) {
    case ESP_SYNC:
      /* Bootloader responds to the SYNC request with eight identical SYNC responses. Stub flasher should react
      * the same way so SYNC could be possible with the flasher stub as well. This helps in cases when the chip
      * cannot be reset and the flasher stub keeps running. */
      error = verify_data_len(command, 36);

      if (error == ESP_OK) {
        /* resp.value remains 0 which esptool.py can use to detect the flasher stub */
        resp.value = 0;
        for (int i = 0; i < 7; ++i) {
            SLIP_send_frame_data(error);
            SLIP_send_frame_data(status);
            SLIP_send_frame_delimiter(); /* end the previous frame */

            SLIP_send_frame_delimiter(); /* start new frame */
            SLIP_send_frame_data_buf(&resp, sizeof(esp_command_response_t));
        }
        /* The last frame is ended outside of the "switch case" at the same place regular one-response frames are
         * ended. */
      }
      break;
    #if ESP32S2_OR_LATER
    case ESP_GET_SECURITY_INFO:
      error = verify_data_len(command, 0) || handle_get_security_info();
      break;
    #endif // ESP32S2_OR_LATER
    case ESP_ERASE_FLASH:
      error = verify_data_len(command, 0) || SPIEraseChip();
      break;
    case ESP_ERASE_REGION:
      /* Params for ERASE_REGION are addr, len */
      error = verify_data_len(command, 8) || handle_flash_erase(data_words[0], data_words[1]);
      break;
    case ESP_SET_BAUD:
      /* ESP_SET_BAUD sends two args, new and old baud rates */
      error = verify_data_len(command, 8);
      /* actual baud setting happens after we send the reply */
      break;
    case ESP_READ_FLASH:
      error = verify_data_len(command, 16);
      /* actual data is sent after we send the reply */
      break;
    case ESP_FLASH_VERIFY_MD5:
      /* unsure why the MD5 command has 4 params but we only pass 2 of them,
         but this is in ESP32 ROM so we can't mess with it.
      */
      error = verify_data_len(command, 16) || handle_flash_get_md5sum(data_words[0], data_words[1]);
      break;
    case ESP_FLASH_BEGIN:
      /* parameters (interpreted differently to ROM flasher):
         0 - erase_size (used as total size to write)
         1 - num_blocks (ignored)
         2 - block_size (should be MAX_WRITE_BLOCK, relies on num_blocks * block_size >= erase_size)
         3 - offset (used as-is)
       */
        if (command->data_len == 16 && data_words[2] > MAX_WRITE_BLOCK) {
            error = ESP_BAD_BLOCKSIZE;
        } else {
            error = verify_data_len(command, 16) || handle_flash_begin(data_words[0], data_words[3]);
        }
      break;
    case ESP_FLASH_DEFLATED_BEGIN:
      /* parameters:
         0 - uncompressed size
         1 - num_blocks (based on compressed size)
         2 - block_size (should be MAX_WRITE_BLOCK, total bytes over serial = num_blocks * block_size)
         3 - offset (used as-is)
      */
        if (command->data_len == 16 && data_words[2] > MAX_WRITE_BLOCK) {
            error = ESP_BAD_BLOCKSIZE;
        } else {
            error = verify_data_len(command, 16) || handle_flash_deflated_begin(data_words[0], data_words[1] * data_words[2], data_words[3]);
        }
        break;
    case ESP_FLASH_DATA:
    case ESP_FLASH_DEFLATED_DATA:
#if !ESP8266
    case ESP_FLASH_ENCRYPT_DATA:
#endif

      /* ACK DATA commands immediately, then process them a few lines down,
         allowing next command to buffer */
      if(is_in_flash_mode()) {
        error = get_flash_error();
        int payload_len = command->data_len - 16;
        if (data_words[0] != payload_len) {
          /* First byte of data payload header is length (repeated) as a word */
          error = ESP_BAD_DATA_LEN;
        }
        uint8_t data_checksum = calculate_checksum(command->data_buf + 16, payload_len);
        if (data_checksum != command->checksum) {
          error = ESP_BAD_DATA_CHECKSUM;
        }
      }
      else {
        error = ESP_NOT_IN_FLASH_MODE;
      }
      break;
    case ESP_FLASH_END:
    case ESP_FLASH_DEFLATED_END:
      error = handle_flash_end();
      break;
    case ESP_SPI_SET_PARAMS:
      /* data params: fl_id, total_size, block_size, sector_Size, page_size, status_mask */
      error = verify_data_len(command, 24) || handle_spi_set_params(data_words, &status);
      break;
    case ESP_SPI_ATTACH:
      /* parameter is 'hspi mode' (0, 1 or a pin mask for ESP32. Ignored on ESP8266.) */
      error = verify_data_len(command, 4) || handle_spi_attach(data_words[0]);
      break;
    case ESP_WRITE_REG:
      /* The write_reg command can pass multiple write operations in a sequence */
      if (command->data_len % sizeof(write_reg_args_t) != 0) {
          error = ESP_BAD_DATA_LEN;
      } else {
          error = handle_write_reg((const write_reg_args_t *)data_words, command->data_len/sizeof(write_reg_args_t));
      }
      break;
    case ESP_READ_REG:
      /* actual READ_REG operation happens higher up */
      error = verify_data_len(command, 4);
      break;
    case ESP_MEM_BEGIN:
        error = verify_data_len(command, 16) || handle_mem_begin(data_words[0], data_words[3]);
        break;
    case ESP_MEM_DATA:
        error = handle_mem_data(command->data_buf + 16, command->data_len - 16);
        break;
    case ESP_MEM_END:
        error = verify_data_len(command, 8) || handle_mem_finish();
        break;
    case ESP_RUN_USER_CODE:
        /* Returning from here will run user code, ie standard boot process

           This command does not send a response.
        */
        return;
    }

    SLIP_send_frame_data(error);
    SLIP_send_frame_data(status);
    SLIP_send_frame_delimiter();

    /* Some commands need to do things after after sending this response */
    if (error == ESP_OK) {
      switch(command->op) {
      case ESP_SET_BAUD:
        stub_io_set_baudrate(data_words[1], data_words[0]);
        break;
      case ESP_READ_FLASH:
        /* args are: offset, length, block_size, max_in_flight */
        handle_flash_read(data_words[0], data_words[1], data_words[2],
                          data_words[3]);
        break;
      case ESP_FLASH_DATA:
        /* drop into flashing mode, discard 16 byte payload header */
        handle_flash_data(command->data_buf + 16, command->data_len - 16);
        break;
#if !ESP8266
      case ESP_FLASH_ENCRYPT_DATA:
        /* write encrypted data */
        handle_flash_encrypt_data(command->data_buf + 16, command->data_len -16);
        break;
#endif
      case ESP_FLASH_DEFLATED_DATA:
        handle_flash_deflated_data(command->data_buf + 16, command->data_len - 16);
        break;
      case ESP_FLASH_DEFLATED_END:
      case ESP_FLASH_END:
        /* passing 0 as parameter for ESP_FLASH_END means reboot now */
        if (data_words[0] == 0) {
          /* Flush the FLASH_END response before rebooting */
          stub_tx_flush();
          ets_delay_us(10000);
          #if USE_MAX_CPU_FREQ
            reset_cpu_freq();
          #endif // USE_MAX_CPU_FREQ
          software_reset();
        }
        break;
      case ESP_MEM_END:
          if (data_words[1] != 0) {
              void (*entrypoint_fn)(void) = (void (*))data_words[1];
              /* Make sure the command response has been flushed out
                 of the UART before we run the new code */
              stub_tx_flush();
              ets_delay_us(1000);
              /* this is a little different from the ROM loader,
                 which exits the loader routine and _then_ calls this
                 function. But for our purposes so far, having a bit of
                 extra stuff on the stack doesn't really matter.
              */
              #if USE_MAX_CPU_FREQ
                reset_cpu_freq();
              #endif // USE_MAX_CPU_FREQ
              entrypoint_fn();
          }
          break;
      }
    }
  }
}


extern uint32_t _bss_start;
extern uint32_t _bss_end;

void __attribute__((used)) stub_main();


#ifdef ESP8266
__asm__ (
  ".global stub_main_8266\n"
  ".literal_position\n"
  ".align 4\n"
  "stub_main_8266:\n"
/* ESP8266 wrapper for "stub_main()" manipulates the return address in
 * a0, so 'return' from here runs user code.
 *
 * After setting a0, we jump directly to stub_main_inner() which is a
 * normal C function
 *
 * Adapted from similar approach used by Cesanta Software for ESP8266
 * flasher stub.
 *
 */
  "movi a0, 0x400010a8;"
  "j stub_main;");
#endif

/* This function is called from stub_main, with return address
   reset to point to user code. */
void stub_main()
{
  const uint32_t greeting = 0x4941484f; /* OHAI */

  /* this points to stub_main now, clear for next boot */
  ets_set_user_start(0);

  #if USE_MAX_CPU_FREQ
    set_max_cpu_freq();
  #endif // USE_MAX_CPU_FREQ

  /* zero bss */
  for(uint32_t *p = &_bss_start; p < &_bss_end; p++) {
    *p = 0;
  }

  SLIP_send(&greeting, 4);

  ub.reading_buf = ub.buf_a;
  stub_io_init(&stub_handle_rx_byte);

  /* Configure default SPI flash functionality.
     Can be overriden later by esptool.py. */
#ifdef ESP8266
        SelectSpiFunction();

        spi_flash_attach();
#else
#if !ESP32C2 && !ESP32C6
        uint32_t spiconfig = ets_efuse_get_spiconfig();
#else
        // ESP32C2/ESP32C6 doesn't support get spiconfig.
        uint32_t spiconfig = 0;
#endif
        uint32_t strapping = READ_REG(GPIO_STRAP_REG);
        /* If GPIO1 (U0TXD) is pulled low and no other boot mode is
           set in efuse, assume HSPI flash mode (same as normal boot)
        */
        if (spiconfig == 0 && (strapping & 0x1c) == 0x08) {
            spiconfig = 1; /* HSPI flash mode */
        }
        spi_flash_attach(spiconfig, 0);
#endif
        SPIParamCfg(0, FLASH_MAX_SIZE, FLASH_BLOCK_SIZE, FLASH_SECTOR_SIZE,
                    FLASH_PAGE_SIZE, FLASH_STATUS_MASK);

  cmd_loop();

  /* if cmd_loop returns, it's due to ESP_RUN_USER_CODE command. */

  #if USE_MAX_CPU_FREQ
    reset_cpu_freq();
  #endif // USE_MAX_CPU_FREQ

  return;
}
