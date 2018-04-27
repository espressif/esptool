/*
 * Copyright (c) 2016 Cesanta Software Limited & Espressif Systems (Shanghai) PTE LTD
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

/*
 * Spiffy flasher. Implements strong checksums (MD5) and can use higher
 * baud rates. Actual max baud rate will differ from device to device,
 * but 921K seems to be common.
 *
 * SLIP protocol is used for communication.
 * First packet is a single byte - command number.
 * After that, a packet with a variable number of 32-bit (LE) arguments,
 * depending on command.
 *
 * Then command produces variable number of packets of output, but first
 * packet of length 1 is the response code: 0 for success, non-zero - error.
 *
 * See individual command description below.
 */

#include "stub_flasher.h"
#include "rom_functions.h"
#include "slip.h"
#include "stub_commands.h"
#include "stub_write_flash.h"
#include "soc_support.h"

#define UART_RX_INTS (UART_RXFIFO_FULL_INT_ENA | UART_RXFIFO_TOUT_INT_ENA)


#ifdef ESP32
/* ESP32 register naming is a bit more consistent */
#define UART_INT_CLR(X) UART_INT_CLR_REG(X)
#define UART_INT_ST(X) UART_INT_ST_REG(X)
#define UART_INT_ENA(X) UART_INT_ENA_REG(X)
#define UART_STATUS(X) UART_STATUS_REG(X)
#define UART_FIFO(X) UART_FIFO_REG(X)
#endif

static uint32_t get_new_uart_divider(uint32_t current_baud, uint32_t new_baud)
{
  uint32_t master_freq;
  /* ESP32 has ROM code to detect the crystal freq but ESP8266 does not have this...
     So instead we use the previously auto-synced 115200 baud rate (which we know
     is correct wrt the relative crystal accuracy of the ESP & the USB/serial adapter).
     From this we can estimate crystal freq, and update for a new baud rate relative to that.
  */
  uint32_t uart_reg = REG_READ(UART_CLKDIV_REG(0));
  uint32_t uart_div = uart_reg & UART_CLKDIV_M;
#ifdef ESP32
  // account for fractional part of divider (bottom 4 bits)
  uint32_t fraction = (uart_reg >> UART_CLKDIV_FRAG_S) & UART_CLKDIV_FRAG_V;
  uart_div = (uart_div << 4) + fraction;
#endif
  master_freq = uart_div * current_baud;
  return master_freq / new_baud;

}

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

static void uart_isr_receive(char byte)
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

void uart_isr(void *arg) {
  uint32_t int_st = READ_PERI_REG(UART_INT_ST(0));
  while (1) {
    uint32_t fifo_len = READ_PERI_REG(UART_STATUS(0)) & 0xff;
    if (fifo_len == 0) {
      break;
    }
    while (fifo_len-- > 0) {
      uint8_t byte = READ_PERI_REG(UART_FIFO(0)) & 0xff;
      uart_isr_receive(byte);
    }
  }
  WRITE_PERI_REG(UART_INT_CLR(0), int_st);
}

static esp_command_error verify_data_len(esp_command_req_t *command, uint8_t len)
{
  return (command->data_len == len) ? ESP_OK : ESP_BAD_DATA_LEN;
}

void cmd_loop() {
  while(1) {
    /* Wait for a command */
    while(ub.command == NULL) { }
    esp_command_req_t *command = ub.command;
    ub.command = NULL;
    /* provide easy access for 32-bit data words */
    uint32_t *data_words = (uint32_t *)command->data_buf;

    /* Send command response header */
    esp_command_response_t resp = {
      .resp = 1,
      .op_ret = command->op,
      .len_ret = 2, /* esptool.py ignores this value, but other users of the stub may not */
      .value = 0,
    };

    /* Some commands need to set resp.len_ret or resp.value before it is sent back */
    switch(command->op) {
    case ESP_READ_REG:
        if (command->data_len == 4) {
            resp.value = REG_READ(data_words[0]);
        }
        break;
    case ESP_FLASH_VERIFY_MD5:
        resp.len_ret = 16 + 2; /* Will sent 16 bytes of data with MD5 value */
        break;
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

    /* ... ESP_FLASH_VERIFY_MD5 will insert in-frame response data
       between here and when we send the status bytes at the
       end of the frame */

    esp_command_error error = ESP_CMD_NOT_IMPLEMENTED;
    int status = 0;

    /* First stage of command processing - before sending error/status */
    switch (command->op) {
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
        if (command->data_len == 16 && data_words[2] != MAX_WRITE_BLOCK) {
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
        if (command->data_len == 16 && data_words[2] != MAX_WRITE_BLOCK) {
            error = ESP_BAD_BLOCKSIZE;
        } else {
            error = verify_data_len(command, 16) || handle_flash_deflated_begin(data_words[0], data_words[1] * data_words[2], data_words[3]);            }
        break;
    case ESP_FLASH_DATA:
    case ESP_FLASH_DEFLATED_DATA:
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
      /* params are addr, value, mask (ignored), delay_us (ignored) */
      error = verify_data_len(command, 16);
      if (error == ESP_OK) {
        REG_WRITE(data_words[0], data_words[1]);
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
        ets_delay_us(10000);
        uart_div_modify(0, get_new_uart_divider(data_words[1], data_words[0]));
        ets_delay_us(1000);
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
      case ESP_FLASH_DEFLATED_DATA:
        handle_flash_deflated_data(command->data_buf + 16, command->data_len - 16);
        break;
      case ESP_FLASH_DEFLATED_END:
      case ESP_FLASH_END:
        /* passing 0 as parameter for ESP_FLASH_END means reboot now */
        if (data_words[0] == 0) {
          /* Flush the FLASH_END response before rebooting */
#ifdef ESP32
          uart_tx_flush(0);
#endif
          ets_delay_us(10000);
          software_reset();
        }
        break;
      case ESP_MEM_END:
          if (data_words[1] != 0) {
              void (*entrypoint_fn)(void) = (void (*))data_words[1];
              /* Make sure the command response has been flushed out
                 of the UART before we run the new code */
#ifdef ESP32
              uart_tx_flush(0);
#endif
              ets_delay_us(1000);
              /* this is a little different from the ROM loader,
                 which exits the loader routine and _then_ calls this
                 function. But for our purposes so far, having a bit of
                 extra stuff on the stack doesn't really matter.
              */
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

  /* zero bss */
  for(uint32_t *p = &_bss_start; p < &_bss_end; p++) {
    *p = 0;
  }

  SLIP_send(&greeting, 4);

  /* All UART reads come via uart_isr */
  ub.reading_buf = ub.buf_a;
  ets_isr_attach(ETS_UART0_INUM, uart_isr, NULL);
  SET_PERI_REG_MASK(UART_INT_ENA(0), UART_RX_INTS);
  ets_isr_unmask(1 << ETS_UART0_INUM);

  /* Configure default SPI flash functionality.
     Can be overriden later by esptool.py. */
#ifdef ESP8266
        SelectSpiFunction();
#else
        uint32_t spiconfig = ets_efuse_get_spiconfig();
        uint32_t strapping = REG_READ(GPIO_STRAP_REG);
        /* If GPIO1 (U0TXD) is pulled low and no other boot mode is
           set in efuse, assume HSPI flash mode (same as normal boot)
        */
        if (spiconfig == 0 && (strapping & 0x1c) == 0x08) {
            spiconfig = 1; /* HSPI flash mode */
        }
        spi_flash_attach(spiconfig, 0);
#endif
        SPIParamCfg(0, 16*1024*1024, FLASH_BLOCK_SIZE, FLASH_SECTOR_SIZE,
                    FLASH_PAGE_SIZE, FLASH_STATUS_MASK);

  cmd_loop();

  /* if cmd_loop returns, it's due to ESP_RUN_USER_CODE command. */

  return;
}
