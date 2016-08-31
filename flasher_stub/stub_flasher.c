/*
 * Copyright (c) 2016 Cesanta Software Limited
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

#include "eagle_soc.h"
#include "ets_sys.h"
#include "examples/driver_lib/include/driver/uart_register.h"

#include "slip.h"

/* TODO(rojer): read sector and block sizes from device ROM. */
#define FLASH_SECTOR_SIZE 4096
#define FLASH_BLOCK_SIZE 65536
#define UART_CLKDIV_26MHZ(B) (52000000 + B / 2) / B

#define UART_BUF_SIZE 6144
#define SPI_WRITE_SIZE 1024

#define UART_RX_INTS (UART_RXFIFO_FULL_INT_ENA | UART_RXFIFO_TOUT_INT_ENA)

/* From spi_register.h */
#define REG_SPI_BASE(i) (0x60000200 - i * 0x100)

#define SPI_CMD(i) (REG_SPI_BASE(i) + 0x0)
#define SPI_RDID (BIT(28))

#define SPI_W0(i) (REG_SPI_BASE(i) + 0x40)

#define MAX_WRITE_BLOCK 8192

int handle_flash_erase(uint32_t addr, uint32_t len) {
  if (addr % FLASH_SECTOR_SIZE != 0) return 0x32;
  if (len % FLASH_SECTOR_SIZE != 0) return 0x33;
  if (SPIUnlock() != 0) return 0x34;

  while (len > 0 && (addr % FLASH_BLOCK_SIZE != 0)) {
    if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  while (len > FLASH_BLOCK_SIZE) {
    if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
    len -= FLASH_BLOCK_SIZE;
    addr += FLASH_BLOCK_SIZE;
  }

  while (len > 0) {
    if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  return 0;
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

typedef struct {
  bool in_flash_mode;
  uint32_t next_write;
  uint32_t remaining;
  esp_command_error last_error;
} flashing_state_t;
flashing_state_t flashing_state;

esp_command_error handle_flash_begin(uint32_t erase_size, uint32_t num_blocks, uint32_t block_size, uint32_t offset) {
  if (block_size > MAX_WRITE_BLOCK)
	return ESP_BAD_BLOCKSIZE;

  flashing_state.in_flash_mode = true;
  flashing_state.next_write = offset;
  flashing_state.remaining = num_blocks * block_size;
  flashing_state.last_error = ESP_OK;

  if (SPIUnlock() != 0) {
	return ESP_FAILED_SPI_UNLOCK;
  }

  return ESP_OK;
}

void handle_flash_data(void *data_buf, uint32_t length) {
  /* This code for finding what we need to erase is very lazy,
	 can be made less lazy and a bit faster! */
  for(uint32_t o = flashing_state.next_write; o < flashing_state.next_write + length; o++) {
	if (o % FLASH_SECTOR_SIZE == 0) {
	  if (SPIEraseSector(o / FLASH_SECTOR_SIZE)) {
		flashing_state.last_error = ESP_FAILED_SPI_OP;
	  }
	}
  }

  if (SPIWrite(flashing_state.next_write, data_buf, length)) {
	flashing_state.last_error = ESP_FAILED_SPI_OP;
  }
  flashing_state.next_write += length;
}

esp_command_error handle_flash_end(void)
{
  if(!flashing_state.in_flash_mode) {
	return ESP_NOT_IN_FLASH_MODE;
  }

  /* TODO: check bytes written, etc. */

  flashing_state.in_flash_mode = false;
  return flashing_state.last_error;
}

void handle_flash_read(uint32_t addr, uint32_t len, uint32_t block_size,
                  uint32_t max_in_flight) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  uint32_t num_sent = 0, num_acked = 0;

  /* This is one routine where we still do synchronous I/O */
  ets_isr_mask(1 << ETS_UART_INUM);

  if (block_size > sizeof(buf)) {
	return;
  }
  MD5Init(&ctx);
  while (num_acked < len && num_acked <= num_sent) {
    while (num_sent < len && num_sent - num_acked < max_in_flight) {
      uint32_t n = len - num_sent;
      if (n > block_size) n = block_size;
      if (SPIRead(addr, buf, n) != 0) {
		break;
	  }
      send_packet(buf, n);
      MD5Update(&ctx, buf, n);
      addr += n;
      num_sent += n;
    }
	int r = SLIP_recv(&num_acked, sizeof(num_acked));
	if (r != 4) {
	  break;
	}
  }
  MD5Final(digest, &ctx);
  send_packet(digest, sizeof(digest));

  /* Go back to async UART */
  ets_isr_unmask(1 << ETS_UART_INUM);
}

int handle_flash_get_md5sum(uint32_t addr, uint32_t len) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  MD5Init(&ctx);
  while (len > 0) {
    uint32_t n = len;
    if (n > FLASH_SECTOR_SIZE) n = FLASH_SECTOR_SIZE;
    if (SPIRead(addr, buf, n) != 0) return 0x63;
    MD5Update(&ctx, buf, n);
    addr += n;
    len -= n;
  }
  MD5Final(digest, &ctx);
  /* ESP32 ROM sends as hex, but we just send a raw bytes - esptool.py can handle either. */
  SLIP_send_frame_data_buf(digest, sizeof(digest));
  return 0;
}

int handle_flash_read_chip_id() {
  uint32_t chip_id = 0;
  WRITE_PERI_REG(SPI_CMD(0), SPI_RDID);
  while (READ_PERI_REG(SPI_CMD(0)) & SPI_RDID) {
  }
  chip_id = READ_PERI_REG(SPI_W0(0)) & 0xFFFFFF;
  SLIP_send_frame_data_buf(&chip_id, sizeof(chip_id));
  return 0;
}

static esp_command_error verify_data_len(esp_command_req_t *command, uint8_t len)
{
  return (command->data_len == len) ? ESP_OK : ESP_BAD_DATA_LEN;
}

uint8_t cmd_loop() {
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
	  .len_ret = 0, /* esptool.py ignores this value */
	  .value = 0,
	};
	/* Send the command response. */
	SLIP_send_frame_delimiter();
	SLIP_send_frame_data_buf(&resp, sizeof(esp_command_response_t));

	if(command->data_len > MAX_WRITE_BLOCK+16) {
	  SLIP_send_frame_data(ESP_BAD_DATA_LEN);
	  SLIP_send_frame_data(0xEE);
	  SLIP_send_frame_delimiter();
	  continue;
	}

	/* ... some commands will insert in-frame response data
	   between here and when we send the end of the frame */

	esp_command_error error = ESP_CMD_NOT_IMPLEMENTED;

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
	  /* ESP_SET_BAUD sends two args, we ignore the second one */
	  error = verify_data_len(command, 8);
	  /* actual baud setting happens after we send the reply */
	  break;
	case ESP_READ_FLASH:
	  error = verify_data_len(command, 16);
	  /* actual data is sent after we send the reply */
	  break;
	case ESP_GET_FLASH_ID:
	  error = verify_data_len(command, 0) || handle_flash_read_chip_id();
	  break;
	case ESP_FLASH_VERIFY_MD5:
	  /* unsure why the MD5 command has 4 params but we only pass 2 of them,
		 but this is in ESP32 ROM so we can't mess with it.
	  */
	  error = verify_data_len(command, 16) || handle_flash_get_md5sum(data_words[0], data_words[1]);
	  break;
	case ESP_FLASH_BEGIN:
	  error = verify_data_len(command, 16) || handle_flash_begin(data_words[0], data_words[1], data_words[2], data_words[3]);
	  break;
	case ESP_FLASH_DATA:
	  /* ACK all write data immediately, then process it a few lines down,
		 allowing next command to buffer */
	  if(flashing_state.in_flash_mode) {
		error = ESP_OK;
		if (data_words[0] != command->data_len - 16) {
		  /* First byte of data payload header is length (repeated) as a word */
		  error = ESP_BAD_DATA_LEN;
		}
	  }
	  else {
		error = ESP_NOT_IN_FLASH_MODE;
	  }
	  break;
	case ESP_FLASH_END:
	  error = handle_flash_end();
	  break;
	}

	SLIP_send_frame_data(error);
	SLIP_send_frame_data(0);
	SLIP_send_frame_delimiter();

	/* Some commands need to do things after after sending this response */
	if (error == ESP_OK) {
	  switch(command->op) {
	  case ESP_SET_BAUD:
		ets_delay_us(10000);
		uart_div_modify(0, UART_CLKDIV_26MHZ(data_words[0]));
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
	  }
	}
  }
  return 0;
}


extern uint32_t _bss_start;
extern uint32_t _bss_end;

void stub_main() {
  uint32_t greeting = 0x4941484f; /* OHAI */
  uint32_t last_cmd;

  /* zero bss */
  for(uint32_t *p = &_bss_start; p <= &_bss_end; p++) {
	*p = 0;
  }

  SLIP_send(&greeting, 4);

  /* All UART reads come via uart_isr */
  ub.reading_buf = ub.buf_a;
  ets_isr_attach(ETS_UART_INUM, uart_isr, NULL);
  SET_PERI_REG_MASK(UART_INT_ENA(0), UART_RX_INTS);
  ets_isr_unmask(1 << ETS_UART_INUM);

  /* This points at us right now, reset for next boot. */
  ets_set_user_start(NULL);

  /* Selects SPI functions for flash pins. */
  SelectSpiFunction();

  last_cmd = cmd_loop();

  ets_delay_us(10000);

  if (last_cmd == -1/*CMD_BOOT_FW*/) {
    /*
     * Find the return address in our own stack and change it.
     * "flash_finish" it gets to the same point, except it doesn't need to
     * patch up its RA: it returns from UartDwnLdProc, then from f_400011ac,
     * then jumps to 0x4000108a, then checks strapping bits again (which will
     * not have changed), and then proceeds to 0x400010a8.
     */
    volatile uint32_t *sp = &last_cmd;
    while (*sp != (uint32_t) 0x40001100) sp++;
    *sp = 0x400010a8;
    /*
     * The following dummy asm fragment acts as a barrier, to make sure function
     * epilogue, including return address loading, is added after our stack
     * patching.
     */
    __asm volatile("nop.n");
    return; /* To 0x400010a8 */
  } else {
    _ResetVector();
  }
  /* Not reached */
}
