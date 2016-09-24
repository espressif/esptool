/*
 * Copyright (c) 2016 Cesanta Software Limited & Angus Gratton
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

#include <esp/interrupts.h>
#include <esp/uart.h>
#include <esp/spi_regs.h>

#ifdef ESP31
/* ESP31 has no (known) set of MD5 functions in ROM */
#include <md5.h>
#endif

#include "slip.h"

/* Params sent by esptool.py */
volatile struct {
  uint32_t desired_baudrate; /* if non-zero, change to this baud rate when running */
} params __attribute__((section(".params")));

/* Params sent back to esptool.py on startup */
struct startup_params {
  uint32_t max_writeahead;
  uint32_t write_block_len;
};

/* TODO(rojer): read sector and block sizes from device ROM. */
#define FLASH_SECTOR_SIZE 4096
#define FLASH_BLOCK_SIZE 65536

#define UART_BUF_SIZE 6144
#define SPI_WRITE_SIZE 1024

#ifdef ESP8266
#define MAX_WRITEAHEAD (UART_BUF_SIZE - SPI_WRITE_SIZE)
#else
/* ESP31 only supports synchronous writes for now */
#define MAX_WRITEAHEAD SPI_WRITE_SIZE
#endif

#define SPI_RDID (BIT(28)) /* SPI read ID command */

#define UART_RX_INTS (UART_INT_ENABLE_RXFIFO_FULL | UART_INT_ENABLE_RXFIFO_TIMEOUT)

/* This function needs modifying before it works on ESP31 */
static inline uint32_t read_flash_chip_id() {
  SPI(0).CMD = SPI_RDID;
  while (SPI(0).CMD & SPI_RDID) {
  }
  return SPI(0).W0 & 0xFFFFFF;
}

int do_flash_erase(uint32_t addr, uint32_t len) {
  if (addr % FLASH_SECTOR_SIZE != 0) return 0x32;
  if (len % FLASH_SECTOR_SIZE != 0) return 0x33;
  if (SPIUnlock() != 0) return 0x34;

  while (len > 0 && (addr % FLASH_BLOCK_SIZE != 0)) {
    if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

#ifdef ESP8266 /* Only ESP8266 has SPIEraseBlock */
  while (len > FLASH_BLOCK_SIZE) {
    if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
    len -= FLASH_BLOCK_SIZE;
    addr += FLASH_BLOCK_SIZE;
  }
#endif

  while (len > 0) {
    if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  return 0;
}

struct uart_buf {
  uint8_t data[UART_BUF_SIZE];
  uint32_t nr;
  uint8_t *pr, *pw;
};

#ifdef ESP8266
/* Asynchronous UART reader routine for ESP8266 */

void uart_isr(void *arg) {
  uint32_t int_st = UART(0).INT_STATUS;
  struct uart_buf *ub = (struct uart_buf *) arg;
  while (1) {
    uint32_t fifo_len = FIELD2VAL(UART_STATUS_RXFIFO_COUNT, UART(0).STATUS);
    if (fifo_len == 0) break;
    while (fifo_len-- > 0) {
      uint8_t byte = UART(0).FIFO & 0xff;
      *ub->pw++ = byte;
      ub->nr++;
      if (ub->pw >= ub->data + UART_BUF_SIZE) ub->pw = ub->data;
    }
  }
  UART(0).INT_CLEAR = int_st;
}

static void uart_reader_init(volatile struct uart_buf *ub)
{
  ets_isr_attach(INUM_UART, uart_isr, (void *)ub);
  UART(0).INT_ENABLE = UART_RX_INTS;
  /* note: on ESP8266 we have to use ets_isr_unmask/mask not
	 _xt_isr_mask as the ROM functions set flags in RAM for
	 the user exception handler to pick up on.
  */
  ets_isr_unmask(BIT(INUM_UART));
}

static void uart_reader_fill_buffer_before_erase(volatile struct uart_buf *ub)
{
}

static void uart_reader_fill_buffer_after_erase(volatile struct uart_buf *ub)
{
  /* Happens in the ISR, so we just wait for enough data to have arrived. */
  while (ub->nr < SPI_WRITE_SIZE) { }
}

static void uart_reader_deinit(void)
{
  ets_isr_mask(BIT(INUM_UART));
}

#elif defined(ESP31) /* End of ESP8266 async uart_reader_xxx routines */

/* ESP31 cureently doesn't have documented interrupt routines,
   so do slower synchronus read/write */

static void uart_reader_init(struct uart_buf *ub)
{

}

static void uart_reader_fill_buffer_before_erase(struct uart_buf *ub)
{
  /* We have to read SPI_WRITE_SIZE bytes before erasing, or we'll drop bytes. */
  while (ub->nr < SPI_WRITE_SIZE) {
	*ub->pw++ = uart_getc(0);
	ub->nr++;
	if (ub->pw >= ub->data + UART_BUF_SIZE) ub->pw = ub->data;
  }
}

static void uart_reader_fill_buffer_after_erase(struct uart_buf *ub)
{
}

static void uart_reader_deinit(void)
{
}

#else
#error "Unknown Espressif chip type?"
#endif

int do_flash_write(uint32_t addr, uint32_t len, uint32_t erase) {
  struct uart_buf ub;
  uint8_t digest[16];
  uint32_t num_written = 0, num_erased = 0;
  struct MD5Context ctx;
  MD5Init(&ctx);

  if (addr % FLASH_SECTOR_SIZE != 0) return 0x32;
  if (len % FLASH_SECTOR_SIZE != 0) return 0x33;
  if (SPIUnlock() != 0) return 0x34;

  ub.nr = 0;
  ub.pr = ub.pw = ub.data;

  uart_reader_init(&ub);

  SLIP_send(&num_written, 4);

  while (num_written < len) {
	uart_reader_fill_buffer_before_erase(&ub);

    /* Prepare the space ahead. */
#ifdef ESP8266
    if (erase && num_erased < num_written + SPI_WRITE_SIZE
		   && (len - num_erased) > FLASH_BLOCK_SIZE
		   && (addr % FLASH_BLOCK_SIZE) == 0) {
	  if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x35;
	  num_erased += FLASH_BLOCK_SIZE;
	} else
#endif
    if (erase && num_erased < num_written + SPI_WRITE_SIZE) {
	  /* len % FLASH_SECTOR_SIZE == 0 is enforced, no further checks needed */
	  if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x36;
	  num_erased += FLASH_SECTOR_SIZE;
	}

	uart_reader_fill_buffer_after_erase(&ub);

	if (SPIWrite(addr, ub.pr, SPI_WRITE_SIZE) != 0) return 0x37;
	uint32_t int_level = _xt_disable_interrupts();
	ub.nr -= SPI_WRITE_SIZE;
	_xt_restore_interrupts(int_level);

	MD5Update(&ctx, ub.pr, SPI_WRITE_SIZE);

	num_written += SPI_WRITE_SIZE;
    addr += SPI_WRITE_SIZE;
    ub.pr += SPI_WRITE_SIZE;
    if (ub.pr >= ub.data + UART_BUF_SIZE) ub.pr = ub.data;
    SLIP_send(&num_written, 4);
  }

  uart_reader_deinit();

  MD5Final(digest, &ctx);
  SLIP_send(digest, 16);

  return 0;
}

int do_flash_read(uint32_t addr, uint32_t len, uint32_t block_size,
                  uint32_t max_in_flight) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  uint32_t num_sent = 0, num_acked = 0;
  if (block_size > sizeof(buf)) return 0x52;
  MD5Init(&ctx);
  while (num_acked < len) {
    while (num_sent < len && num_sent - num_acked < max_in_flight) {
      uint32_t n = len - num_sent;
      if (n > block_size) n = block_size;
      if (SPIRead(addr, buf, n) != 0) return 0x53;
      SLIP_send(buf, n);
      MD5Update(&ctx, buf, n);
      addr += n;
      num_sent += n;
    }
    {
      if (SLIP_recv(&num_acked, sizeof(num_acked)) != 4) return 0x54;
      if (num_acked > num_sent) return 0x55;
    }
  }
  MD5Final(digest, &ctx);
  SLIP_send(digest, sizeof(digest));
  return 0;
}

int do_flash_digest(uint32_t addr, uint32_t len, uint32_t digest_block_size) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  uint32_t read_block_size =
      digest_block_size ? digest_block_size : sizeof(buf);
  struct MD5Context ctx;
  if (digest_block_size > sizeof(buf)) return 0x62;
  MD5Init(&ctx);
  while (len > 0) {
    uint32_t n = len;
    struct MD5Context block_ctx;
    MD5Init(&block_ctx);
    if (n > read_block_size) n = read_block_size;
    if (SPIRead(addr, buf, n) != 0) return 0x63;
    MD5Update(&ctx, buf, n);
    if (digest_block_size > 0) {
      MD5Update(&block_ctx, buf, n);
      MD5Final(digest, &block_ctx);
      SLIP_send(digest, sizeof(digest));
    }
    addr += n;
    len -= n;
  }
  MD5Final(digest, &ctx);
  SLIP_send(digest, sizeof(digest));
  return 0;
}

int do_flash_read_chip_id() {
  uint32_t chip_id = read_flash_chip_id();
  SLIP_send(&chip_id, sizeof(chip_id));
  return 0;
}

uint8_t cmd_loop() {
  uint8_t cmd;
  do {
    uint32_t args[4];
    uint32_t len = SLIP_recv(&cmd, 1);
    if (len != 1) {
      continue;
    }
    uint8_t resp = 0xff;
    switch (cmd) {
      case CMD_FLASH_ERASE: {
        len = SLIP_recv(args, sizeof(args));
        if (len == 8) {
          resp = do_flash_erase(args[0] /* addr */, args[1] /* len */);
        } else {
          resp = 0x31;
        }
        break;
      }
      case CMD_FLASH_WRITE: {
        len = SLIP_recv(args, sizeof(args));
        if (len == 12) {
          resp = do_flash_write(args[0] /* addr */, args[1] /* len */,
                                args[2] /* erase */);
        } else {
          resp = 0x41;
        }
        break;
      }
      case CMD_FLASH_READ: {
        len = SLIP_recv(args, sizeof(args));
        if (len == 16) {
          resp = do_flash_read(args[0] /* addr */, args[1], /* len */
                               args[2] /* block_size */,
                               args[3] /* max_in_flight */);
        } else {
          resp = 0x51;
        }
        break;
      }
      case CMD_FLASH_DIGEST: {
        len = SLIP_recv(args, sizeof(args));
        if (len == 12) {
          resp = do_flash_digest(args[0] /* addr */, args[1], /* len */
                                 args[2] /* digest_block_size */);
        } else {
          resp = 0x61;
        }
        break;
      }
      case CMD_FLASH_READ_CHIP_ID: {
        resp = do_flash_read_chip_id();
        break;
      }
      case CMD_FLASH_ERASE_CHIP: {
#ifdef ESP8266
        resp = SPIEraseChip();
#else
		resp = 1; /* TODO: ESP31 erase chip function! */
#endif
        break;
      }
      case CMD_BOOT_FW:
      case CMD_REBOOT: {
        resp = 0;
        SLIP_send(&resp, 1);
        return cmd;
      }
    }
    SLIP_send(&resp, 1);
  } while (cmd != CMD_BOOT_FW && cmd != CMD_REBOOT);
  return cmd;
}

void stub_main() {
  const uint32_t greeting = 0x4941484f; /* OHAI */
  uint8_t last_cmd;

#ifdef ESP8266
  /* This points at us right now, reset for next boot. */
  ets_set_user_start(0);
#endif

#ifdef ESP8266
  /* Selects SPI functions for flash pins. */
  SelectSpiFunction();
#endif

  /* Give host time to get ready too
	 (also allows any pending UART TX to flush before
	 we change baud rates.)*/
  ets_delay_us(10000);

  if (params.desired_baudrate > 0) {
	uart_set_baud(0, params.desired_baudrate);
  }

  SLIP_send(&greeting, sizeof(greeting));

  const struct startup_params startup_params = {
	.write_block_len = SPI_WRITE_SIZE,
	.max_writeahead = MAX_WRITEAHEAD,
  };
  SLIP_send(&startup_params, sizeof(struct startup_params));

  last_cmd = cmd_loop();

  ets_delay_us(10000);

  if (last_cmd == CMD_BOOT_FW) {
    /*
     * Find the return address in our own stack and change it.
     * "flash_finish" it gets to the same point, except it doesn't need to
     * patch up its RA: it returns from UartDwnLdProc, then from f_400011ac,
     * then jumps to 0x4000108a, then checks strapping bits again (which will
     * not have changed), and then proceeds to 0x400010a8.
     */
    volatile uint32_t *sp;
    __asm volatile("mov %0, a1" : "=r" (sp));
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
#ifdef ESP8266
    _ResetVector();
#else
	/* ESP31 TODO */
#endif
  }
  /* Not reached */
}
