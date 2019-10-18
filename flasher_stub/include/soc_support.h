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

/* SoC-level support for ESP8266/ESP32.
 *
 * Provide a unified register-level interface.
 *
 * This is the same information provided in the register headers
 * of ESP8266 Non-OS SDK and ESP-IDF soc component, however
 * only values that are needed for the flasher stub are included here.
 *
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define READ_REG(REG) (*((volatile uint32_t *)(REG)))
#define WRITE_REG(REG, VAL) *((volatile uint32_t *)(REG)) = (VAL)
#define REG_SET_MASK(reg, mask) WRITE_REG((reg), (READ_REG(reg)|(mask)))


/**********************************************************
 * Per-SOC based peripheral register base addresses
 */
#ifdef ESP8266
#define UART_BASE_REG      0x60000000 /* UART0 */
#define SPI_BASE_REG       0x60000200 /* SPI peripheral 0 */
#endif

#ifdef ESP32
#define UART_BASE_REG      0x3ff40000 /* UART0 */
#define SPI_BASE_REG       0x3ff42000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG      0x3ff43000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG      0x3ff44000
#endif


/**********************************************************
 * UART peripheral
 *
 * The features we use are the same on both ESP8266 and ESP32
 *
 * Only UART0 is used
 */
#define UART_CLKDIV_REG(X) (UART_BASE_REG + 0x14)
#define UART_CLKDIV_M      (0x000FFFFF)

#ifdef ESP32
#define UART_CLKDIV_FRAG_S 20
#define UART_CLKDIV_FRAG_V 0xF
#endif

#define UART_FIFO(X)       (UART_BASE_REG + 0x00)
#define UART_INT_ST(X)     (UART_BASE_REG + 0x08) // TODO RENAME
#define UART_INT_ENA(X)    (UART_BASE_REG + 0x0C)
#define UART_INT_CLR(X)    (UART_BASE_REG + 0x10)
#define UART_STATUS(X)     (UART_BASE_REG + 0x1C)

#define UART_RXFIFO_FULL_INT_ENA            (1<<0)
#define UART_RXFIFO_TOUT_INT_ENA            (1<<8)

#define ETS_UART0_INUM 5


/**********************************************************
 * SPI peripheral
 *
 * The features we use are mostly the same on both ESP8266 and ESP32,
 * except for W0 base address & option for 2-byte status command
 *
 * Only one SPI peripheral is used (0 on ESP8266, 1 on ESP32)
 */
#define SPI_CMD_REG       (SPI_BASE_REG + 0x00)
#define SPI_FLASH_RDSR    (1<<27)
#define SPI_FLASH_SE      (1<<24)
#define SPI_FLASH_BE      (1<<23)
#define SPI_FLASH_WREN    (1<<30)

#define SPI_ADDR_REG      (SPI_BASE_REG + 0x04)

#define SPI_CTRL_REG      (SPI_BASE_REG + 0x08)
#ifdef ESP32
#define SPI_WRSR_2B       (1<<22)
#endif

#define SPI_RD_STATUS_REG (SPI_BASE_REG + 0x10)

#ifdef ESP8266
#define SPI_W0_REG        (SPI_BASE_REG + 0x40)
#endif
#ifdef ESP32
#define SPI_W0_REG        (SPI_BASE_REG + 0x80)
#endif

#define SPI_EXT2_REG      (SPI_BASE_REG + 0xF8)
#define SPI_ST 0x7

#ifdef ESP32
/* On ESP32 the SPI peripherals are layered
 * flash, this lets us check the state of the internal
 * state machine under the SPI flash controller
 */
#define SPI0_EXT2_REG     (SPI0_BASE_REG + 0xF8)
#endif


/**********************************************************
 * GPIO peripheral
 *
 * We only need to read the strapping register on ESP32
 */
#define GPIO_STRAP_REG    (GPIO_BASE_REG + 0x38)
