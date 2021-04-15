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
#define REG_CLR_MASK(reg, mask) WRITE_REG((reg), (READ_REG(reg)&(~(mask))))

#define ESP32_OR_LATER (ESP32 || ESP32S2 || ESP32S3 || ESP32C3 || ESP32C6)
#define ESP32S2_OR_LATER (ESP32S2 || ESP32S3 || ESP32C3 || ESP32C6)
#define ESP32S3_OR_LATER (ESP32S3 || ESP32C3 || ESP32C6)
#define ESP32C3_OR_LATER (ESP32C3 || ESP32C6)

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
#define GPIO_BASE_REG      0x3ff44000 /* GPIO */
#endif

#ifdef ESP32S2
#define UART_BASE_REG      0x60000000 /* UART0 */
#define SPI_BASE_REG       0x3f402000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG      0x3f403000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG      0x3f404000
#define USB_BASE_REG       0x60080000
#define RTCCNTL_BASE_REG   0x3f408000
#endif

#ifdef ESP32S3
#define UART_BASE_REG      0x60000000 /* UART0 */
#define SPI_BASE_REG       0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG      0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG      0x60004000 /* GPIO */
#define RTCCNTL_BASE_REG   0x60008000 /* RTC Control */
#endif

#ifdef ESP32C3
#define UART_BASE_REG      0x60000000 /* UART0 */
#define SPI_BASE_REG       0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG      0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG      0x60004000
#define RTCCNTL_BASE_REG   0x60008000
#define USB_DEVICE_BASE_REG          0x60043000
#endif

#ifdef ESP32C6
#define UART_BASE_REG      0x60000000 /* UART0 */
#define SPI_BASE_REG       0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG      0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG      0x60004000
#define RTCCNTL_BASE_REG   0x60008000
#endif

/**********************************************************
 * UART peripheral
 *
 * The features we use are basically the same on all chips
 *
 * Only UART0 is used
 */
#define UART_CLKDIV_REG(X) (UART_BASE_REG + 0x14)
#define UART_CLKDIV_M      (0x000FFFFF)

#if ESP32_OR_LATER
#define UART_CLKDIV_FRAG_S 20
#define UART_CLKDIV_FRAG_V 0xF
#endif

#define UART_FIFO(X)       (UART_BASE_REG + 0x00)
#define UART_INT_ST(X)     (UART_BASE_REG + 0x08)
#define UART_INT_ENA(X)    (UART_BASE_REG + 0x0C)
#define UART_INT_CLR(X)    (UART_BASE_REG + 0x10)
#define UART_STATUS(X)     (UART_BASE_REG + 0x1C)

#if defined(ESP32S2) || defined(ESP32S3)
#define UART_RXFIFO_CNT_M 0x3FF
#else
#define UART_RXFIFO_CNT_M 0xFF
#endif

#define UART_RXFIFO_FULL_INT_ENA            (1<<0)
#define UART_RXFIFO_TOUT_INT_ENA            (1<<8)

#define ETS_UART0_INUM 5


/**********************************************************
 * SPI peripheral
 *
 * The features we use are mostly the same on all chips
 * except for W0 base address & option for 2-byte status command
 *
 * Only one SPI peripheral is used (0 on ESP8266, 1 on ESP32).
 * On ESP32S2 && ESP32S3 this is called SPI_MEM_xxx index 1
 */
#define SPI_CMD_REG       (SPI_BASE_REG + 0x00)
#define SPI_FLASH_WREN    (1<<30)
#define SPI_FLASH_RDSR    (1<<27)
#define SPI_FLASH_SE      (1<<24)
#define SPI_FLASH_BE      (1<<23)

#define SPI_ADDR_REG      (SPI_BASE_REG + 0x04)

#define SPI_CTRL_REG      (SPI_BASE_REG + 0x08)
#if ESP32_OR_LATER
#define SPI_WRSR_2B       (1<<22)
#endif

#if ESP32S2_OR_LATER
#define SPI_RD_STATUS_REG (SPI_BASE_REG + 0x2C)
#else
#define SPI_RD_STATUS_REG (SPI_BASE_REG + 0x10)
#endif

#ifdef ESP8266
#define SPI_W0_REG        (SPI_BASE_REG + 0x40)
#endif
#ifdef ESP32
#define SPI_W0_REG        (SPI_BASE_REG + 0x80)
#endif
#if ESP32S2_OR_LATER
#define SPI_W0_REG        (SPI_BASE_REG + 0x58)
#endif

#if ESP32S2_OR_LATER
#define SPI_EXT2_REG      (SPI_BASE_REG + 0x54) /* renamed SPI_MEM_FSM_REG */
#else
#define SPI_EXT2_REG      (SPI_BASE_REG + 0xF8)
#endif

#define SPI_ST 0x7 /* done state value */

#ifdef ESP32
/* On ESP32 & newer the SPI peripherals are layered
 * flash, this lets us check the state of the internal
 * state machine under the SPI flash controller
 */
#define SPI0_EXT2_REG     (SPI0_BASE_REG + 0xF8)
#endif
#if ESP32S2_OR_LATER
#define SPI0_EXT2_REG     (SPI0_BASE_REG + 0x54)
#endif

/**********************************************************
 * GPIO peripheral
 *
 * We only need to read the strapping register on ESP32 & ESP32S2 & ESP32S3
 */
#define GPIO_STRAP_REG    (GPIO_BASE_REG + 0x38)

/**********************************************************
 * USB peripheral
 */

#ifdef ESP32S2
#define ETS_USB_INTR_SOURCE  48
#define ETS_USB_INUM  9  /* arbitrary level 1 level interrupt */
#endif // ESP32S2

#ifdef ESP32C3
#define USB_DEVICE_INT_CLR_REG          (USB_DEVICE_BASE_REG + 0x014)
#define USB_DEVICE_EP1_CONF_REG         (USB_DEVICE_BASE_REG + 0x004)
#define USB_DEVICE_EP1_REG              (USB_DEVICE_BASE_REG + 0x000)
#define USB_DEVICE_SERIAL_OUT_RECV_PKT_INT_CLR  (1<<2)
#define USB_DEVICE_SERIAL_OUT_EP_DATA_AVAIL     (1<<2)

#define DR_REG_INTERRUPT_CORE0_BASE             0x600c2000
#define INTERRUPT_CORE0_USB_INTR_MAP_REG        (DR_REG_INTERRUPT_CORE0_BASE + 0x068)

#define USB_DEVICE_INT_ENA_REG                  (USB_DEVICE_BASE_REG + 0x010)
#define USB_DEVICE_SERIAL_OUT_RECV_PKT_INT_ENA  (1<<2)

#define ETS_USB_INUM 17  /* arbitrary level 1 level interrupt */
#endif

#define USB_GAHBCFG_REG    (USB_BASE_REG + 0x8)
#define USB_GLBLLNTRMSK    (1 << 0)


/**********************************************************
 * RTC_CNTL peripheral
 */

#define RTC_CNTL_OPTION1_REG          (RTCCNTL_BASE_REG + 0x0128)
#define RTC_CNTL_FORCE_DOWNLOAD_BOOT  (1 << 0)
