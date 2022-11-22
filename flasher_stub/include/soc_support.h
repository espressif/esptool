/*
 * SPDX-FileCopyrightText: 2016-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#define ESP32_OR_LATER   !(ESP8266)
#define ESP32S2_OR_LATER !(ESP8266 || ESP32)
#define ESP32S3_OR_LATER !(ESP8266 || ESP32 || ESP32S2)

/**********************************************************
 * Per-SOC capabilities
 */
#ifdef ESP32S2
#define WITH_USB_OTG 1
#endif // ESP32S2

#ifdef ESP32C3
#define WITH_USB_JTAG_SERIAL 1
#define IS_RISCV 1
#endif // ESP32C3

#ifdef ESP32S3
#define WITH_USB_JTAG_SERIAL 1
#define WITH_USB_OTG 1
#endif // ESP32S3

#ifdef ESP32C6
#define WITH_USB_JTAG_SERIAL 1
#define IS_RISCV 1
#endif // ESP32C6

// Increase CPU freq to speed up read/write operations over USB
#define USE_MAX_CPU_FREQ (WITH_USB_JTAG_SERIAL || WITH_USB_OTG)

/**********************************************************
 * Per-SOC based peripheral register base addresses
 */
#ifdef ESP8266
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x60000200 /* SPI peripheral 0 */
#endif

#ifdef ESP32
#define UART_BASE_REG       0x3ff40000 /* UART0 */
#define SPI_BASE_REG        0x3ff42000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x3ff43000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x3ff44000 /* GPIO */
#endif

#ifdef ESP32S2
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x3f402000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x3f403000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x3f404000
#define USB_BASE_REG        0x60080000
#define RTCCNTL_BASE_REG    0x3f408000
#define SYSTEM_BASE_REG     0x3F4C0000
#endif

#ifdef ESP32S3
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x60004000 /* GPIO */
#define USB_BASE_REG        0x60080000
#define RTCCNTL_BASE_REG    0x60008000 /* RTC Control */
#define USB_DEVICE_BASE_REG 0x60038000
#define SYSTEM_BASE_REG     0x600C0000
#endif

#ifdef ESP32C3
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x60004000
#define USB_DEVICE_BASE_REG 0x60043000
#define SYSTEM_BASE_REG     0x600C0000
#endif

#ifdef ESP32C6BETA
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x60004000
#endif

#ifdef ESP32H2BETA1
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x60004000
#define RTCCNTL_BASE_REG    0x60008000
#endif

#ifdef ESP32H2BETA2
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x60004000
#endif

#ifdef ESP32C2
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x60002000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x60003000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x60004000
#endif

#ifdef ESP32C6
#define UART_BASE_REG       0x60000000 /* UART0 */
#define SPI_BASE_REG        0x60003000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG       0x60002000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG       0x60091000
#define USB_DEVICE_BASE_REG 0x6000F000
#define DR_REG_PCR_BASE     0x60096000
#endif

#ifdef ESP32H2
#define UART_BASE_REG      0x60000000 /* UART0 */
#define SPI_BASE_REG       0x60003000 /* SPI peripheral 1, used for SPI flash */
#define SPI0_BASE_REG      0x60002000 /* SPI peripheral 0, inner state machine */
#define GPIO_BASE_REG      0x60091000
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

#if ESP32S2_OR_LATER && !ESP32C6 && !ESP32H2
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
 * We only need to read the strapping register on ESP32 or later
 */
#define GPIO_STRAP_REG    (GPIO_BASE_REG + 0x38)

/**********************************************************
 * USB peripheral
 */

#ifdef ESP32S2
#define UART_USB_OTG  2

#define ETS_USB_INTR_SOURCE  48
#define ETS_USB_INUM  9  /* arbitrary level 1 level interrupt */
#endif // ESP32S2

#ifdef ESP32C3
#define UART_USB_JTAG_SERIAL  3

#define DR_REG_INTERRUPT_CORE0_BASE             0x600c2000
#define INTERRUPT_CORE0_USB_INTR_MAP_REG        (DR_REG_INTERRUPT_CORE0_BASE + 0x068) /* USB-JTAG-Serial */

#define ETS_USB_INUM 17  /* arbitrary level 1 level interrupt */
#endif // ESP32C3

#ifdef ESP32S3
#define UART_USB_OTG  3
#define UART_USB_JTAG_SERIAL  4

#define DR_REG_INTERRUPT_CORE0_BASE             0x600c2000
#define INTERRUPT_CORE0_USB_INTR_MAP_REG        (DR_REG_INTERRUPT_CORE0_BASE + 0x098) /* DWC-OTG */
#define INTERRUPT_CORE0_USB_DEVICE_INT_MAP_REG  (DR_REG_INTERRUPT_CORE0_BASE + 0x180) /* USB-JTAG-Serial */

#define ETS_USB_INUM 17  /* arbitrary level 1 level interrupt */
#endif // ESP32S3

#ifdef ESP32C6
#define UART_USB_JTAG_SERIAL  3

#define DR_REG_INTERRUPT_MATRIX_BASE            0x60010000
#define INTERRUPT_CORE0_USB_INTR_MAP_REG        (DR_REG_INTERRUPT_MATRIX_BASE + 0xC0) /* USB-JTAG-Serial, INTMTX_CORE0_USB_INT_MAP_REG */

#define ETS_USB_INUM 17  /* arbitrary level 1 level interrupt */
#endif // ESP32C6

#ifdef WITH_USB_JTAG_SERIAL
#define USB_DEVICE_INT_ENA_REG          (USB_DEVICE_BASE_REG + 0x010)
#define USB_DEVICE_INT_CLR_REG          (USB_DEVICE_BASE_REG + 0x014)
#define USB_DEVICE_EP1_CONF_REG         (USB_DEVICE_BASE_REG + 0x004)
#define USB_DEVICE_EP1_REG              (USB_DEVICE_BASE_REG + 0x000)
#define USB_DEVICE_SERIAL_OUT_RECV_PKT_INT_CLR  (1<<2)
#define USB_DEVICE_SERIAL_OUT_EP_DATA_AVAIL     (1<<2)
#define USB_DEVICE_SERIAL_OUT_RECV_PKT_INT_ENA  (1<<2)
#endif // WITH_USB_JTAG_SERIAL

#define USB_GAHBCFG_REG    (USB_BASE_REG + 0x8)
#define USB_GLBLLNTRMSK    (1 << 0)


/**********************************************************
 * RTC_CNTL peripheral
 */

#ifdef ESP32S2
#define RTC_CNTL_OPTION1_REG          (RTCCNTL_BASE_REG + 0x0128)
#endif

#ifdef ESP32S3
#define RTC_CNTL_OPTION1_REG          (RTCCNTL_BASE_REG + 0x012C)
#endif

#define RTC_CNTL_FORCE_DOWNLOAD_BOOT  (1 << 0)

/**********************************************************
 * SYSTEM registers
 */

#ifdef ESP32S3
#define SYSTEM_CPU_PER_CONF_REG       (SYSTEM_BASE_REG + 0x010)
#define SYSTEM_CPUPERIOD_SEL_M        ((SYSTEM_CPUPERIOD_SEL_V)<<(SYSTEM_CPUPERIOD_SEL_S))
#define SYSTEM_CPUPERIOD_SEL_V        0x3
#define SYSTEM_CPUPERIOD_SEL_S        0
#define SYSTEM_CPUPERIOD_MAX          2  // CPU_CLK frequency is 240 MHz

#define SYSTEM_SYSCLK_CONF_REG        (SYSTEM_BASE_REG + 0x060)
#define SYSTEM_SOC_CLK_SEL_M          ((SYSTEM_SOC_CLK_SEL_V)<<(SYSTEM_SOC_CLK_SEL_S))
#define SYSTEM_SOC_CLK_SEL_V          0x3
#define SYSTEM_SOC_CLK_SEL_S          10
#define SYSTEM_SOC_CLK_MAX            1
#endif // ESP32S3

#ifdef ESP32C3
#define SYSTEM_CPU_PER_CONF_REG       (SYSTEM_BASE_REG + 0x008)
#define SYSTEM_CPUPERIOD_SEL_M        ((SYSTEM_CPUPERIOD_SEL_V)<<(SYSTEM_CPUPERIOD_SEL_S))
#define SYSTEM_CPUPERIOD_SEL_V        0x3
#define SYSTEM_CPUPERIOD_SEL_S        0
#define SYSTEM_CPUPERIOD_MAX          1  // CPU_CLK frequency is 160 MHz

#define SYSTEM_SYSCLK_CONF_REG        (SYSTEM_BASE_REG + 0x058)
#define SYSTEM_SOC_CLK_SEL_M          ((SYSTEM_SOC_CLK_SEL_V)<<(SYSTEM_SOC_CLK_SEL_S))
#define SYSTEM_SOC_CLK_SEL_V          0x3
#define SYSTEM_SOC_CLK_SEL_S          10
#define SYSTEM_SOC_CLK_MAX            1
#endif // ESP32C3

#ifdef ESP32S2
#define SYSTEM_CPU_PER_CONF_REG       (SYSTEM_BASE_REG + 0x018)
#define SYSTEM_CPUPERIOD_SEL_M        ((SYSTEM_CPUPERIOD_SEL_V)<<(SYSTEM_CPUPERIOD_SEL_S))
#define SYSTEM_CPUPERIOD_SEL_V        0x3
#define SYSTEM_CPUPERIOD_SEL_S        0
#define SYSTEM_CPUPERIOD_MAX          2  // CPU_CLK frequency is 240 MHz

#define SYSTEM_SYSCLK_CONF_REG        (SYSTEM_BASE_REG + 0x08C)
#define SYSTEM_SOC_CLK_SEL_M          ((SYSTEM_SOC_CLK_SEL_V)<<(SYSTEM_SOC_CLK_SEL_S))
#define SYSTEM_SOC_CLK_SEL_V          0x3
#define SYSTEM_SOC_CLK_SEL_S          10
#define SYSTEM_SOC_CLK_MAX            1
#endif // ESP32S2

#ifdef ESP32C6
#define PCR_SYSCLK_CONF_REG          (DR_REG_PCR_BASE + 0x110)
#define PCR_SOC_CLK_SEL_M            ((PCR_SOC_CLK_SEL_V)<<(PCR_SOC_CLK_SEL_S))
#define PCR_SOC_CLK_SEL_V            0x3
#define PCR_SOC_CLK_SEL_S            16
#define PCR_SOC_CLK_MAX              1 // CPU_CLK frequency is 160 MHz (source is PLL_CLK)
#endif // ESP32C6

/**********************************************************
 * Per-SOC security info buffer size
 */

#ifdef ESP32S2
#define SECURITY_INFO_BYTES 12 /* doesn't include chip_id and api_version */
#endif // ESP32S2

#if ESP32S3_OR_LATER
#define SECURITY_INFO_BYTES 20
#endif // ESP32S3_OR_LATER
