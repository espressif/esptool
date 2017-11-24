/* SoC support for ESP8266/ESP32.
 *
 * Provide a unified interface where possible, from ESP8266 Non-OS SDK & esp-idf
 * headers.
 *
 */
#pragma once

#ifdef ESP8266
#define SPI_IDX 0

#include "ets_sys.h"
#include "eagle_soc.h"
#include "driver_lib/include/driver/uart_register.h"
#include "driver_lib/include/driver/spi_register.h"

/* Harmonise register names between ESP8266 & -32 */
#define SPI_CMD_REG(X) SPI_CMD(X)
#define SPI_W0_REG(X) SPI_W0(X)
#define SPI_ADDR_REG(X) SPI_ADDR(X)
#define SPI_EXT2_REG(X) SPI_EXT2(X)
#define SPI_RD_STATUS_REG(X) SPI_RD_STATUS(X)

#define UART_CLKDIV_REG(X) UART_CLKDIV(X)
#define UART_CLKDIV_M (UART_CLKDIV_CNT << UART_CLKDIV_S)

#define SPI_ST 0x7 /* field in SPI_EXT2_REG */

#define REG_READ READ_PERI_REG
#define REG_WRITE WRITE_PERI_REG

#define ETS_UART0_INUM ETS_UART_INUM

#else /* ESP32 */
#define SPI_IDX 1

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "soc/soc.h"
#include "soc/uart_reg.h"
#include "soc/gpio_reg.h"
#include "soc/spi_reg.h"

/* Harmonise register names between ESP8266 and ESP32 */

#endif
