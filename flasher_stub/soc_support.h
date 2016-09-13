/* SoC support for ESP8266/ESP32.
 *
 * Provide a unified interface where possible, from ESP8266 Non-OS SDK & esp-idf
 * headers.
 */
#pragma once

#ifdef ESP8266
#include "ets_sys.h"
#include "eagle_soc.h"
#include "examples/driver_lib/include/driver/uart_register.h"
#include "examples/driver_lib/include/driver/spi_register.h"

/* Harmonise register names between ESP8266 & -32 */
#define SPI_CMD_REG(X) SPI_CMD(X)
#define SPI_W0_REG(X) SPI_W0(X)
#define ETS_UART0_INUM ETS_UART_INUM

#else
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "soc/soc.h"
#include "soc/uart_reg.h"
#endif
