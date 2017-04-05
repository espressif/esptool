/* Declarations for functions in ESP32 ROM code
 *
 * Copyright (c) 2016-2017 Espressif Systems (Shanghai) PTE LTD
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
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Unlike ESP8266, most of these functions are declared in IDF headers
   so we can include these directly.
*/
#include "rom/ets_sys.h"
#include "rom/spi_flash.h"
#include "rom/md5_hash.h"
#include "rom/uart.h"
#include "rom/efuse.h"
#include "rom/rtc.h"

/* I think the difference is \r\n auto-escaping */
#define uart_tx_one_char uart_tx_one_char2
