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

#include "rom_functions.h"

void SLIP_send(const void *pkt, uint32_t size) {
  send_packet(pkt, size);
}

uint32_t SLIP_recv(void *pkt, uint32_t max_len) {
  uint8_t c;
  uint32_t len = 0;
  uint8_t *p = (uint8_t *) pkt;
  do {
    c = uart_rx_one_char_block();
  } while (c != '\xc0');
  while (len < max_len) {
    c = uart_rx_one_char_block();
    if (c == '\xc0') return len;
    if (c == '\xdb') {
      c = uart_rx_one_char_block();
      if (c == '\xdc') {
        c = '\xc0';
      } else if (c == '\xdd') {
        c = '\xdb';
      } else {
        len = 0;
        break; /* Bad esc sequence. */
      }
    }
    *p++ = c;
    len++;
  }
  do {
    c = uart_rx_one_char_block();
  } while (c != '\xc0');
  return len;
}
