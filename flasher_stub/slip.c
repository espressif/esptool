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

#include "rom_functions.h"
#include "slip.h"

void SLIP_send_frame_delimiter(void) {
  uart_tx_one_char('\xc0');
}

void SLIP_send_frame_data(char ch) {
  if(ch == '\xc0') {
	uart_tx_one_char('\xdb');
	uart_tx_one_char('\xdc');
  } else if (ch == '\xdb') {
	uart_tx_one_char('\xdb');
	uart_tx_one_char('\xdd');
  } else {
	uart_tx_one_char(ch);
  }
}

void SLIP_send_frame_data_buf(const void *buf, uint32_t size) {
  const uint8_t *buf_c = (const uint8_t *)buf;
  for(int i = 0; i < size; i++) {
	SLIP_send_frame_data(buf_c[i]);
  }
}

void SLIP_send(const void *pkt, uint32_t size) {
  SLIP_send_frame_delimiter();
  SLIP_send_frame_data_buf(pkt, size);
  SLIP_send_frame_delimiter();
}

int16_t SLIP_recv_byte(char byte, slip_state_t *state)
{
  if (byte == '\xc0') {
	if (*state == SLIP_NO_FRAME) {
	  *state = SLIP_FRAME;
	  return SLIP_NO_BYTE;
	} else {
	  *state = SLIP_NO_FRAME;
	  return SLIP_FINISHED_FRAME;
	}
  }

  switch(*state) {
  case SLIP_NO_FRAME:
	return SLIP_NO_BYTE;
  case SLIP_FRAME:
	if (byte == '\xdb') {
	  *state = SLIP_FRAME_ESCAPING;
	  return SLIP_NO_BYTE;
	}
	return byte;
  case SLIP_FRAME_ESCAPING:
	if (byte == '\xdc') {
	  *state = SLIP_FRAME;
	  return '\xc0';
	}
	if (byte == '\xdd') {
	  *state = SLIP_FRAME;
	  return '\xdb';
	}
	return SLIP_NO_BYTE; /* actually a framing error */
  }
  return SLIP_NO_BYTE; /* actually a framing error */
}

uint32_t SLIP_recv(void *pkt, uint32_t max_len) {
  uint32_t len = 0;
  slip_state_t state = SLIP_NO_FRAME;
  uint8_t *p = (uint8_t *) pkt;

  int16_t r;
  do {
	r = SLIP_recv_byte(uart_rx_one_char_block(), &state);
	if(r >= 0 && len < max_len) {
	  p[len++] = (uint8_t)r;
	}
  } while(r != SLIP_FINISHED_FRAME);

  return len;
}
