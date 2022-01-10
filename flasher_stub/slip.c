/*
 * SPDX-FileCopyrightText: 2016 Cesanta Software Limited
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
 */

#include <stdint.h>
#include "slip.h"
#include "stub_io.h"

void SLIP_send_frame_delimiter(void) {
  stub_tx_one_char('\xc0');
}

void SLIP_send_frame_data(char ch) {
  if(ch == '\xc0') {
	stub_tx_one_char('\xdb');
	stub_tx_one_char('\xdc');
  } else if (ch == '\xdb') {
	stub_tx_one_char('\xdb');
	stub_tx_one_char('\xdd');
  } else {
	stub_tx_one_char(ch);
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

/* This function is needed for the synchornous I/O case,
 * which is only flash_read command at the moment.
 */
uint32_t SLIP_recv(void *pkt, uint32_t max_len) {
  uint32_t len = 0;
  slip_state_t state = SLIP_NO_FRAME;
  uint8_t *p = (uint8_t *) pkt;

  int16_t r;
  do {
	r = SLIP_recv_byte(stub_rx_one_char(), &state);
	if(r >= 0 && len < max_len) {
	  p[len++] = (uint8_t)r;
	}
  } while(r != SLIP_FINISHED_FRAME);

  return len;
}
