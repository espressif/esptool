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

#ifndef SLIP_H_
#define SLIP_H_

#ifdef ESP8266
#include <c_types.h>
#else
#include <stdint.h>
#endif

/* Send the SLIP frame begin/end delimiter. */
void SLIP_send_frame_delimiter(void);

/* Send a single character of SLIP frame data, escaped as per SLIP escaping. */
void SLIP_send_frame_data(char ch);

/* Send some SLIP frame data, escaped as per SLIP escaping. */
void SLIP_send_frame_data_buf(const void *buf, uint32_t size);

/* Send a full SLIP frame, with specified contents. */
void SLIP_send(const void *pkt, uint32_t size);

typedef enum {
  SLIP_NO_FRAME,
  SLIP_FRAME,
  SLIP_FRAME_ESCAPING
} slip_state_t;

int16_t SLIP_recv_byte(char byte, slip_state_t *state);

#define SLIP_FINISHED_FRAME -2
#define SLIP_NO_BYTE -1

/* Receive a SLIP frame, with specified contents. */
uint32_t SLIP_recv(void *pkt, uint32_t max_len);

#endif /* SLIP_H_ */
