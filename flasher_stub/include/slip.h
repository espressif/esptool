/*
 * SPDX-FileCopyrightText: 2016 Cesanta Software Limited
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
 */

#ifndef SLIP_H_
#define SLIP_H_

#include <stdint.h>

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
