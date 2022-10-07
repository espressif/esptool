/*
 * SPDX-FileCopyrightText: 2016 Cesanta Software Limited
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Call to initialize the I/O (either UART or USB CDC at this point).
 * The argument is a callback function which will handle received characters,
 * when asynchronous (interrupt-driven) RX is used.
 * It will be called in an interrupt context.
 */
void stub_io_init(void(*rx_cb_func)(char));

/* Enable or disable asynchronous (interrupt-driven) RX, for UART or USB.
 * Currently needed only for the read_flash command.
 */
void stub_rx_async_enable(bool enable);

/* Wrapper for either uart_tx_one_char or the USB CDC output function.
 * (uart_tx_one_char in ROM can also handle USB CDC, but it is really
 * slow because it flushes the FIFO after every byte).
 */
void stub_tx_one_char(char c);

/* A blocking (polling) function to receive one character.
 * Should only be used when async (interrupt-driven) RX is disabled.
 * Currently only needed for the read_flash command.
 */
char stub_rx_one_char(void);

/* Returns after making sure that all output has been sent to the host */
void stub_tx_flush(void);

/* Updates the baud rate divider based on the current baud rate (from host perspective)
 * and the requested baud rate.
 * No-op for USB CDC.
 */
void stub_io_set_baudrate(uint32_t current_baud, uint32_t new_baud);

/* To be called periodically while waiting for a command.
 * No-op for UART, handles DTR/RTS reset for USB CDC.
 */
void stub_io_idle_hook(void);

/* Checks if USB-Serial/JTAG is being currently used.
 */
#if WITH_USB_JTAG_SERIAL
bool stub_uses_usb_jtag_serial(void);
#endif

/* Checks if USB-OTG is being currently used.
 */
#if WITH_USB_OTG
bool stub_uses_usb_otg(void);
#endif
