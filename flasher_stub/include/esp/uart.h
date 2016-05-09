/** esp/uart.h
 *
 * Utility routines for working with UARTs
 *
 * Part of esp-open-rtos
 * Copyright (C) 2015 Superhouse Automation Pty Ltd
 * BSD Licensed as described in the file LICENSE
 */
#ifndef _ESP_UART_H
#define _ESP_UART_H

#include "esp/types.h"
#include "esp/uart_regs.h"
#include "esp/clocks.h"

#define UART_FIFO_MAX 127

/* Wait for at least `min_count` bytes of data to be available in the UART's
 * receive FIFO
 *
 * Returns the number of bytes actually available for reading.
 */
static inline int uart_rxfifo_wait(int uart_num, int min_count) {
    int count;
    do {
        count = FIELD2VAL(UART_STATUS_RXFIFO_COUNT, UART(uart_num).STATUS);
    } while (count < min_count);
    return count;
}

/* Wait for at least `min_count` bytes of space to be available in the UART's
 * transmit FIFO
 *
 * Returns the number of bytes actually available in the write buffer.
 */
static inline int uart_txfifo_wait(int uart_num, int min_count) {
    int count;
    do {
        count = UART_FIFO_MAX - FIELD2VAL(UART_STATUS_TXFIFO_COUNT, UART(uart_num).STATUS);
    } while (count < min_count);
    return count;
}

/* Read a character from the UART.  Block until a character is available for
 * reading.
 *
 * Returns the character read.
 */
static inline int uart_getc(int uart_num) {
    uart_rxfifo_wait(uart_num, 1);
    return UART(uart_num).FIFO;
}

/* Read a character from the UART.  Does not block.
 *
 * Returns the read character on success.  If the RX FIFO is currently empty
 * (nothing to read), returns -1.
 */
static inline int uart_getc_nowait(int uart_num) {
    if (FIELD2VAL(UART_STATUS_RXFIFO_COUNT, UART(uart_num).STATUS)) {
        return UART(uart_num).FIFO;
    }
    return -1;
}

/* Write a character to the UART.  Blocks if necessary until there is space in
 * the TX FIFO.
 */
static inline void uart_putc(int uart_num, char c) {
    uart_txfifo_wait(uart_num, 1);
    UART(uart_num).FIFO = c;
}

/* Write a character to the UART.  Does not block.
 *
 * Returns 0 on success.  If there is no space currently in the TX FIFO,
 * returns -1.
 */
static inline int uart_putc_nowait(int uart_num, char c) {
    if (FIELD2VAL(UART_STATUS_TXFIFO_COUNT, UART(uart_num).STATUS) < UART_FIFO_MAX) {
        UART(uart_num).FIFO = c;
        return 0;
    }
    return -1;
}

/* Clear (discard) all pending write data in the TX FIFO */
static inline void uart_clear_txfifo(int uart_num) {
    uint32_t conf = UART(uart_num).CONF0;
    UART(uart_num).CONF0 = conf | UART_CONF0_TXFIFO_RESET;
    UART(uart_num).CONF0 = conf & ~UART_CONF0_TXFIFO_RESET;
}

/* Clear (discard) all pending read data in the RX FIFO */
static inline void uart_clear_rxfifo(int uart_num) {
    uint32_t conf = UART(uart_num).CONF0;
    UART(uart_num).CONF0 = conf | UART_CONF0_RXFIFO_RESET;
    UART(uart_num).CONF0 = conf & ~UART_CONF0_RXFIFO_RESET;
}

/* Wait until all pending output in the UART's TX FIFO has been sent out the
 * serial port. */
static inline void uart_flush_txfifo(int uart_num) {
    while (FIELD2VAL(UART_STATUS_TXFIFO_COUNT, UART(uart_num).STATUS) != 0) {}
}

/* Flush all pending input in the UART's RX FIFO
 * (this is just another name for uart_clear_rxfifo)
 */
static inline void uart_flush_rxfifo(int uart_num) {
    uart_clear_rxfifo(uart_num);
}

/* Set uart baud rate to the desired value */
static inline void uart_set_baud(int uart_num, int bps)
{
    uint32_t divider = APB_CLK_FREQ / bps;
    UART(uart_num).CLOCK_DIVIDER = divider;
}

/* Returns the current baud rate for the UART */
static inline int uart_get_baud(int uart_num)
{
    return APB_CLK_FREQ / FIELD2VAL(UART_CLOCK_DIVIDER_VALUE, UART(uart_num).CLOCK_DIVIDER);
}

#endif /* _ESP_UART_H */
