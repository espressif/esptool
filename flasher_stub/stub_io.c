/*
 * Copyright (c) 2016 Cesanta Software Limited and 2016-2020 Espressif Systems (Shanghai) PTE LTD
 *
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

#include <stdlib.h>
#include "stub_io.h"
#include "rom_functions.h"
#include "soc_support.h"


#define UART_RX_INTS (UART_RXFIFO_FULL_INT_ENA | UART_RXFIFO_TOUT_INT_ENA)


static void(*s_rx_cb_func)(char);
#ifdef WITH_USB_OTG
static uint32_t s_cdcacm_old_rts;
static volatile bool s_cdcacm_reset_requested;
static char s_cdcacm_txbuf[ACM_BYTES_PER_TX];
static size_t s_cdcacm_txpos;
#endif // WITH_USB_OTG


void uart_isr(void *arg) {
  uint32_t int_st = READ_REG(UART_INT_ST(0));
  while (1) {
    uint32_t fifo_len = READ_REG(UART_STATUS(0)) & UART_RXFIFO_CNT_M;
    if (fifo_len == 0) {
      break;
    }
    while (fifo_len-- > 0) {
      uint8_t byte = READ_REG(UART_FIFO(0)) & 0xff;
      (*s_rx_cb_func)(byte);
    }
  }
  WRITE_REG(UART_INT_CLR(0), int_st);
}

#if WITH_USB_JTAG_SERIAL
static bool stub_uses_usb_jtag_serial(void)
{
  UartDevice *uart = GetUartDevice();

  /* buff_uart_no indicates which UART is used for SLIP communication) */
  return uart->buff_uart_no == UART_USB_JTAG_SERIAL;
}

void jtag_serial_isr(void *arg)
{
    WRITE_REG(USB_DEVICE_INT_CLR_REG, USB_DEVICE_SERIAL_OUT_RECV_PKT_INT_CLR); //ack interrupt
    while (READ_REG(USB_DEVICE_EP1_CONF_REG) & USB_DEVICE_SERIAL_OUT_EP_DATA_AVAIL)
    {
      uint8_t byte = READ_REG(USB_DEVICE_EP1_REG);
      (*s_rx_cb_func)(byte);
    }
}
#endif // WITH_USB_JTAG_SERIAL

static void stub_configure_rx_uart(void)
{
  /* All UART reads come via uart_isr or jtag_serial_isr */
#if WITH_USB_JTAG_SERIAL
  if (stub_uses_usb_jtag_serial()) {
    WRITE_REG(INTERRUPT_CORE0_USB_INTR_MAP_REG, ETS_USB_INUM);
    esprv_intc_int_set_priority(ETS_USB_INUM, 1);
    ets_isr_attach(ETS_USB_INUM, jtag_serial_isr, NULL);
    REG_SET_MASK(USB_DEVICE_INT_ENA_REG, USB_DEVICE_SERIAL_OUT_RECV_PKT_INT_ENA);
    ets_isr_unmask(1 << ETS_USB_INUM);
    return;
  }
#endif // WITH_USB_JTAG_SERIAL
  ets_isr_attach(ETS_UART0_INUM, uart_isr, NULL);
  REG_SET_MASK(UART_INT_ENA(0), UART_RX_INTS);
  ets_isr_unmask(1 << ETS_UART0_INUM);
}

#ifdef WITH_USB_OTG

void stub_cdcacm_cb(cdc_acm_device *dev, int status)
{
  if (status == ACM_STATUS_RX) {
    while (cdc_acm_rx_fifo_cnt(uart_acm_dev) > 0) {
      uint8_t c;
      cdc_acm_fifo_read(uart_acm_dev, &c, 1);
      (*s_rx_cb_func)((char) c);
    }
  } else if (status == ACM_STATUS_LINESTATE_CHANGED) {
    uint32_t rts = 0;
    cdc_acm_line_ctrl_get(dev, LINE_CTRL_RTS, &rts);
    if (rts == 0 && s_cdcacm_old_rts == 1) {
      s_cdcacm_reset_requested = true;
    }
    s_cdcacm_old_rts = rts;
  }
}

static void stub_cdcacm_flush(void)
{
    cdc_acm_fifo_fill(uart_acm_dev, (const uint8_t *) s_cdcacm_txbuf, s_cdcacm_txpos);
    /* return value ignored — if bootloader fails to log something, proceed anyway */
    s_cdcacm_txpos = 0;
}

static void stub_cdcacm_write_char(char ch)
{
    s_cdcacm_txbuf[s_cdcacm_txpos++] = ch;
    if (ch == '\xc0' || s_cdcacm_txpos == sizeof(s_cdcacm_txbuf)) {
        stub_cdcacm_flush();
    }
}

static bool stub_uses_usb_otg(void)
{
  return UartDev_buff_uart_no == UART_USB_OTG;
}

static void stub_configure_rx_usb(void)
{
  cdc_acm_line_ctrl_get(uart_acm_dev, LINE_CTRL_RTS, &s_cdcacm_old_rts);
  intr_matrix_set(0, ETS_USB_INTR_SOURCE, ETS_USB_INUM);
  ets_isr_attach(ETS_USB_INUM, usb_dw_isr_handler, NULL);
  ets_isr_unmask(1 << ETS_USB_INUM);
  cdc_acm_irq_callback_set(uart_acm_dev, &stub_cdcacm_cb);
  cdc_acm_irq_rx_enable(uart_acm_dev);
  cdc_acm_irq_state_enable(uart_acm_dev);
  REG_SET_MASK(USB_GAHBCFG_REG, USB_GLBLLNTRMSK);
}
#endif // WITH_USB_OTG

void stub_tx_one_char(char c)
{
#if WITH_USB_OTG
  if (stub_uses_usb_otg()) {
    stub_cdcacm_write_char(c);
    return;
  }
#endif // WITH_USB_OTG
  uart_tx_one_char(c);
#if WITH_USB_JTAG_SERIAL
  if (stub_uses_usb_jtag_serial()){
    stub_tx_flush();
  }
#endif // WITH_USB_JTAG_SERIAL
}

void stub_tx_flush(void)
{
#if WITH_USB_OTG
  if (stub_uses_usb_otg()) {
    if (s_cdcacm_txpos > 0) {
      stub_cdcacm_flush();
    }
  }
#endif // WITH_USB_OTG
#if WITH_USB_JTAG_SERIAL
  if (stub_uses_usb_jtag_serial()){
      uart_tx_flush(UART_USB_JTAG_SERIAL);
      return;
  }
#endif // WITH_USB_JTAG_SERIAL
#if ESP32_OR_LATER
  uart_tx_flush(0);
#endif
}

char stub_rx_one_char(void)
{
  char c = 0;
  /* Using uart_rx_one_char here instead of uart_rx_one_char_block,
   * because the latter simply returns (char) 0 if no bytes
   * are available, when used with USB CDC.
   */
  while (uart_rx_one_char((uint8_t*) &c) != 0) { }
  return c;
}

void stub_rx_async_enable(bool enable)
{
  uint32_t mask;
#if WITH_USB_OTG
  if (stub_uses_usb_otg()) {
    mask = 1 << ETS_USB_INUM;
    if (enable) {
      cdc_acm_irq_rx_enable(uart_acm_dev);
      ets_isr_unmask(mask);
    } else {
      ets_isr_mask(mask);
      cdc_acm_irq_rx_disable(uart_acm_dev);
    }
    return;
  }
#endif // WITH_USB_OTG
#if WITH_USB_JTAG_SERIAL
  mask = stub_uses_usb_jtag_serial() ? 1 << ETS_USB_INUM : 1 << ETS_UART0_INUM;
#else
  mask = 1 << ETS_UART0_INUM;
#endif
  if (enable) {
    ets_isr_unmask(mask);
  } else {
    ets_isr_mask(mask);
  }
}

void stub_io_idle_hook(void)
{
#if WITH_USB_OTG
  if (s_cdcacm_reset_requested)
  {
    s_cdcacm_reset_requested = false;
    ets_isr_mask(1 << ETS_USB_INUM);
    ets_delay_us(10000);
    /* Handle the last few interrupts as they come in before the USB peripheral is idle */
    usb_dc_check_poll_for_interrupts();
    REG_CLR_MASK(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
    chip_usb_set_persist_flags(USBDC_PERSIST_ENA);
    usb_dc_prepare_persist();
    software_reset_cpu(0);
  }
#endif // WITH_USB_OTG
}

void stub_io_init(void(*rx_cb_func)(char))
{
  s_rx_cb_func = rx_cb_func;
#if WITH_USB_OTG
  if (stub_uses_usb_otg()) {
    stub_configure_rx_usb();
    return;
  }
#endif // WITH_USB_OTG
  stub_configure_rx_uart();
}

static uint32_t get_new_uart_divider(uint32_t current_baud, uint32_t new_baud)
{
  uint32_t master_freq;
  /* ESP32 has ROM code to detect the crystal freq but ESP8266 does not have this...
     So instead we use the previously auto-synced 115200 baud rate (which we know
     is correct wrt the relative crystal accuracy of the ESP & the USB/serial adapter).
     From this we can estimate crystal freq, and update for a new baud rate relative to that.
  */
  uint32_t uart_reg = READ_REG(UART_CLKDIV_REG(0));
  uint32_t uart_div = uart_reg & UART_CLKDIV_M;
#if ESP32_OR_LATER
  // account for fractional part of divider (bottom 4 bits)
  uint32_t fraction = (uart_reg >> UART_CLKDIV_FRAG_S) & UART_CLKDIV_FRAG_V;
  uart_div = (uart_div << 4) + fraction;
#endif
  master_freq = uart_div * current_baud;
  return master_freq / new_baud;
}

void stub_io_set_baudrate(uint32_t current_baud, uint32_t new_baud)
{
#if WITH_USB_OTG
  /* Technically no harm in increasing UART baud rate when communicating over USB,
   * however for debugging the USB part it is occasionally useful to ets_printf
   * something to UART. Not changing the baud rate helps in such case.
   */
  if (stub_uses_usb_otg()) {
    return;
  }
#endif // WITH_USB_OTG
  ets_delay_us(10000);
  uart_div_modify(0, get_new_uart_divider(current_baud, new_baud));
  ets_delay_us(1000);
}
