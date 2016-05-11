/* esp/clocks.h
 *
 * ESP8266 internal clock values
 *
 * Adapted for use in bootloader stub!
 *
 * Part of esp-open-rtos
 * Copyright (C) 2015 Superhouse Automation Pty Ltd
 * BSD Licensed as described in the file LICENSE
 */
#ifndef _ESP_CLOCKS_H
#define _ESP_CLOCKS_H
#include <common_macros.h>

/* CPU clock, is 2x crystal frequency inside bootloader
 */
#if defined(ESP8266)
#define CPU_CLK_FREQ 52*1000000
#elif defined(ESP32)
#define CPU_CLK_FREQ 80*1000000
#else
#error "Unknown SoC target?"
#endif

/* Main peripheral clock

   This is also the master frequency for the UART and the TIMER module
   (before divisors applied to either.)
 */
#define APB_CLK_FREQ CPU_CLK_FREQ

#endif
