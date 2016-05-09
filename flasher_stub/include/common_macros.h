/* Some common compiler macros
 *
 * Not esp8266-specific.
 *
 * Part of esp-open-rtos
 * Copyright (C) 2015 Superhouse Automation Pty Ltd
 * BSD Licensed as described in the file LICENSE
 */

#ifndef _COMMON_MACROS_H
#define _COMMON_MACROS_H

#include <sys/cdefs.h>

#define UNUSED __attributed((unused))

#ifndef BIT
#define BIT(X) (1<<(X))
#endif

/* These macros convert values to/from bitfields specified by *_M and *_S (mask
 * and shift) constants.  Used primarily with ESP8266 register access.
 */

#define VAL2FIELD(fieldname, value) ((value) << fieldname##_S)
#define FIELD2VAL(fieldname, regbits) (((regbits) >> fieldname##_S) & fieldname##_M)

#define FIELD_MASK(fieldname) (fieldname##_M << fieldname##_S)
#define SET_FIELD(regbits, fieldname, value) (((regbits) & ~FIELD_MASK(fieldname)) | VAL2FIELD(fieldname, value))

/* VAL2FIELD/SET_FIELD do not normally check to make sure that the passed value
 * will fit in the specified field (without clobbering other bits).  This makes
 * them faster and is usually fine.  If you do need to make sure that the value
 * will not overflow the field, use VAL2FIELD_M or SET_FIELD_M (which will
 * first mask the supplied value to only the allowed number of bits) instead.
 */
#define VAL2FIELD_M(fieldname, value) (((value) & fieldname##_M) << fieldname##_S)
#define SET_FIELD_M(regbits, fieldname, value) (((regbits) & ~FIELD_MASK(fieldname)) | VAL2FIELD_M(fieldname, value))

/* Use this macro to store constant values in IROM flash instead
   of having them loaded into rodata (which resides in DRAM)

   Unlike the ESP8266 SDK you don't need an attribute like this for
   standard functions. They're stored in flash by default. But
   variables need them.

   Important to note: IROM flash can only be accessed via 32-bit word
   aligned reads. It's up to the user of this attribute to ensure this.
*/
#ifdef	__cplusplus
    #define IROM __attribute__((section(".irom0.literal")))
#else
    #define IROM __attribute__((section(".irom0.literal"))) const
#endif

/* Use this macro to place functions into Instruction RAM (IRAM)
   instead of flash memory (IROM).

   This is useful for functions which are called when the flash may
   not be available (for example during NMI exceptions), or for
   functions which are called very frequently and need high
   performance.

   Bear in mind IRAM is limited (32KB), compared to up to 1MB of flash.
*/
#define IRAM __attribute__((section(".iram1.text")))

/* Use this macro to place read-only data into Instruction RAM (IRAM)
   instead of loaded into rodata which resides in DRAM.

   This may be useful to free up data RAM. However all data read from
   the instruction space must be 32-bit aligned word reads
   (non-aligned reads will use an interrupt routine to "fix" them and
   still work, but are very slow..
*/
#ifdef	__cplusplus
    #define IRAM_DATA __attribute__((section(".iram1.rodata")))
#else
    #define IRAM_DATA __attribute__((section(".iram1.rodata"))) const
#endif

#endif
