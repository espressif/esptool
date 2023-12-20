/*
 * SPDX-FileCopyrightText: 2016 Cesanta Software Limited
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
 */

/* ROM function prototypes for functions in ROM which are
   called by the flasher stubs.
*/
#pragma once

#include <stdint.h>
#include "soc_support.h"

int uart_rx_one_char(uint8_t *ch);
uint8_t uart_rx_one_char_block();
int uart_tx_one_char(char ch);

#if ESP32C6 || ESP32H2 || ESP32C5BETA3
/* uart_tx_one_char doesn't send data to USB device serial, needs to be replaced */
int uart_tx_one_char2(char ch);
#define uart_tx_one_char(ch) uart_tx_one_char2(ch)
#endif // ESP32C6 || ESP32H2 || ESP32C5BETA3

void uart_div_modify(uint32_t uart_no, uint32_t baud_div);

void ets_delay_us(uint32_t us);

typedef enum { SPI_FLASH_RESULT_OK = 0,
               SPI_FLASH_RESULT_ERR = 1,
               SPI_FLASH_RESULT_TIMEOUT = 2 } SpiFlashOpResult;

SpiFlashOpResult SPILock();
SpiFlashOpResult SPIUnlock();
SpiFlashOpResult SPIRead(uint32_t addr, void *dst, uint32_t size);
SpiFlashOpResult SPIWrite(uint32_t addr, const uint8_t *src, uint32_t size);
SpiFlashOpResult SPIEraseChip();
SpiFlashOpResult SPIEraseBlock(uint32_t block_num);
SpiFlashOpResult SPIEraseSector(uint32_t sector_num);
uint32_t SPI_read_status();
uint32_t Wait_SPI_Idle();
void spi_flash_attach();

void SelectSpiFunction();
uint32_t SPIParamCfg(uint32_t deviceId, uint32_t chip_size, uint32_t block_size, uint32_t sector_size, uint32_t page_size, uint32_t status_mask);

void ets_isr_mask(uint32_t ints);
void ets_isr_unmask(uint32_t ints);
void ets_set_user_start(void (*user_start_fn)());

void software_reset();
void software_reset_cpu(int cpu_no);

#ifdef ESP32C2  // ESP32C2 ROM uses mbedtls_md5
struct MD5Context {  // Called mbedtls_md5_context in ROM
    uint32_t total[2];        // number of bytes processed
    uint32_t state[4];        // intermediate digest state
    unsigned char buffer[64]; // data block being processed
};

int mbedtls_md5_starts_ret(struct MD5Context *ctx);
int mbedtls_md5_update_ret(struct MD5Context *ctx, const unsigned char *input, size_t ilen);
int mbedtls_md5_finish_ret(struct MD5Context *ctx, unsigned char digest[16]);

#define MD5Init(ctx) mbedtls_md5_starts_ret(ctx)
#define MD5Update(ctx, buf, n) mbedtls_md5_update_ret(ctx, buf, n)
#define MD5Final(digest, ctx) mbedtls_md5_finish_ret(ctx, digest)
#else  // not ESP32C2
struct MD5Context {
    uint32_t buf[4];
    uint32_t bits[2];
    uint8_t in[64];
};

void MD5Init(struct MD5Context *ctx);
void MD5Update(struct MD5Context *ctx, void *buf, uint32_t len);
void MD5Final(uint8_t digest[16], struct MD5Context *ctx);
#endif // not ESP32C2

typedef struct {
    uint32_t device_id;
    uint32_t chip_size;    // chip size in bytes
    uint32_t block_size;
    uint32_t sector_size;
    uint32_t page_size;
    uint32_t status_mask;
} esp_rom_spiflash_chip_t;


typedef void (*int_handler_t)(void *arg);
int_handler_t ets_isr_attach(uint32_t int_num, int_handler_t handler,
                             void *arg);
/* Some ESP32-onwards ROM functions */
#if ESP32_OR_LATER
void uart_tx_flush(int uart);
uint32_t ets_efuse_get_spiconfig(void);

#if ESP32
SpiFlashOpResult esp_rom_spiflash_write_encrypted(uint32_t addr, const uint8_t *src, uint32_t size);
#else
void SPI_Write_Encrypt_Enable();
void SPI_Write_Encrypt_Disable();
SpiFlashOpResult SPI_Encrypt_Write(uint32_t flash_addr, const void* data, uint32_t len);
#endif

#if ESP32S2_OR_LATER
uint32_t GetSecurityInfoProc(int* pMsg, int* pnErr, uint8_t *buf);  // pMsg and pnErr unused in ROM
#if ESP32C3
extern uint32_t _rom_eco_version; // rom constant to define ECO version
uint32_t GetSecurityInfoProcNewEco(int* pMsg, int* pnErr, uint8_t *buf);  // GetSecurityInfo for C3 ECO7+
#endif // ESP32C3
SpiFlashOpResult SPI_read_status_high(esp_rom_spiflash_chip_t *spi, uint32_t *status);
#else
/* Note: On ESP32 this was a static function whose first argument was elided by the
   compiler. */
SpiFlashOpResult SPI_read_status_high(uint32_t *status);
#endif

SpiFlashOpResult SPI_write_status(esp_rom_spiflash_chip_t *spi, uint32_t status_value);

void intr_matrix_set(int cpu_no, uint32_t module_num, uint32_t intr_num);
#endif /* ESP32_OR_LATER */

/* RISC-V-only ROM functions */
#if IS_RISCV
void esprv_intc_int_set_priority(int intr_num, int priority);
#endif // IS_RISCV

/* USB-OTG and USB-JTAG-Serial imports */
#ifdef WITH_USB_OTG
#define ACM_BYTES_PER_TX   64
#define ACM_STATUS_LINESTATE_CHANGED   -1
#define ACM_STATUS_RX                  -4
#define LINE_CTRL_BAUD_RATE   (1 << 0)
#define LINE_CTRL_RTS         (1 << 1)
#define LINE_CTRL_DTR         (1 << 2)
#define LINE_CTRL_DCD         (1 << 3)
#define LINE_CTRL_DSR         (1 << 4)
#define USBDC_PERSIST_ENA  (1<<31)
void usb_dw_isr_handler(void* arg);
typedef void cdc_acm_device;
extern cdc_acm_device *uart_acm_dev;
typedef void(*uart_irq_callback_t)(cdc_acm_device *dev, int status);
void cdc_acm_irq_callback_set(cdc_acm_device *dev, uart_irq_callback_t cb);
void cdc_acm_irq_rx_enable(cdc_acm_device *dev);
void cdc_acm_irq_rx_disable(cdc_acm_device *dev);
int cdc_acm_fifo_read(cdc_acm_device *dev, uint8_t *rx_data, const int size);
int cdc_acm_fifo_fill(cdc_acm_device *dev, const uint8_t *tx_data, int len);
int cdc_acm_line_ctrl_get(cdc_acm_device *dev, uint32_t ctrl, uint32_t *val);
int cdc_acm_rx_fifo_cnt(cdc_acm_device *dev);
void cdc_acm_irq_state_enable(cdc_acm_device *dev);
void usb_dc_check_poll_for_interrupts(void);
void chip_usb_set_persist_flags(uint32_t flags);
int usb_dc_prepare_persist(void);
#endif // WITH_USB_OTG

#if WITH_USB_JTAG_SERIAL || WITH_USB_OTG
typedef struct {
    uint8_t *pRcvMsgBuff;
    uint8_t *pWritePos;
    uint8_t *pReadPos;
    uint8_t  TrigLvl;
    int BuffState;
} RcvMsgBuff;

typedef struct {
    int     baud_rate;
    int     data_bits;
    int     exist_parity;
    int     parity;
    int     stop_bits;
    int     flow_ctrl;
    uint8_t buff_uart_no;
    RcvMsgBuff     rcv_buff;
    int     rcv_state;
    int     received;
} UartDevice;

UartDevice * GetUartDevice();
#endif // WITH_USB_JTAG_SERIAL || WITH_USB_OTG

#if defined(ESP32S3)
#define BIT(nr)                 (1UL << (nr))
#define ESP_ROM_OPIFLASH_SEL_CS0     (BIT(0))

typedef enum {
    SPI_FLASH_QIO_MODE = 0,
    SPI_FLASH_QOUT_MODE,
    SPI_FLASH_DIO_MODE,
    SPI_FLASH_DOUT_MODE,
    SPI_FLASH_FASTRD_MODE,
    SPI_FLASH_SLOWRD_MODE,
    SPI_FLASH_OPI_STR_MODE,
    SPI_FLASH_OPI_DTR_MODE,
    SPI_FLASH_OOUT_MODE,
    SPI_FLASH_OIO_STR_MODE,
    SPI_FLASH_OIO_DTR_MODE,
    SPI_FLASH_QPI_MODE,
} SpiFlashRdMode;

typedef enum {
    ESP_ROM_SPIFLASH_RESULT_OK,
    ESP_ROM_SPIFLASH_RESULT_ERR,
    ESP_ROM_SPIFLASH_RESULT_TIMEOUT
} esp_rom_spiflash_result_t;

#define CMD_RDID                    0x9F
#define CMD_RDSR                    0x05
#define CMD_WREN                    0x06
#define CMD_SECTOR_ERASE            0x20
#define CMD_SECTOR_ERASE_4B         0x21
#define CMD_FSTRD4B                 0x0C
#define CMD_LARGE_BLOCK_ERASE       0xD8
#define CMD_LARGE_BLOCK_ERASE_4B    0xDC
#define CMD_PROGRAM_PAGE_4B         0x12

#define OPIFLASH_DRIVER() {   \
    .rdid = {              \
        .mode = SPI_FLASH_FASTRD_MODE, \
        .cmd_bit_len = 8, \
        .cmd = CMD_RDID, \
        .addr = 0, \
        .addr_bit_len = 0, \
        .dummy_bit_len = 0, \
        .data_bit_len = 24, \
        .cs_sel = 0x1, \
        .is_pe = 0, \
    }, \
    .rdsr = { \
        .mode = SPI_FLASH_FASTRD_MODE, \
        .cmd_bit_len = 8, \
        .cmd = CMD_RDSR, \
        .addr = 0, \
        .addr_bit_len = 0, \
        .dummy_bit_len = 0, \
        .data_bit_len = 8, \
        .cs_sel = 0x1, \
        .is_pe = 0, \
    }, \
    .wren = { \
        .mode = SPI_FLASH_FASTRD_MODE, \
        .cmd_bit_len = 8, \
        .cmd = CMD_WREN, \
        .addr = 0, \
        .addr_bit_len = 0, \
        .dummy_bit_len = 0, \
        .data_bit_len = 0, \
        .cs_sel = 0x1, \
        .is_pe = 0, \
    }, \
    .se = { \
        .mode = SPI_FLASH_FASTRD_MODE, \
        .cmd_bit_len = 8, \
        .cmd = CMD_SECTOR_ERASE_4B, \
        .addr = 0, \
        .addr_bit_len = 32, \
        .dummy_bit_len = 0, \
        .data_bit_len = 0, \
        .cs_sel = 0x1, \
        .is_pe = 1, \
    }, \
    .be64k = { \
        .mode = SPI_FLASH_FASTRD_MODE, \
        .cmd_bit_len = 8, \
        .cmd = CMD_LARGE_BLOCK_ERASE_4B, \
        .addr = 0, \
        .addr_bit_len = 32, \
        .dummy_bit_len = 0, \
        .data_bit_len = 0, \
        .cs_sel = 0x1, \
        .is_pe = 1, \
    }, \
    .read = { \
        .mode = SPI_FLASH_FASTRD_MODE, \
        .cmd_bit_len = 8, \
        .cmd = CMD_FSTRD4B, \
        .addr = 0, \
        .addr_bit_len = 32, \
        .dummy_bit_len = 0, \
        .data_bit_len = 0, \
        .cs_sel = 0x1, \
        .is_pe = 0, \
    }, \
    .pp = { \
        .mode = SPI_FLASH_FASTRD_MODE, \
        .cmd_bit_len = 8, \
        .cmd = CMD_PROGRAM_PAGE_4B, \
        .addr = 0, \
        .addr_bit_len = 32, \
        .dummy_bit_len = 0, \
        .data_bit_len = 0, \
        .cs_sel = 0x1, \
        .is_pe = 1, \
    }, \
    .cache_rd_cmd = { \
        .addr_bit_len = 32, \
        .dummy_bit_len = 20*2, \
        .cmd = CMD_FSTRD4B, \
        .cmd_bit_len = 16, \
        .var_dummy_en = 1, \
    } \
}

#ifndef ESP32S3BETA2
typedef struct {
    uint8_t mode;
    uint8_t cmd_bit_len;
    uint16_t cmd;
    uint32_t addr;
    uint8_t addr_bit_len;
    uint8_t dummy_bit_len;
    uint8_t data_bit_len;
    uint8_t cs_sel: 4;
    uint8_t is_pe: 4;
} esp_rom_opiflash_cmd_t;

typedef struct {
    uint8_t addr_bit_len;
    uint8_t dummy_bit_len;
    uint16_t cmd;
    uint8_t cmd_bit_len;
    uint8_t var_dummy_en;
} esp_rom_opiflash_spi0rd_t;

typedef struct {
    esp_rom_opiflash_cmd_t rdid;
    esp_rom_opiflash_cmd_t rdsr;
    esp_rom_opiflash_cmd_t wren;
    esp_rom_opiflash_cmd_t se;
    esp_rom_opiflash_cmd_t be64k;
    esp_rom_opiflash_cmd_t read;
    esp_rom_opiflash_cmd_t pp;
    esp_rom_opiflash_spi0rd_t cache_rd_cmd;
} esp_rom_opiflash_def_t;

void esp_rom_opiflash_legacy_driver_init(const esp_rom_opiflash_def_t *flash_cmd_def);
bool ets_efuse_flash_octal_mode(void);
#endif //ESP32S3BETA2

void esp_rom_opiflash_exec_cmd(int spi_num, SpiFlashRdMode mode,
    uint32_t cmd, int cmd_bit_len,
    uint32_t addr, int addr_bit_len,
    int dummy_bits,
    uint8_t* mosi_data, int mosi_bit_len,
    uint8_t* miso_data, int miso_bit_len,
    uint32_t cs_mask,
    bool is_write_erase_operation);

esp_rom_spiflash_result_t esp_rom_opiflash_wait_idle();
esp_rom_spiflash_result_t esp_rom_opiflash_wren();
esp_rom_spiflash_result_t esp_rom_opiflash_erase_sector(uint32_t sector_num);
esp_rom_spiflash_result_t esp_rom_opiflash_erase_block_64k(uint32_t block_num);
SpiFlashOpResult SPI_write_enable(esp_rom_spiflash_chip_t *spi);
#endif // ESP32S3
