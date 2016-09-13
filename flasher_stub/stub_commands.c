#include "stub_commands.h"
#include "stub_flasher.h"
#include "rom_functions.h"
#include "slip.h"
#include "soc_support.h"

int handle_flash_erase(uint32_t addr, uint32_t len) {
  if (addr % FLASH_SECTOR_SIZE != 0) return 0x32;
  if (len % FLASH_SECTOR_SIZE != 0) return 0x33;
  if (SPIUnlock() != 0) return 0x34;

  while (len > 0 && (addr % FLASH_BLOCK_SIZE != 0)) {
    if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  while (len > FLASH_BLOCK_SIZE) {
    if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
    len -= FLASH_BLOCK_SIZE;
    addr += FLASH_BLOCK_SIZE;
  }

  while (len > 0) {
    if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  return 0;
}

void handle_flash_read(uint32_t addr, uint32_t len, uint32_t block_size,
                  uint32_t max_in_flight) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  uint32_t num_sent = 0, num_acked = 0;

  /* This is one routine where we still do synchronous I/O */
  ets_isr_mask(1 << ETS_UART0_INUM);

  if (block_size > sizeof(buf)) {
	return;
  }
  MD5Init(&ctx);
  while (num_acked < len && num_acked <= num_sent) {
    while (num_sent < len && num_sent - num_acked < max_in_flight) {
      uint32_t n = len - num_sent;
      if (n > block_size) n = block_size;
      if (SPIRead(addr, (uint32_t *)buf, n) != 0) {
		break;
	  }
      SLIP_send(buf, n);
      MD5Update(&ctx, buf, n);
      addr += n;
      num_sent += n;
    }
	int r = SLIP_recv(&num_acked, sizeof(num_acked));
	if (r != 4) {
	  break;
	}
  }
  MD5Final(digest, &ctx);
  SLIP_send(digest, sizeof(digest));

  /* Go back to async UART */
  ets_isr_unmask(1 << ETS_UART0_INUM);
}

int handle_flash_get_md5sum(uint32_t addr, uint32_t len) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  MD5Init(&ctx);
  while (len > 0) {
    uint32_t n = len;
    if (n > FLASH_SECTOR_SIZE) n = FLASH_SECTOR_SIZE;
    if (SPIRead(addr, (uint32_t *)buf, n) != 0) return 0x63;
    MD5Update(&ctx, buf, n);
    addr += n;
    len -= n;
  }
  MD5Final(digest, &ctx);
  /* ESP32 ROM sends as hex, but we just send a raw bytes - esptool.py can handle either. */
  SLIP_send_frame_data_buf(digest, sizeof(digest));
  return 0;
}

int handle_flash_read_chip_id() {
  uint32_t chip_id = 0;
  WRITE_PERI_REG(SPI_CMD_REG(0), SPI_FLASH_RDID);
  while (READ_PERI_REG(SPI_CMD_REG(0)) & SPI_FLASH_RDID) {
  }
  chip_id = READ_PERI_REG(SPI_W0_REG(0)) & 0xFFFFFF;
  SLIP_send_frame_data_buf(&chip_id, sizeof(chip_id));
  return 0;
}

esp_command_error handle_spi_set_params(uint32_t *args, int *status)
{
  *status = SPIParamCfg(args[0], args[1], args[2], args[3], args[4], args[5]);
  return *status ? ESP_FAILED_SPI_OP : ESP_OK;
}

esp_command_error handle_spi_attach(bool isHspi, bool isLegacy)
{
#ifdef ESP8266
	    /* ESP8266 doesn't yet support SPI flash on HSPI, but could:
		 see https://github.com/themadinventor/esptool/issues/98 */
	    SelectSpiFunction();
#else
		/* spi_flash_attach calls SelectSpiFunction() and another
		   function to initialise SPI flash interface. */
		spi_flash_attach(isHspi, isLegacy);
#endif
		return ESP_OK; /* neither function/attach command takes an arg */
}

