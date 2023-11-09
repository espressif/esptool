# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
import time

from ..loader import ESPLoader
from ..util import FatalError, NotSupportedError


class ESP32ROM(ESPLoader):
    """Access class for ESP32 ROM bootloader"""

    CHIP_NAME = "ESP32"
    IMAGE_CHIP_ID = 0
    IS_STUB = False

    CHIP_DETECT_MAGIC_VALUE = [0x00F01D83]

    IROM_MAP_START = 0x400D0000
    IROM_MAP_END = 0x40400000

    DROM_MAP_START = 0x3F400000
    DROM_MAP_END = 0x3F800000

    # ESP32 uses a 4 byte status reply
    STATUS_BYTES_LENGTH = 4

    SPI_REG_BASE = 0x3FF42000
    SPI_USR_OFFS = 0x1C
    SPI_USR1_OFFS = 0x20
    SPI_USR2_OFFS = 0x24
    SPI_MOSI_DLEN_OFFS = 0x28
    SPI_MISO_DLEN_OFFS = 0x2C
    EFUSE_RD_REG_BASE = 0x3FF5A000

    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG = EFUSE_RD_REG_BASE + 0x18
    EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT = 1 << 7  # EFUSE_RD_DISABLE_DL_ENCRYPT

    EFUSE_SPI_BOOT_CRYPT_CNT_REG = EFUSE_RD_REG_BASE  # EFUSE_BLK0_WDATA0_REG
    EFUSE_SPI_BOOT_CRYPT_CNT_MASK = 0x7F << 20  # EFUSE_FLASH_CRYPT_CNT

    EFUSE_RD_ABS_DONE_REG = EFUSE_RD_REG_BASE + 0x018
    EFUSE_RD_ABS_DONE_0_MASK = 1 << 4
    EFUSE_RD_ABS_DONE_1_MASK = 1 << 5

    DR_REG_SYSCON_BASE = 0x3FF66000
    APB_CTL_DATE_ADDR = DR_REG_SYSCON_BASE + 0x7C
    APB_CTL_DATE_V = 0x1
    APB_CTL_DATE_S = 31

    SPI_W0_OFFS = 0x80

    UART_CLKDIV_REG = 0x3FF40014

    XTAL_CLK_DIVIDER = 1

    RTCCALICFG1 = 0x3FF5F06C
    TIMERS_RTC_CALI_VALUE = 0x01FFFFFF
    TIMERS_RTC_CALI_VALUE_S = 7

    FLASH_SIZES = {
        "1MB": 0x00,
        "2MB": 0x10,
        "4MB": 0x20,
        "8MB": 0x30,
        "16MB": 0x40,
        "32MB": 0x50,
        "64MB": 0x60,
        "128MB": 0x70,
    }

    FLASH_FREQUENCY = {
        "80m": 0xF,
        "40m": 0x0,
        "26m": 0x1,
        "20m": 0x2,
    }

    BOOTLOADER_FLASH_OFFSET = 0x1000

    OVERRIDE_VDDSDIO_CHOICES = ["1.8V", "1.9V", "OFF"]

    MEMORY_MAP = [
        [0x00000000, 0x00010000, "PADDING"],
        [0x3F400000, 0x3F800000, "DROM"],
        [0x3F800000, 0x3FC00000, "EXTRAM_DATA"],
        [0x3FF80000, 0x3FF82000, "RTC_DRAM"],
        [0x3FF90000, 0x40000000, "BYTE_ACCESSIBLE"],
        [0x3FFAE000, 0x40000000, "DRAM"],
        [0x3FFE0000, 0x3FFFFFFC, "DIRAM_DRAM"],
        [0x40000000, 0x40070000, "IROM"],
        [0x40070000, 0x40078000, "CACHE_PRO"],
        [0x40078000, 0x40080000, "CACHE_APP"],
        [0x40080000, 0x400A0000, "IRAM"],
        [0x400A0000, 0x400BFFFC, "DIRAM_IRAM"],
        [0x400C0000, 0x400C2000, "RTC_IRAM"],
        [0x400D0000, 0x40400000, "IROM"],
        [0x50000000, 0x50002000, "RTC_DATA"],
    ]

    FLASH_ENCRYPTED_WRITE_ALIGN = 32

    UF2_FAMILY_ID = 0x1C5F21B0

    """ Try to read the BLOCK1 (encryption key) and check if it is valid """

    def is_flash_encryption_key_valid(self):
        """Bit 0 of efuse_rd_disable[3:0] is mapped to BLOCK1
        this bit is at position 16 in EFUSE_BLK0_RDATA0_REG"""
        word0 = self.read_efuse(0)
        rd_disable = (word0 >> 16) & 0x1

        # reading of BLOCK1 is NOT ALLOWED so we assume valid key is programmed
        if rd_disable:
            return True
        else:
            # reading of BLOCK1 is ALLOWED so we will read and verify for non-zero.
            # When ESP32 has not generated AES/encryption key in BLOCK1,
            # the contents will be readable and 0.
            # If the flash encryption is enabled it is expected to have a valid
            # non-zero key. We break out on first occurance of non-zero value
            key_word = [0] * 7
            for i in range(len(key_word)):
                key_word[i] = self.read_efuse(14 + i)
                # key is non-zero so break & return
                if key_word[i] != 0:
                    return True
            return False

    def get_flash_crypt_config(self):
        """For flash encryption related commands we need to make sure
        user has programmed all the relevant efuse correctly so before
        writing encrypted write_flash_encrypt esptool will verify the values
        of flash_crypt_config to be non zero if they are not read
        protected. If the values are zero a warning will be printed

        bit 3 in efuse_rd_disable[3:0] is mapped to flash_crypt_config
        this bit is at position 19 in EFUSE_BLK0_RDATA0_REG"""
        word0 = self.read_efuse(0)
        rd_disable = (word0 >> 19) & 0x1

        if rd_disable == 0:
            """we can read the flash_crypt_config efuse value
            so go & read it (EFUSE_BLK0_RDATA5_REG[31:28])"""
            word5 = self.read_efuse(5)
            word5 = (word5 >> 28) & 0xF
            return word5
        else:
            # if read of the efuse is disabled we assume it is set correctly
            return 0xF

    def get_encrypted_download_disabled(self):
        return (
            self.read_reg(self.EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT_REG)
            & self.EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT
        )

    def get_flash_encryption_enabled(self):
        flash_crypt_cnt = (
            self.read_reg(self.EFUSE_SPI_BOOT_CRYPT_CNT_REG)
            & self.EFUSE_SPI_BOOT_CRYPT_CNT_MASK
        )
        # Flash encryption enabled when odd number of bits are set
        return bin(flash_crypt_cnt).count("1") & 1 != 0

    def get_secure_boot_enabled(self):
        efuses = self.read_reg(self.EFUSE_RD_ABS_DONE_REG)
        rev = self.get_chip_revision()
        return efuses & self.EFUSE_RD_ABS_DONE_0_MASK or (
            rev >= 300 and efuses & self.EFUSE_RD_ABS_DONE_1_MASK
        )

    def get_pkg_version(self):
        word3 = self.read_efuse(3)
        pkg_version = (word3 >> 9) & 0x07
        pkg_version += ((word3 >> 2) & 0x1) << 3
        return pkg_version

    def get_chip_revision(self):
        return self.get_major_chip_version() * 100 + self.get_minor_chip_version()

    def get_minor_chip_version(self):
        return (self.read_efuse(5) >> 24) & 0x3

    def get_major_chip_version(self):
        rev_bit0 = (self.read_efuse(3) >> 15) & 0x1
        rev_bit1 = (self.read_efuse(5) >> 20) & 0x1
        apb_ctl_date = self.read_reg(self.APB_CTL_DATE_ADDR)
        rev_bit2 = (apb_ctl_date >> self.APB_CTL_DATE_S) & self.APB_CTL_DATE_V
        combine_value = (rev_bit2 << 2) | (rev_bit1 << 1) | rev_bit0

        revision = {
            0: 0,
            1: 1,
            3: 2,
            7: 3,
        }.get(combine_value, 0)
        return revision

    def get_chip_description(self):
        pkg_version = self.get_pkg_version()
        major_rev = self.get_major_chip_version()
        minor_rev = self.get_minor_chip_version()
        rev3 = major_rev == 3
        single_core = self.read_efuse(3) & (1 << 0)  # CHIP_VER DIS_APP_CPU

        chip_name = {
            0: "ESP32-S0WDQ6" if single_core else "ESP32-D0WDQ6",
            1: "ESP32-S0WD" if single_core else "ESP32-D0WD",
            2: "ESP32-D2WD",
            4: "ESP32-U4WDH",
            5: "ESP32-PICO-V3" if rev3 else "ESP32-PICO-D4",
            6: "ESP32-PICO-V3-02",
            7: "ESP32-D0WDR2-V3",
        }.get(pkg_version, "unknown ESP32")

        # ESP32-D0WD-V3, ESP32-D0WDQ6-V3
        if chip_name.startswith("ESP32-D0WD") and rev3:
            chip_name += "-V3"

        return f"{chip_name} (revision v{major_rev}.{minor_rev})"

    def get_chip_features(self):
        features = ["WiFi"]
        word3 = self.read_efuse(3)

        # names of variables in this section are lowercase
        #  versions of EFUSE names as documented in TRM and
        # ESP-IDF efuse_reg.h

        chip_ver_dis_bt = word3 & (1 << 1)
        if chip_ver_dis_bt == 0:
            features += ["BT"]

        chip_ver_dis_app_cpu = word3 & (1 << 0)
        if chip_ver_dis_app_cpu:
            features += ["Single Core"]
        else:
            features += ["Dual Core"]

        chip_cpu_freq_rated = word3 & (1 << 13)
        if chip_cpu_freq_rated:
            chip_cpu_freq_low = word3 & (1 << 12)
            if chip_cpu_freq_low:
                features += ["160MHz"]
            else:
                features += ["240MHz"]

        pkg_version = self.get_pkg_version()
        if pkg_version in [2, 4, 5, 6]:
            features += ["Embedded Flash"]

        if pkg_version == 6:
            features += ["Embedded PSRAM"]

        word4 = self.read_efuse(4)
        adc_vref = (word4 >> 8) & 0x1F
        if adc_vref:
            features += ["VRef calibration in efuse"]

        blk3_part_res = word3 >> 14 & 0x1
        if blk3_part_res:
            features += ["BLK3 partially reserved"]

        word6 = self.read_efuse(6)
        coding_scheme = word6 & 0x3
        features += [
            "Coding Scheme %s"
            % {0: "None", 1: "3/4", 2: "Repeat (UNSUPPORTED)", 3: "Invalid"}[
                coding_scheme
            ]
        ]

        return features

    def read_efuse(self, n):
        """Read the nth word of the ESP3x EFUSE region."""
        return self.read_reg(self.EFUSE_RD_REG_BASE + (4 * n))

    def chip_id(self):
        raise NotSupportedError(self, "Function chip_id")

    def read_mac(self, mac_type="BASE_MAC"):
        """Read MAC from EFUSE region"""
        if mac_type != "BASE_MAC":
            return None
        words = [self.read_efuse(2), self.read_efuse(1)]
        bitstring = struct.pack(">II", *words)
        bitstring = bitstring[2:8]  # trim the 2 byte CRC
        return tuple(bitstring)

    def get_erase_size(self, offset, size):
        return size

    def override_vddsdio(self, new_voltage):
        new_voltage = new_voltage.upper()
        if new_voltage not in self.OVERRIDE_VDDSDIO_CHOICES:
            raise FatalError(
                "The only accepted VDDSDIO overrides are '1.8V', '1.9V' and 'OFF'"
            )
        RTC_CNTL_SDIO_CONF_REG = 0x3FF48074
        RTC_CNTL_XPD_SDIO_REG = 1 << 31
        RTC_CNTL_DREFH_SDIO_M = 3 << 29
        RTC_CNTL_DREFM_SDIO_M = 3 << 27
        RTC_CNTL_DREFL_SDIO_M = 3 << 25
        # RTC_CNTL_SDIO_TIEH = (1 << 23)
        # not used here, setting TIEH=1 would set 3.3V output,
        # not safe for esptool.py to do
        RTC_CNTL_SDIO_FORCE = 1 << 22
        RTC_CNTL_SDIO_PD_EN = 1 << 21

        reg_val = RTC_CNTL_SDIO_FORCE  # override efuse setting
        reg_val |= RTC_CNTL_SDIO_PD_EN
        if new_voltage != "OFF":
            reg_val |= RTC_CNTL_XPD_SDIO_REG  # enable internal LDO
        if new_voltage == "1.9V":
            reg_val |= (
                RTC_CNTL_DREFH_SDIO_M | RTC_CNTL_DREFM_SDIO_M | RTC_CNTL_DREFL_SDIO_M
            )  # boost voltage
        self.write_reg(RTC_CNTL_SDIO_CONF_REG, reg_val)
        print("VDDSDIO regulator set to %s" % new_voltage)

    def read_flash_slow(self, offset, length, progress_fn):
        BLOCK_LEN = 64  # ROM read limit per command (this limit is why it's so slow)

        data = b""
        while len(data) < length:
            block_len = min(BLOCK_LEN, length - len(data))
            r = self.check_command(
                "read flash block",
                self.ESP_READ_FLASH_SLOW,
                struct.pack("<II", offset + len(data), block_len),
            )
            if len(r) < block_len:
                raise FatalError(
                    "Expected %d byte block, got %d bytes. Serial errors?"
                    % (block_len, len(r))
                )
            # command always returns 64 byte buffer,
            # regardless of how many bytes were actually read from flash
            data += r[:block_len]
            if progress_fn and (len(data) % 1024 == 0 or len(data) == length):
                progress_fn(len(data), length)
        return data

    def get_rom_cal_crystal_freq(self):
        """
        Get the crystal frequency calculated by the ROM
        """
        # - Simulate the calculation in the ROM to get the XTAL frequency
        #   calculated by the ROM

        cali_val = (
            self.read_reg(self.RTCCALICFG1) >> self.TIMERS_RTC_CALI_VALUE_S
        ) & self.TIMERS_RTC_CALI_VALUE
        clk_8M_freq = self.read_efuse(4) & (0xFF)  # EFUSE_RD_CK8M_FREQ
        rom_calculated_freq = cali_val * 15625 * clk_8M_freq / 40
        return rom_calculated_freq

    def change_baud(self, baud):
        assert self.CHIP_NAME == "ESP32", "This workaround should only apply to ESP32"
        # It's a workaround to avoid esp32 CK_8M frequency drift.
        rom_calculated_freq = self.get_rom_cal_crystal_freq()
        valid_freq = 40000000 if rom_calculated_freq > 33000000 else 26000000
        false_rom_baud = int(baud * rom_calculated_freq // valid_freq)

        print(f"Changing baud rate to {baud}")
        self.command(self.ESP_CHANGE_BAUDRATE, struct.pack("<II", false_rom_baud, 0))
        print("Changed.")
        self._set_port_baudrate(baud)
        time.sleep(0.05)  # get rid of garbage sent during baud rate change
        self.flush_input()

    def check_spi_connection(self, spi_connection):
        # Pins 30, 31 do not exist
        if not set(spi_connection).issubset(set(range(0, 30)) | set((32, 33))):
            raise FatalError("SPI Pin numbers must be in the range 0-29, 32, or 33.")


class ESP32StubLoader(ESP32ROM):
    """Access class for ESP32 stub loader, runs on top of ROM."""

    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self.secure_download_mode = rom_loader.secure_download_mode
        self._port = rom_loader._port
        self._trace_enabled = rom_loader._trace_enabled
        self.cache = rom_loader.cache
        self.flush_input()  # resets _slip_reader

    def change_baud(self, baud):
        ESPLoader.change_baud(self, baud)


ESP32ROM.STUB_CLASS = ESP32StubLoader
