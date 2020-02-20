#!/usr/bin/env python
# This file describes eFuses for ESP32 chip
#
# Copyright (C) 2020 Espressif Systems (Shanghai) PTE LTD
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.
from __future__ import division, print_function

import struct
import time
import esptool
from .. import base_fields
from .. import util


class EfuseBlock(base_fields.EfuseBlockBase):
    def len_of_burn_unit(self):
        # The writing register window is the same as len of a block.
        return self.len

    def __init__(self, parent, param, skip_read=False):
        if skip_read:
            parent.coding_scheme = parent.CODING_SCHEME_NONE
        else:
            if parent.coding_scheme is None:
                parent.read_coding_scheme()
        super(EfuseBlock, self).__init__(parent, param, skip_read=skip_read)

    def apply_coding_scheme(self):
        data = self.get_raw(from_read=False)[::-1]
        if self.get_coding_scheme() == self.parent.CODING_SCHEME_34:
            # CODING_SCHEME 3/4 applied only for BLK1..3
            # Takes 24 byte sequence to be represented in 3/4 encoding,
            # returns 8 words suitable for writing "encoded" to an efuse block
            if len(data) != 24:
                raise esptool.FatalError("Should take 24 bytes for 3/4 encoding.")
            data = data[:24]
            outbits = b""
            while len(data) > 0:  # process in chunks of 6 bytes
                bits = data[0:6]
                data = data[6:]
                xor_res = 0
                mul_res = 0
                index = 1
                for b in struct.unpack("B" * 6, bits):
                    xor_res ^= b
                    mul_res += index * util.popcnt(b)
                    index += 1
                outbits += bits
                outbits += struct.pack("BB", xor_res, mul_res)
            words = struct.unpack("<" + "I" * (len(outbits) // 4), outbits)
            # returns 8 words
        else:
            # CODING_SCHEME NONE applied for BLK0 and BLK1..3
            # BLK0 len = 7 words, BLK1..3 len = 8 words.
            words = struct.unpack("<" + ("I" * (len(data) // 4)), data)
            # returns 7 words for BLK0 or 8 words for BLK1..3
        return words


class EspEfuses(base_fields.EspEfusesBase):
    """
    Wrapper object to manage the efuse fields in a connected ESP bootloader
    """

    # List of efuse blocks
    # Name, Alias, Index, Read address, Write address, Write protect bit, Read protect bit, Len, key_purpose
    _BLOCKS = [
        ("BLK0",    None,                  0, 0x6001A000, 0x3FF5A01C, None, None, 7,                None),
        ("BLK1",    "flash_encryption",    1, 0x6001A038, 0x3FF5A098, 7,    0,    8,                None),
        ("BLK2",    "secure_boot",         2, 0x6001A058, 0x3FF5A0B8, 8,    1,    8,                None),
        ("BLK3",    None,                  3, 0x6001A078, 0x3FF5A0D8, 9,    2,    8,                None),
    ]

    BURN_BLOCK_DATA_NAMES = []
    for block in _BLOCKS:
        if block[0]:
            BURN_BLOCK_DATA_NAMES.append(block[0])

    BLOCKS_FOR_KEYS = []
    for block in _BLOCKS:
        if block[2] > 0:
            if block[0]:
                BLOCKS_FOR_KEYS.append(block[0])
            if block[1]:
                BLOCKS_FOR_KEYS.append(block[1])

    # Lists of efuse fields
    _EFUSES = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('WR_DIS',               "efuse",       0, 0, 0,   "uint:16",   1,    None, None,       "Efuse write disable mask", None),
        ('RD_DIS',               "efuse",       0, 0, 16,  "uint:4",    0,    None, None,       "Efuse read disable mask", None),
        ('CODING_SCHEME',        "efuse",       0, 6, 0,   "uint:2",    10,   3,    None,       "Efuse variable block length scheme",
            {0:"NONE (BLK1-3 len=256 bits)", 1:"3/4 (BLK1-3 len=192 bits)", 2:"REPEAT (BLK1-3 len=128 bits) not supported", 3:"NONE (BLK1-3 len=256 bits)"}),
        ('KEY_STATUS',           "efuse",       0, 6, 10,  "bool",      10,   3,    None,       "Usage of efuse block 3 (reserved)", None),
        ('MAC',                  "identity",    0, 1, 0,   "bytes:6",   3,    None, "mac",      "Factory MAC Address", None),
        ('MAC_CRC',              "identity",    0, 2, 16,  "uint:8",    3,    None, None,       "CRC8 for factory MAC address", None),
        ('CHIP_VER_REV1',        "identity",    0, 3, 15,  "bool",      3,    None, None,       "Silicon Revision 1", None),
        ('CHIP_VER_REV2',        "identity",    0, 5, 20,  "bool",      6,    None, None,       "Silicon Revision 2", None),
        ('CHIP_VERSION',         "identity",    0, 3, 12,  "uint:2",    3,    None, None,       "Reserved for future chip versions", None),
        ('CHIP_PACKAGE',         "identity",    0, 3, 9,   "uint:3",    3,    None, None,       "Chip package identifier", None),
        ('XPD_SDIO_FORCE',       "config",      0, 4, 16,  "bool",      5,    None, None,       "Ignore MTDI pin (GPIO12) for VDD_SDIO on reset", None),
        ('XPD_SDIO_REG',         "config",      0, 4, 14,  "bool",      5,    None, None,       "If XPD_SDIO_FORCE, enable VDD_SDIO reg on reset", None),
        ('XPD_SDIO_TIEH',        "config",      0, 4, 15,  "bool",      5,    None, None,       "If XPD_SDIO_FORCE & XPD_SDIO_REG", {1:"3.3V", 0:"1.8V"}),
        ('CLK8M_FREQ',           "config",      0, 4, 0,   "uint:8",    None, None, None,       "8MHz clock freq override", None),
        ('SPI_PAD_CONFIG_CLK',   "config",      0, 5, 0,   "uint:5",    6,    None, "spipin",   "Override SD_CLK pad (GPIO6/SPICLK)", None),
        ('SPI_PAD_CONFIG_Q',     "config",      0, 5, 5,   "uint:5",    6,    None, "spipin",   "Override SD_DATA_0 pad (GPIO7/SPIQ)", None),
        ('SPI_PAD_CONFIG_D',     "config",      0, 5, 10,  "uint:5",    6,    None, "spipin",   "Override SD_DATA_1 pad (GPIO8/SPID)", None),
        ('SPI_PAD_CONFIG_HD',    "config",      0, 3, 4,   "uint:5",    6,    None, "spipin",   "Override SD_DATA_2 pad (GPIO9/SPIHD)", None),
        ('SPI_PAD_CONFIG_CS0',   "config",      0, 5, 15,  "uint:5",    6,    None, "spipin",   "Override SD_CMD pad (GPIO11/SPICS0)", None),
        ('DISABLE_SDIO_HOST',    "config",      0, 6, 3,   "bool",      None, None, None,       "Disable SDIO host", None),
        ('FLASH_CRYPT_CNT',      "security",    0, 0, 20,  "uint:7",    2,    None, "bitcount", "Flash encryption mode counter", None),
        ('UART_DOWNLOAD_DIS',    "security",    0, 0, 27,  "bool",      2,    None, None,       "Disable UART download mode (ESP32 rev3 only)", None),
        ('FLASH_CRYPT_CONFIG',   "security",    0, 5, 28,  "uint:4",    10,   3,    None,       "Flash encryption config (key tweak bits)", None),
        ('CONSOLE_DEBUG_DISABLE',"security",    0, 6, 2,   "bool",      15,   None, None,       "Disable ROM BASIC interpreter fallback", None),
        ('ABS_DONE_0',           "security",    0, 6, 4,   "bool",      12,   None, None,       "secure boot enabled for bootloader", None),
        ('ABS_DONE_1',           "security",    0, 6, 5,   "bool",      13,   None, None,       "secure boot abstract 1 locked", None),
        ('JTAG_DISABLE',         "security",    0, 6, 6,   "bool",      14,   None, None,       "Disable JTAG", None),
        ('DISABLE_DL_ENCRYPT',   "security",    0, 6, 7,   "bool",      15,   None, None,       "Disable flash encryption in UART bootloader", None),
        ('DISABLE_DL_DECRYPT',   "security",    0, 6, 8,   "bool",      15,   None, None,       "Disable flash decryption in UART bootloader", None),
        ('DISABLE_DL_CACHE',     "security",    0, 6, 9,   "bool",      15,   None, None,       "Disable flash cache in UART bootloader", None),
        ('BLK3_PART_RESERVE',    "calibration", 0, 3, 14,  "bool",      10,   3,    None,       "BLOCK3 partially served for ADC calibration data", None),
        ('ADC_VREF',             "calibration", 0, 4, 8,   "uint:5",    0,    None, "vref",     "Voltage reference calibration", None),
        ('MAC_VERSION',          "identity",    3, 5, 24,  "uint:8",    9,    2,    None,       "Version of the MAC field", {1:"Custom MAC in BLK3"}),
    ]

    # if MAC_VERSION is set "1", these efuse fields are in BLK3:
    _CUSTOM_MAC = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('CUSTOM_MAC',           "identity",    3, 0, 8,   "bytes:6",   9,    2,   "mac",       "Custom MAC", None),
        ('CUSTOM_MAC_CRC',       "identity",    3, 0, 0,   "uint:8",    9,    2,    None,       "CRC of custom MAC", None),
    ]

    # The len of fields depends on coding scheme: for CODING_SCHEME_NONE
    _KEYBLOCKS_256 = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('BLK1',                 "security",    1, 0, 0,   "bytes:32", 7,    0,    "keyblock", "Flash encryption key", None),
        ('BLK2',                 "security",    2, 0, 0,   "bytes:32", 8,    1,    "keyblock", "Secure boot key", None),
        ('BLK3',                 "security",    3, 0, 0,   "bytes:32", 9,    2,    "keyblock", "Variable Block 3", None),
    ]

    # The len of fields depends on coding scheme: for CODING_SCHEME_34
    _KEYBLOCKS_192 = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('BLK1',                 "security",    1, 0, 0,   "bytes:24", 7,    0,    "keyblock", "Flash encryption key", None),
        ('BLK2',                 "security",    2, 0, 0,   "bytes:24", 8,    1,    "keyblock", "Secure boot key", None),
        ('BLK3',                 "security",    3, 0, 0,   "bytes:24", 9,    2,    "keyblock", "Variable Block 3", None),
    ]

    # if BLK3_PART_RESERVE is set, these efuse fields are in BLK3:
    _ADC_CALIBRATION = [
        # Name                   Category  Block Word Pos  Type:len   WR_DIS RD_DIS Class       Description                Dictionary
        ('ADC1_TP_LOW',          "calibration", 3, 3, 0,   "uint:7",    9,    2,    "adc_tp",   "ADC1 150mV reading", None),
        ('ADC1_TP_HIGH',         "calibration", 3, 3, 7,   "uint:9",    9,    2,    "adc_tp",   "ADC1 850mV reading", None),
        ('ADC2_TP_LOW',          "calibration", 3, 3, 16,  "uint:7",    9,    2,    "adc_tp",   "ADC2 150mV reading", None),
        ('ADC2_TP_HIGH',         "calibration", 3, 3, 23,  "uint:9",    9,    2,    "adc_tp",   "ADC2 850mV reading", None),
    ]

    # EFUSE registers & command/conf values
    EFUSE_REG_CONF = 0x3FF5A0FC
    EFUSE_CONF_WRITE = 0x5A5A
    EFUSE_CONF_READ = 0x5AA5
    EFUSE_REG_CMD  = 0x3FF5A104
    EFUSE_CMD_WRITE = 0x2
    EFUSE_CMD_READ  = 0x1

    # 3/4 Coding scheme warnings registers
    EFUSE_REG_DEC_STATUS = 0x3FF5A11C
    EFUSE_REG_DEC_STATUS_MASK = 0xFFF

    # Efuse clock control
    EFUSE_DAC_CONF_REG = 0x3FF5A118
    EFUSE_CLK_REG = 0x3FF5A0F8
    EFUSE_DAC_CLK_DIV_MASK = 0xFF
    EFUSE_CLK_SEL0_MASK = 0x00FF
    EFUSE_CLK_SEL1_MASK = 0xFF00

    EFUSE_CLK_SETTINGS = {
        # APB freq: clk_sel0, clk_sel1, dac_clk_div
        # Taken from TRM chapter "eFuse Controller": Timing Configuration
        26: (250, 255, 52),
        40: (160, 255, 80),
        80: (80, 128, 100),  # this is here for completeness only as esptool never sets an 80MHz APB clock
    }

    EFUSE_BURN_TIMEOUT = 0.250  # seconds

    debug = False
    do_not_confirm = False

    def __init__(self, esp, skip_connect=False, debug=False, do_not_confirm=False):
        self._esp = esp
        self.debug = debug
        self.do_not_confirm = do_not_confirm
        if esp is not None and type(esp) is not esptool.ESP32ROM:
            raise esptool.FatalError("The eFuse module describes ESP32 chip. Check the chip setting for esptool, it gives '%s' name." % (esp.CHIP_NAME))
        self.blocks = [EfuseBlock(self, block, skip_read=skip_connect) for block in self._BLOCKS]
        self.efuses = [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._EFUSES]
        if skip_connect:
            self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._KEYBLOCKS_256]
            self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._CUSTOM_MAC]
            self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._ADC_CALIBRATION]
        else:
            if self.coding_scheme == self.CODING_SCHEME_NONE:
                self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._KEYBLOCKS_256]
            elif self.coding_scheme == self.CODING_SCHEME_34:
                self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._KEYBLOCKS_192]
            else:
                raise esptool.FatalError("The coding scheme (%d) - is not supported" % self.coding_scheme)
            if self["MAC_VERSION"].get() == 1:
                self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._CUSTOM_MAC]
            if self["BLK3_PART_RESERVE"].get():
                self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._ADC_CALIBRATION]

    def __getitem__(self, efuse_name):
        """ Return the efuse field with the given name """
        for e in self.efuses:
            if efuse_name == e.name:
                return e
        new_fields = False
        for efuse in self._CUSTOM_MAC:
            if efuse[0] == efuse_name:
                self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._CUSTOM_MAC]
                new_fields = True
        for efuse in self._ADC_CALIBRATION:
            if efuse[0] == efuse_name:
                self.efuses += [EfuseField.from_tuple(self, efuse, efuse[8]) for efuse in self._ADC_CALIBRATION]
                new_fields = True
        if new_fields:
            for e in self.efuses:
                if efuse_name == e.name:
                    return e
        raise KeyError

    def read_coding_scheme(self):
        self.coding_scheme = self._esp.read_efuse(6) & 0x3

    def write_efuses(self, block):
        """ Write the values in the efuse write registers to
        the efuse hardware, then refresh the efuse read registers.
        """

        # Configure clock
        apb_freq = self._esp.get_crystal_freq()
        clk_sel0, clk_sel1, dac_clk_div = self.EFUSE_CLK_SETTINGS[apb_freq]

        self.update_reg(self.EFUSE_DAC_CONF_REG, self.EFUSE_DAC_CLK_DIV_MASK, dac_clk_div)
        self.update_reg(self.EFUSE_CLK_REG, self.EFUSE_CLK_SEL0_MASK, clk_sel0)
        self.update_reg(self.EFUSE_CLK_REG, self.EFUSE_CLK_SEL1_MASK, clk_sel1)

        self.write_reg(self.EFUSE_REG_CONF, self.EFUSE_CONF_WRITE)
        self.write_reg(self.EFUSE_REG_CMD, self.EFUSE_CMD_WRITE)

        def wait_idle():
            deadline = time.time() + self.EFUSE_BURN_TIMEOUT
            while time.time() < deadline:
                if self.read_reg(self.EFUSE_REG_CMD) == 0:
                    return
            raise esptool.FatalError("Timed out waiting for Efuse controller command to complete")
        wait_idle()
        self.write_reg(self.EFUSE_REG_CONF, self.EFUSE_CONF_READ)
        self.write_reg(self.EFUSE_REG_CMD, self.EFUSE_CMD_READ)
        wait_idle()
        return self.get_coding_scheme_warnings()

    def get_coding_scheme_warnings(self):
        """ Check if the coding scheme has detected any errors.
        Meaningless for default coding scheme (0)
        """
        return self.read_reg(self.EFUSE_REG_DEC_STATUS) & self.EFUSE_REG_DEC_STATUS_MASK

    def summary(self):
        if self["XPD_SDIO_FORCE"].get() == 0:
            output = "Flash voltage (VDD_SDIO) determined by GPIO12 on reset (High for 1.8V, Low/NC for 3.3V)."
        elif self["XPD_SDIO_REG"].get() == 0:
            output = "Flash voltage (VDD_SDIO) internal regulator disabled by efuse."
        elif self["XPD_SDIO_TIEH"].get() == 0:
            output = "Flash voltage (VDD_SDIO) set to 1.8V by efuse."
        else:
            output = "Flash voltage (VDD_SDIO) set to 3.3V by efuse."
        return output


class EfuseField(base_fields.EfuseFieldBase):
    @staticmethod
    def from_tuple(parent, efuse_tuple, category):
        return {
            "mac":      EfuseMacField,
            "spipin":   EfuseSpiPinField,
            "vref":     EfuseVRefField,
            "adc_tp":   EfuseAdcPointCalibration,
        }.get(category, EfuseField)(parent, *efuse_tuple)

    def get_info(self):
        return "%s (BLOCK%d):" % (self.name, self.block)


class EfuseMacField(EfuseField):
    """
    Supports: MAC and CUSTOM_MAC fields.
    (if MAC_VERSION == 1 then the CUSTOM_MAC is used)
    """

    def check_format(self, new_value_str):
        if new_value_str is None:
            raise esptool.FatalError("Required MAC Address in AB:CD:EF:01:02:03 format!")
        if new_value_str.count(":") != 5:
            raise esptool.FatalError("MAC Address needs to be a 6-byte hexadecimal format separated by colons (:)!")
        hexad = new_value_str.replace(":", "")
        if len(hexad) != 12:
            raise esptool.FatalError("MAC Address needs to be a 6-byte hexadecimal number (12 hexadecimal characters)!")
        # order of bytearray = b'\xab\xcd\xef\x01\x02\x03',
        return hexad.decode("hex")

    @staticmethod
    def get_and_check(raw_mac, stored_crc):
        computed_crc = EfuseMacField.calc_crc(raw_mac)
        if computed_crc == stored_crc:
            valid_msg = "(CRC 0x%02x OK)" % stored_crc
        else:
            valid_msg = "(CRC 0x%02x invalid - calculated 0x%02x)" % (stored_crc, computed_crc)
        return "%s %s" % (util.hexify(raw_mac, ":"), valid_msg)

    @staticmethod
    def calc_crc(raw_mac):
        """
        This algorithm is the equivalent of esp_crc8() in ESP32 ROM code

        This is CRC-8 w/ inverted polynomial value 0x8C & initial value 0x00.
        """
        result = 0x00
        for b in struct.unpack("B" * 6, raw_mac):
            result ^= b
            for _ in range(8):
                lsb = result & 1
                result >>= 1
                if lsb != 0:
                    result ^= 0x8c
        return result

    def get(self, from_read=True):
        if self.name == "CUSTOM_MAC":
            mac = self.get_raw(from_read)[::-1]
            stored_crc = self.parent["CUSTOM_MAC_CRC"].get(from_read)
        else:
            mac = self.get_raw(from_read)
            stored_crc = self.parent["MAC_CRC"].get(from_read)
        return EfuseMacField.get_and_check(mac, stored_crc)

    def save(self, new_value):
        def print_field(e, new_value):
            print("    - '{}' ({}) {} -> {}".format(e.name, e.description, e.get_bitstring(), new_value))

        if self.name == "CUSTOM_MAC":
            # Writing the BLK3:
            #  - MAC_VERSION = 1
            #  - CUSTOM_MAC = AB:CD:EF:01:02:03
            #  - CUSTOM_MAC_CRC = crc8(CUSTOM_MAC)
            mac_version = self.parent["MAC_VERSION"]
            if mac_version.get() == 0:
                mac_version_value = 1
                print_field(mac_version, hex(mac_version_value))
                mac_version.save(mac_version_value)
            else:
                if mac_version.get() != 1:
                    if not self.parent.force_write_always:
                        raise esptool.FatalError("MAC_VERSION = {}, should be 0 or 1.".format(mac_version.get()))

            bitarray_mac = self.convert_to_bitstring(new_value)
            print_field(self, bitarray_mac)
            super(EfuseMacField, self).save(new_value)

            crc_val = self.calc_crc(new_value)
            crc_field = self.parent["CUSTOM_MAC_CRC"]
            print_field(crc_field, hex(crc_val))
            crc_field.save(crc_val)
        else:
            # Writing the BLK0 default MAC is not sensible, as it's written in the factory.
            raise esptool.FatalError("Writing Factory MAC address is not supported")


class EfuseSpiPinField(EfuseField):
    def get(self, from_read=True):
        val = self.get_raw(from_read)
        if val >= 30:
            val += 2  # values 30,31 map to 32, 33
        return val

    def save(self, new_value):
        if new_value in [30, 31]:
            raise esptool.FatalError("IO pins 30 & 31 cannot be set for SPI flash. 0-29, 32 & 33 only.")
        if new_value > 33:
            raise esptool.FatalError("IO pin %d cannot be set for SPI flash. 0-29, 32 & 33 only." % new_value)
        if new_value > 30:
            new_value -= 2  # values 32,33 map to 30, 31
        super(EfuseSpiPinField, self).save(new_value)


class EfuseVRefField(EfuseField):
    VREF_OFFSET = 1100  # ideal efuse value in mV
    VREF_STEP_SIZE = 7  # 1 count in efuse == 7mV
    VREF_SIGN_BIT = 0x10
    VREF_MAG_BITS = 0x0F

    def get(self, from_read=True):
        val = self.get_raw(from_read)
        # sign-magnitude format
        if (val & self.VREF_SIGN_BIT):
            val = -(val & self.VREF_MAG_BITS)
        else:
            val = (val & self.VREF_MAG_BITS)
        val *= self.VREF_STEP_SIZE
        return self.VREF_OFFSET + val

    def save(self, new_value):
        raise esptool.FatalError("Writing to VRef is not supported.")


class EfuseAdcPointCalibration(EfuseField):
    TP_OFFSET = {  # See TP_xxxx_OFFSET in esp_adc_cal.c in ESP-IDF
        "ADC1_TP_LOW":  278,
        "ADC2_TP_LOW":  421,
        "ADC1_TP_HIGH": 3265,
        "ADC2_TP_HIGH": 3406,
    }
    SIGN_BIT = (0x40, 0x100)  # LOW, HIGH (2s complement format)
    STEP_SIZE = 4

    def get(self, from_read=True):
        idx = 0 if self.name.endswith("LOW") else 1
        sign_bit = self.SIGN_BIT[idx]
        offset = self.TP_OFFSET[self.name]
        raw = self.get_raw()
        delta = (raw & (sign_bit - 1)) - (raw & sign_bit)
        return offset + (delta * self.STEP_SIZE)
