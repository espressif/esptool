# This file describes eFuses for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import binascii
import struct
import time

import esptool
from esptool import log

from .mem_definition import EfuseDefineBlocks, EfuseDefineFields, EfuseDefineRegisters
from .. import base_fields
from .. import util


class EfuseBlock(base_fields.EfuseBlockBase):
    def len_of_burn_unit(self):
        # The writing register window is the same as len of a block.
        return self.len

    def __init__(self, parent, param, skip_read=False):
        if skip_read:
            parent.coding_scheme = parent.REGS.CODING_SCHEME_NONE
        else:
            if parent.coding_scheme is None:
                parent.read_coding_scheme()
        super().__init__(parent, param, skip_read=skip_read)

    def apply_coding_scheme(self):
        data = self.get_raw(from_read=False)[::-1]
        if self.get_coding_scheme() == self.parent.REGS.CODING_SCHEME_34:
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

    def __init__(
        self,
        esp,
        skip_connect=False,
        debug=False,
        do_not_confirm=False,
        extend_efuse_table=None,
    ):
        super().__init__(esp, skip_connect, debug, do_not_confirm, extend_efuse_table)
        self.Blocks = EfuseDefineBlocks()
        self.Fields = EfuseDefineFields(extend_efuse_table)
        self.REGS = EfuseDefineRegisters
        self.BURN_BLOCK_DATA_NAMES = self.Blocks.get_burn_block_data_names()
        self.BLOCKS_FOR_KEYS = self.Blocks.get_blocks_for_keys()
        if esp.CHIP_NAME != "ESP32":
            raise esptool.FatalError(
                f"Expected the 'esp' param for ESP32 chip but got for '{esp.CHIP_NAME}'."
            )
        self.blocks = [
            EfuseBlock(self, self.Blocks.get(block), skip_read=skip_connect)
            for block in self.Blocks.BLOCKS
        ]
        if not skip_connect:
            self.get_coding_scheme_warnings()
        self.efuses = [EfuseField.convert(self, efuse) for efuse in self.Fields.EFUSES]
        if skip_connect:
            self.efuses += [
                EfuseField.convert(self, efuse) for efuse in self.Fields.KEYBLOCKS_256
            ]
            self.efuses += [
                EfuseField.convert(self, efuse) for efuse in self.Fields.CUSTOM_MAC
            ]
            self.efuses += [
                EfuseField.convert(self, efuse) for efuse in self.Fields.ADC_CALIBRATION
            ]
        else:
            if self.coding_scheme == self.REGS.CODING_SCHEME_NONE:
                self.efuses += [
                    EfuseField.convert(self, efuse)
                    for efuse in self.Fields.KEYBLOCKS_256
                ]
            elif self.coding_scheme == self.REGS.CODING_SCHEME_34:
                self.efuses += [
                    EfuseField.convert(self, efuse)
                    for efuse in self.Fields.KEYBLOCKS_192
                ]
            else:
                raise esptool.FatalError(
                    f"The coding scheme ({self.coding_scheme}) - is not supported"
                )
            if self["MAC_VERSION"].get() == 1:
                self.efuses += [
                    EfuseField.convert(self, efuse) for efuse in self.Fields.CUSTOM_MAC
                ]
            if self["BLK3_PART_RESERVE"].get():
                self.efuses += [
                    EfuseField.convert(self, efuse)
                    for efuse in self.Fields.ADC_CALIBRATION
                ]
            self.efuses += [
                EfuseField.convert(self, efuse) for efuse in self.Fields.CALC
            ]

    def __getitem__(self, efuse_name):
        """Return the efuse field with the given name"""
        for e in self.efuses:
            if efuse_name == e.name or any(x == efuse_name for x in e.alt_names):
                return e
        new_fields = False
        for efuse in self.Fields.CUSTOM_MAC:
            if efuse.name == efuse_name or any(
                x == efuse_name for x in efuse.alt_names
            ):
                self.efuses += [
                    EfuseField.convert(self, efuse) for efuse in self.Fields.CUSTOM_MAC
                ]
                new_fields = True
        for efuse in self.Fields.ADC_CALIBRATION:
            if efuse.name == efuse_name or any(
                x == efuse_name for x in efuse.alt_names
            ):
                self.efuses += [
                    EfuseField.convert(self, efuse)
                    for efuse in self.Fields.ADC_CALIBRATION
                ]
                new_fields = True
        if new_fields:
            for e in self.efuses:
                if efuse_name == e.name or any(x == efuse_name for x in e.alt_names):
                    return e
        raise KeyError

    def read_coding_scheme(self):
        coding_scheme = (
            self.read_efuse(self.REGS.EFUSE_CODING_SCHEME_WORD)
            & self.REGS.EFUSE_CODING_SCHEME_MASK
        )
        if coding_scheme == self.REGS.CODING_SCHEME_NONE_RECOVERY:
            self.coding_scheme = self.REGS.CODING_SCHEME_NONE
        else:
            self.coding_scheme = coding_scheme

    def print_status_regs(self):
        log.print("")
        log.print(
            "{:27} 0x{:08x}".format(
                "EFUSE_REG_DEC_STATUS", self.read_reg(self.REGS.EFUSE_REG_DEC_STATUS)
            )
        )

    def write_efuses(self, block):
        """Write the values in the efuse write registers to
        the efuse hardware, then refresh the efuse read registers.
        """

        # Configure clock
        apb_freq = self.get_crystal_freq()
        clk_sel0, clk_sel1, dac_clk_div = self.REGS.EFUSE_CLK_SETTINGS[apb_freq]

        self.update_reg(
            self.REGS.EFUSE_DAC_CONF_REG, self.REGS.EFUSE_DAC_CLK_DIV_MASK, dac_clk_div
        )
        self.update_reg(
            self.REGS.EFUSE_CLK_REG, self.REGS.EFUSE_CLK_SEL0_MASK, clk_sel0
        )
        self.update_reg(
            self.REGS.EFUSE_CLK_REG, self.REGS.EFUSE_CLK_SEL1_MASK, clk_sel1
        )

        self.write_reg(self.REGS.EFUSE_REG_CONF, self.REGS.EFUSE_CONF_WRITE)
        self.write_reg(self.REGS.EFUSE_REG_CMD, self.REGS.EFUSE_CMD_WRITE)

        self.efuse_read()
        return self.get_coding_scheme_warnings(silent=True)

    def wait_efuse_idle(self):
        deadline = time.time() + self.REGS.EFUSE_BURN_TIMEOUT
        while time.time() < deadline:
            if self.read_reg(self.REGS.EFUSE_REG_CMD) == 0:
                return
        raise esptool.FatalError(
            "Timed out waiting for eFuse controller command to complete"
        )

    def efuse_read(self):
        self.wait_efuse_idle()
        self.write_reg(self.REGS.EFUSE_REG_CONF, self.REGS.EFUSE_CONF_READ)
        self.write_reg(self.REGS.EFUSE_REG_CMD, self.REGS.EFUSE_CMD_READ)
        self.wait_efuse_idle()

    def get_coding_scheme_warnings(self, silent=False):
        """Check if the coding scheme has detected any errors.
        Meaningless for default coding scheme (0)
        """
        err = (
            self.read_reg(self.REGS.EFUSE_REG_DEC_STATUS)
            & self.REGS.EFUSE_REG_DEC_STATUS_MASK
        )
        for block in self.blocks:
            if block.id != 0:
                block.num_errors = 0
                block.fail = err != 0
            if not silent and block.fail:
                log.print(
                    f"Error(s) in BLOCK{block.id} "
                    f"[ERRORS:{block.num_errors} FAIL:{block.fail}]"
                )
        if (self.debug or err) and not silent:
            self.print_status_regs()
        return err != 0

    def summary(self):
        if self["XPD_SDIO_FORCE"].get() == 0:
            output = "Flash voltage (VDD_SDIO) determined by GPIO12 on reset (High for 1.8V, Low/NC for 3.3V)"
        elif self["XPD_SDIO_REG"].get() == 0:
            output = "Flash voltage (VDD_SDIO) internal regulator disabled by efuse."
        elif self["XPD_SDIO_TIEH"].get() == 0:
            output = "Flash voltage (VDD_SDIO) set to 1.8V by efuse."
        else:
            output = "Flash voltage (VDD_SDIO) set to 3.3V by efuse."
        return output


class EfuseField(base_fields.EfuseFieldBase):
    @staticmethod
    def convert(parent, efuse):
        return {
            "mac": EfuseMacField,
            "spipin": EfuseSpiPinField,
            "vref": EfuseVRefField,
            "adc_tp": EfuseAdcPointCalibration,
            "wafer": EfuseWafer,
            "pkg": EfusePkg,
        }.get(efuse.class_type, EfuseField)(parent, efuse)


class EfuseMacField(EfuseField):
    """
    Supports: MAC and CUSTOM_MAC fields.
    (if MAC_VERSION == 1 then the CUSTOM_MAC is used)
    """

    def check_format(self, new_value_str: str | None):
        if new_value_str is None:
            raise esptool.FatalError(
                "Required MAC Address in AA:CD:EF:01:02:03 format!"
            )
        if new_value_str.count(":") != 5:
            raise esptool.FatalError(
                "MAC Address needs to be a 6-byte hexadecimal format "
                "separated by colons (:)!"
            )
        hexad = new_value_str.replace(":", "")
        if len(hexad) != 12:
            raise esptool.FatalError(
                "MAC Address needs to be a 6-byte hexadecimal number "
                "(12 hexadecimal characters)!"
            )
        # order of bytearray = b'\xaa\xcd\xef\x01\x02\x03',
        bindata = binascii.unhexlify(hexad)
        # unicast address check according to
        # https://tools.ietf.org/html/rfc7042#section-2.1
        if esptool.util.byte(bindata, 0) & 0x01:
            raise esptool.FatalError("Custom MAC must be a unicast MAC!")
        return bindata

    @staticmethod
    def get_and_check(raw_mac, stored_crc):
        computed_crc = EfuseMacField.calc_crc(raw_mac)
        if computed_crc == stored_crc:
            valid_msg = f"(CRC {stored_crc:#04x} OK)"
        else:
            valid_msg = (
                f"(CRC {stored_crc:#04x} invalid - calculated {computed_crc:#04x})"
            )
        return " ".join([util.hexify(raw_mac, ":"), valid_msg])

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
                    result ^= 0x8C
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
            log.print(
                f"    - '{e.name}' ({e.description}) {e.get_bitstring()} -> {new_value}"
            )

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
                        raise esptool.FatalError(
                            f"MAC_VERSION = {mac_version.get()}, should be 0 or 1."
                        )

            bitarray_mac = self.convert_to_bitstring(new_value)
            print_field(self, bitarray_mac)
            super().save(new_value)

            crc_val = self.calc_crc(new_value)
            crc_field = self.parent["CUSTOM_MAC_CRC"]
            print_field(crc_field, hex(crc_val))
            crc_field.save(crc_val)
        else:
            # Writing the BLK0 default MAC is not possible,
            # as it's written in the factory.
            raise esptool.FatalError("Writing Factory MAC address is not supported")


class EfuseWafer(EfuseField):
    def get(self, from_read=True):
        rev_bit0 = self.parent["CHIP_VER_REV1"].get(from_read)
        assert self.parent["CHIP_VER_REV1"].bit_len == 1
        rev_bit1 = self.parent["CHIP_VER_REV2"].get(from_read)
        assert self.parent["CHIP_VER_REV2"].bit_len == 1
        apb_ctl_date = self.parent.read_reg(self.parent.REGS.APB_CTL_DATE_ADDR)
        rev_bit2 = (
            apb_ctl_date >> self.parent.REGS.APB_CTL_DATE_S
        ) & self.parent.REGS.APB_CTL_DATE_V
        combine_value = (rev_bit2 << 2) | (rev_bit1 << 1) | rev_bit0

        revision = {
            0: 0,
            1: 1,
            3: 2,
            7: 3,
        }.get(combine_value, 0)
        return revision

    def save(self, new_value):
        raise esptool.FatalError(f"Burning {self.name} is not supported")


class EfusePkg(EfuseField):
    def get(self, from_read=True):
        lo_bits = self.parent["CHIP_PACKAGE"].get(from_read)
        hi_bits = self.parent["CHIP_PACKAGE_4BIT"].get(from_read)
        return (hi_bits << 3) + lo_bits

    def save(self, new_value):
        raise esptool.FatalError(f"Burning {self.name} is not supported.")


class EfuseSpiPinField(EfuseField):
    def get(self, from_read=True):
        val = self.get_raw(from_read)
        if val >= 30:
            val += 2  # values 30,31 map to 32, 33
        return val

    def check_format(self, new_value_str):
        if new_value_str is None:
            return new_value_str

        new_value_int = int(new_value_str, 0)

        if new_value_int in [30, 31]:
            raise esptool.FatalError(
                "IO pins 30 & 31 cannot be set for SPI flash. 0-29, 32 & 33 only."
            )
        elif new_value_int > 33:
            raise esptool.FatalError(
                f"IO pin {new_value_int} cannot be set for SPI flash. 0-29, 32 & 33 only."
            )
        elif new_value_int in [32, 33]:
            return str(new_value_int - 2)
        else:
            return new_value_str


class EfuseVRefField(EfuseField):
    VREF_OFFSET = 1100  # ideal efuse value in mV
    VREF_STEP_SIZE = 7  # 1 count in efuse == 7mV
    VREF_SIGN_BIT = 0x10
    VREF_MAG_BITS = 0x0F

    def get(self, from_read=True):
        val = self.get_raw(from_read)
        # sign-magnitude format
        if val & self.VREF_SIGN_BIT:
            val = -(val & self.VREF_MAG_BITS)
        else:
            val = val & self.VREF_MAG_BITS
        val *= self.VREF_STEP_SIZE
        return self.VREF_OFFSET + val

    def save(self, new_value):
        raise esptool.FatalError("Writing to VRef is not supported.")


class EfuseAdcPointCalibration(EfuseField):
    TP_OFFSET = {  # See TP_xxxx_OFFSET in esp_adc_cal.c in ESP-IDF
        "ADC1_TP_LOW": 278,
        "ADC2_TP_LOW": 421,
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
