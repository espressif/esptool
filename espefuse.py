#!/usr/bin/env python
# ESP32 efuse get/set utility
# https://github.com/themadinventor/esptool
#
# Copyright (C) 2016 Espressif Systems (Shanghai) PTE LTD
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

import argparse
import esptool
import io
import json
import os
import struct
import sys
import time

# Table of efuse values - (category, block, word in block, mask, write disable bit, read disable bit, type, description)
# Match values in efuse_reg.h & Efuse technical reference chapter
EFUSES = [
    ('WR_DIS',               "efuse",    0, 0, 0x0000FFFF, 1,  None, "int", "Efuse write disable mask"),
    ('RD_DIS',               "efuse",    0, 0, 0x000F0000, 0,  None, "int", "Efuse read disablemask"),
    ('FLASH_CRYPT_CNT',      "security", 0, 0, 0x07F00000, 2,  None, "bitcount", "Flash encryption mode counter"),
    ('MAC',                  "identity", 0, 1, 0xFFFFFFFF, 3,  None, "mac", "Factory MAC Address"),
    ('XPD_SDIO_FORCE',       "config",   0, 4, 1 << 16,    5,  None, "flag", "Ignore MTDI pin (GPIO12) for VDD_SDIO on reset"),
    ('XPD_SDIO_REG',         "config",   0, 4, 1 << 14,    5,  None, "flag", "If XPD_SDIO_FORCE, enable VDD_SDIO reg on reset"),
    ('XPD_SDIO_TIEH',        "config",   0, 4, 1 << 15,    5,  None, "flag", "If XPD_SDIO_FORCE & XPD_SDIO_REG, 1=3.3V 0=1.8V"),
    ('CLK8M_FREQ',           "config",   0, 4, 0xFF,    None,  None, "int",  "8MHz clock freq override"),
    ('SPI_PAD_CONFIG_CLK',   "config",   0, 5, 0x1F << 0,  6,  None, "spipin", "Override SD_CLK pad (GPIO6/SPICLK)"),
    ('SPI_PAD_CONFIG_Q',     "config",   0, 5, 0x1F << 5,  6,  None, "spipin", "Override SD_DATA_0 pad (GPIO7/SPIQ)"),
    ('SPI_PAD_CONFIG_D',     "config",   0, 5, 0x1F << 10, 6,  None, "spipin", "Override SD_DATA_1 pad (GPIO8/SPID)"),
    ('SPI_PAD_CONFIG_HD',    "config",   0, 3, 0x1F << 4,  6,  None, "spipin", "Override SD_DATA_2 pad (GPIO9/SPIHD)"),
    ('SPI_PAD_CONFIG_CS0',   "config",   0, 5, 0x1F << 15, 6,  None, "spipin", "Override SD_CMD pad (GPIO11/SPICS0)"),
    ('FLASH_CRYPT_CONFIG',   "security", 0, 5, 0x0F << 28, 10, 3, "int", "Flash encryption config (key tweak bits)"),
    ('CHIP_VER_REV1',        "identity", 0, 3, 1 << 15,    3,  None, "flag", "Silicon Revision 1"),
    ('CHIP_VER_REV2',        "identity", 0, 5, 1 << 20,    6,  None, "flag", "Silicon Revision 2"),
    ('BLK3_PART_RESERVE',    "calibration", 0, 3, 1 << 14, 10, 3, "flag", "BLOCK3 partially served for ADC calibration data"),
    ('CHIP_VERSION',         "identity", 0, 3, 0x03 << 12, 3,  None, "int", "Reserved for future chip versions"),
    ('CHIP_PACKAGE',         "identity", 0, 3, 0x07 << 9,  3,  None, "int", "Chip package identifier"),
    ('CODING_SCHEME',        "efuse",    0, 6, 0x3,        10, 3, "int", "Efuse variable block length scheme"),
    ('CONSOLE_DEBUG_DISABLE',"security", 0, 6, 1 << 2,     15, None, "flag", "Disable ROM BASIC interpreter fallback"),
    ('DISABLE_SDIO_HOST',    "config",   0, 6, 1 << 3,   None, None, "flag", "Disable SDIO host"),
    ('ABS_DONE_0',           "security", 0, 6, 1 << 4,     12, None, "flag", "secure boot enabled for bootloader"),
    ('ABS_DONE_1',           "security", 0, 6, 1 << 5,     13, None, "flag", "secure boot abstract 1 locked"),
    ('JTAG_DISABLE',         "security", 0, 6, 1 << 6,     14, None, "flag", "Disable JTAG"),
    ('DISABLE_DL_ENCRYPT',   "security", 0, 6, 1 << 7,     15, None, "flag", "Disable flash encryption in UART bootloader"),
    ('DISABLE_DL_DECRYPT',   "security", 0, 6, 1 << 8,     15, None, "flag", "Disable flash decryption in UART bootloader"),
    ('DISABLE_DL_CACHE',     "security", 0, 6, 1 << 9,     15, None, "flag", "Disable flash cache in UART bootloader"),
    ('KEY_STATUS',           "efuse",    0, 6, 1 << 10,    10, 3, "flag", "Usage of efuse block 3 (reserved)"),
    ('ADC_VREF',             "calibration", 0, 4,0x1F << 8,0, None, "vref", "Voltage reference calibration"),
    ('BLK1',                 "security", 1, 0, 0xFFFFFFFF, 7,  0, "keyblock", "Flash encryption key"),
    ('BLK2',                 "security", 2, 0, 0xFFFFFFFF, 8,  1, "keyblock", "Secure boot key"),
    ('BLK3',                 "security", 3, 0, 0xFFFFFFFF, 9,  2, "keyblock", "Variable Block 3"),
]

# if BLK3_PART_RESERVE is set, these efuse fields are in BLK3:
BLK3_PART_EFUSES = [
    ('ADC1_TP_LOW',  "calibration", 3, 3, 0x7F << 0,   9, 2, "adc_tp", "ADC1 150mV reading"),
    ('ADC1_TP_HIGH', "calibration", 3, 3, 0x1FF << 7,  9, 2, "adc_tp", "ADC1 850mV reading"),
    ('ADC2_TP_LOW',  "calibration", 3, 3, 0x7F << 16,  9, 2, "adc_tp", "ADC2 150mV reading"),
    ('ADC2_TP_HIGH', "calibration", 3, 3, 0x1FF << 23, 9, 2, "adc_tp", "ADC2 850mV reading"),
]

# Offsets and lengths of each of the 4 efuse blocks in register space
#
# These offsets/lens are for esptool.read_efuse(X) which takes
# a word offset (into registers) not a byte offset.
EFUSE_BLOCK_OFFS = [0, 14, 22, 30]
EFUSE_BLOCK_LEN  = [7, 8, 8, 8]

# EFUSE registers & command/conf values
EFUSE_REG_CONF = 0x3FF5A0FC
EFUSE_CONF_WRITE = 0x5A5A
EFUSE_CONF_READ = 0x5AA5
EFUSE_REG_CMD  = 0x3FF5A104
EFUSE_CMD_WRITE = 0x2
EFUSE_CMD_READ  = 0x1
# address of first word of write registers for each efuse
EFUSE_REG_WRITE = [0x3FF5A01C, 0x3FF5A098, 0x3FF5A0B8, 0x3FF5A0D8]
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


# Coding Scheme values
CODING_SCHEME_NONE = 0
CODING_SCHEME_34 = 1


def confirm(action, args):
    print("%s%sThis is an irreversible operation." % (action, "" if action.endswith("\n") else ". "))
    if not args.do_not_confirm:
        print("Type 'BURN' (all capitals) to continue.")
        sys.stdout.flush()  # required for Pythons which disable line buffering, ie mingw in mintty
        try:
            yes = raw_input()  # raw_input renamed to input in Python 3
        except NameError:
            yes = input()
        if yes != "BURN":
            print("Aborting.")
            sys.exit(0)


def efuse_write_reg_addr(block, word):
    """
    Return the physical address of the efuse write data register
    block X word X.
    """
    return EFUSE_REG_WRITE[block] + (4 * word)


class EspEfuses(object):
    """
    Wrapper object to manage the efuse fields in a connected ESP bootloader
    """
    def __init__(self, esp):
        self._esp = esp
        self._efuses = [EfuseField.from_tuple(self, efuse) for efuse in EFUSES]
        if self["BLK3_PART_RESERVE"].get():
            # add these BLK3 efuses, if the BLK3_PART_RESERVE flag is set...
            self._efuses += [EfuseField.from_tuple(self, efuse) for efuse in BLK3_PART_EFUSES]

        self.coding_scheme = self["CODING_SCHEME"].get()

    def __getitem__(self, efuse_name):
        """ Return the efuse field with the given name """
        for e in self._efuses:
            if efuse_name == e.register_name:
                return e
        raise KeyError

    def __iter__(self):
        return self._efuses.__iter__()

    def write_efuses(self):
        """ Write the values in the efuse write registers to
        the efuse hardware, then refresh the efuse read registers.
        """

        # Configure clock
        apb_freq = self._esp.get_crystal_freq()
        clk_sel0, clk_sel1, dac_clk_div = EFUSE_CLK_SETTINGS[apb_freq]

        self.update_reg(EFUSE_DAC_CONF_REG, EFUSE_DAC_CLK_DIV_MASK, dac_clk_div)
        self.update_reg(EFUSE_CLK_REG, EFUSE_CLK_SEL0_MASK, clk_sel0)
        self.update_reg(EFUSE_CLK_REG, EFUSE_CLK_SEL1_MASK, clk_sel1)

        self.write_reg(EFUSE_REG_CONF, EFUSE_CONF_WRITE)
        self.write_reg(EFUSE_REG_CMD, EFUSE_CMD_WRITE)

        def wait_idle():
            deadline = time.time() + EFUSE_BURN_TIMEOUT
            while time.time() < deadline:
                if self._esp.read_reg(EFUSE_REG_CMD) == 0:
                    return
            raise esptool.FatalError("Timed out waiting for Efuse controller command to complete")
        wait_idle()
        self.write_reg(EFUSE_REG_CONF, EFUSE_CONF_READ)
        self.write_reg(EFUSE_REG_CMD, EFUSE_CMD_READ)
        wait_idle()

    def read_efuse(self, addr):
        return self._esp.read_efuse(addr)

    def read_reg(self, addr):
        return self._esp.read_reg(addr)

    def write_reg(self, addr, value):
        return self._esp.write_reg(addr, value)

    def update_reg(self, addr, mask, new_val):
        return self._esp.update_reg(addr, mask, new_val)

    def get_coding_scheme_warnings(self):
        """ Check if the coding scheme has detected any errors.
        Meaningless for default coding scheme (0)
        """
        return self.read_reg(EFUSE_REG_DEC_STATUS) & EFUSE_REG_DEC_STATUS_MASK

    def get_block_len(self):
        """ Return the length of BLK1, BLK2, BLK3 in bytes """
        return 24 if self.coding_scheme == CODING_SCHEME_34 else 32


class EfuseField(object):
    @staticmethod
    def from_tuple(parent, efuse_tuple):
        category = efuse_tuple[7]
        return {
            "mac": EfuseMacField,
            "keyblock": EfuseKeyblockField,
            "spipin": EfuseSpiPinField,
            "vref": EfuseVRefField,
            "adc_tp": EfuseAdcPointCalibration,
        }.get(category, EfuseField)(parent, *efuse_tuple)

    def __init__(self, parent, register_name, category, block, word, mask, write_disable_bit, read_disable_bit, efuse_type, description):
        self.category = category
        self.parent = parent
        self.block = block
        self.word = word
        self.data_reg_offs = EFUSE_BLOCK_OFFS[self.block] + self.word
        self.mask = mask
        self.shift = esptool._mask_to_shift(mask)
        self.write_disable_bit = write_disable_bit
        self.read_disable_bit = read_disable_bit
        self.register_name = register_name
        self.efuse_type = efuse_type
        self.description = description

    def get_raw(self):
        """ Return the raw (unformatted) numeric value of the efuse bits

        Returns a simple integer or (for some subclasses) a bitstring.
        """
        value = self.parent.read_efuse(self.data_reg_offs)
        return (value & self.mask) >> self.shift

    def get(self):
        """ Get a formatted version of the efuse value, suitable for display """
        return self.get_raw()

    def is_readable(self):
        """ Return true if the efuse is readable by software """
        if self.read_disable_bit is None:
            return True  # read cannot be disabled
        value = (self.parent.read_efuse(0) >> 16) & 0xF  # RD_DIS values
        return (value & (1 << self.read_disable_bit)) == 0

    def disable_read(self):
        if self.read_disable_bit is None:
            raise esptool.FatalError("This efuse cannot be read-disabled")
        rddis_reg_addr = efuse_write_reg_addr(0, 0)
        self.parent.write_reg(rddis_reg_addr, 1 << (16 + self.read_disable_bit))
        self.parent.write_efuses()
        return self.get()

    def is_writeable(self):
        if self.write_disable_bit is None:
            return True  # write cannot be disabled
        value = self.parent.read_efuse(0) & 0xFFFF   # WR_DIS values
        return (value & (1 << self.write_disable_bit)) == 0

    def disable_write(self):
        wrdis_reg_addr = efuse_write_reg_addr(0, 0)
        self.parent.write_reg(wrdis_reg_addr, 1 << self.write_disable_bit)
        self.parent.write_efuses()
        return self.get()

    def burn(self, new_value):
        raw_value = (new_value << self.shift) & self.mask
        # don't both reading old value as we can only set bits 0->1
        write_reg_addr = efuse_write_reg_addr(self.block, self.word)
        self.parent.write_reg(write_reg_addr, raw_value)
        self.parent.write_efuses()
        return self.get()


class EfuseMacField(EfuseField):
    def get_raw(self):
        # MAC values are high half of second efuse word, then first efuse word
        words = [self.parent.read_efuse(self.data_reg_offs + word) for word in [1,0]]
        # endian-swap into a bitstring
        bitstring = struct.pack(">II", *words)
        return bitstring[2:]  # trim 2 byte CRC from the beginning

    @staticmethod
    def get_and_check(raw_mac, stored_crc):
        computed_crc = EfuseMacField.calc_crc(raw_mac)
        if computed_crc == stored_crc:
            valid_msg = "(CRC 0x%02x OK)" % stored_crc
        else:
            valid_msg = "(CRC 0x%02x invalid - calculated 0x%02x)" % (stored_crc, computed_crc)
        return "%s %s" % (hexify(raw_mac, ":"), valid_msg)

    def get(self):
        stored_crc = self.get_stored_crc()
        return EfuseMacField.get_and_check(self.get_raw(), stored_crc)

    def burn(self, new_value):
        # Writing the BLK0 default MAC is not sensible, as it's written in the factory.
        raise esptool.FatalError("Writing Factory MAC address is not supported")

    def get_stored_crc(self):
        return (self.parent.read_efuse(self.data_reg_offs + 1) >> 16) & 0xFF

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


class EfuseKeyblockField(EfuseField):
    def get_raw(self):
        words = self.get_words()
        return struct.pack("<" + ("I" * len(words)), *words)

    def get_key(self):
        # Keys are stored in reverse byte order
        result = self.get_raw()
        result = result[::-1]
        return result

    def get_words(self):
        num_words = self.parent.get_block_len() // 4
        return [self.parent.read_efuse(self.data_reg_offs + word) for word in range(num_words)]

    def get(self):
        return hexify(self.get_raw(), " ")

    def apply_34_encoding(self, inbits):
        """ Takes 24 byte sequence to be represented in 3/4 encoding,
            returns 8 words suitable for writing "encoded" to an efuse block
        """
        def popcnt(b):
            """ Return number of "1" bits set in 'b' """
            return len([x for x in bin(b) if x == "1"])

        outbits = b""
        while len(inbits) > 0:  # process in chunks of 6 bytes
            bits = inbits[0:6]
            inbits = inbits[6:]
            xor_res = 0
            mul_res = 0
            index = 1
            for b in struct.unpack("B" * 6, bits):
                xor_res ^= b
                mul_res += index * popcnt(b)
                index += 1
            outbits += bits
            outbits += struct.pack("BB", xor_res, mul_res)
        return struct.unpack("<" + "I" * (len(outbits) // 4), outbits)

    def burn_key(self, new_value):
        new_value = new_value[::-1]  # AES keys are stored in reverse order in efuse
        return self.burn(new_value)

    def burn(self, new_value):
        key_len = self.parent.get_block_len()
        if len(new_value) != key_len:
            raise RuntimeError("Invalid new value length for key block (%d), %d is required" % len(new_value), key_len)

        if self.parent.coding_scheme == CODING_SCHEME_34:
            words = self.apply_34_encoding(new_value)
        else:
            words = struct.unpack("<" + ("I" * 8), new_value)
        return self.burn_words(words)

    def burn_words(self, words, word_offset=0):
        write_reg_addr = efuse_write_reg_addr(self.block, self.word + word_offset)
        for word in words:
            self.parent.write_reg(write_reg_addr, word)
            write_reg_addr += 4
        warnings_before = self.parent.get_coding_scheme_warnings()
        self.parent.write_efuses()
        warnings_after = self.parent.get_coding_scheme_warnings()
        if warnings_after & ~warnings_before != 0:
            print("WARNING: Burning efuse block added coding scheme warnings 0x%x -> 0x%x. Encoding bug?" % (warnings_before, warnings_after))
        return self.get()


class EfuseSpiPinField(EfuseField):
    def get(self):
        val = self.get_raw()
        if val >= 30:
            val += 2  # values 30,31 map to 32, 33
        return val

    def burn(self, new_value):
        if new_value in [30, 31]:
            raise esptool.FatalError("IO pins 30 & 31 cannot be set for SPI flash. 0-29, 32 & 33 only.")
        if new_value > 33:
            raise esptool.FatalError("IO pin %d cannot be set for SPI flash. 0-29, 32 & 33 only." % new_value)
        if new_value > 30:
            new_value -= 2  # values 32,33 map to 30, 31
        return super(EfuseSpiPinField, self).burn(new_value)


class EfuseVRefField(EfuseField):
    VREF_OFFSET = 1100  # ideal efuse value in mV
    VREF_STEP_SIZE = 7  # 1 count in efuse == 7mV
    VREF_SIGN_BIT = 0x10
    VREF_MAG_BITS = 0x0F

    def get(self):
        val = self.get_raw()
        # sign-magnitude format
        if (val & self.VREF_SIGN_BIT):
            val = -(val & self.VREF_MAG_BITS)
        else:
            val = (val & self.VREF_MAG_BITS)
        val *= self.VREF_STEP_SIZE
        return self.VREF_OFFSET + val

    def burn(self, new_value):
        raise RuntimeError("Writing to VRef is not supported.")


class EfuseAdcPointCalibration(EfuseField):
    TP_OFFSET = {  # See TP_xxxx_OFFSET in esp_adc_cal.c in ESP-IDF
        "ADC1_TP_LOW":  278,
        "ADC2_TP_LOW":  421,
        "ADC1_TP_HIGH": 3265,
        "ADC2_TP_HIGH": 3406,
    }
    SIGN_BIT = (0x40, 0x100)  # LOW, HIGH (2s complement format)
    STEP_SIZE = 4

    def get(self):
        idx = 0 if self.register_name.endswith("LOW") else 1
        sign_bit = self.SIGN_BIT[idx]
        offset = self.TP_OFFSET[self.register_name]
        raw = self.get_raw()
        delta = (raw & (sign_bit - 1)) - (raw & sign_bit)
        return offset + (delta * self.STEP_SIZE)


def dump(esp, _efuses, args):
    """ Dump raw efuse data registers """
    for block in range(len(EFUSE_BLOCK_OFFS)):
        print("EFUSE block %d:" % block)
        offsets = [x + EFUSE_BLOCK_OFFS[block] for x in range(EFUSE_BLOCK_LEN[block])]
        print(" ".join(["%08x" % esp.read_efuse(offs) for offs in offsets]))


def summary(esp, efuses, args):
    """ Print a human-readable summary of efuse contents """
    ROW_FORMAT = "%-22s %-50s%s= %s %s %s"
    human_output = (args.format == 'summary')
    json_efuse = {}
    if args.file != sys.stdout:
        print("Saving efuse values to " + args.file.name)
    if human_output:
        print(ROW_FORMAT.replace("-50", "-12") % ("EFUSE_NAME", "Description", "", "[Meaningful Value]", "[Readable/Writeable]", "(Hex Value)"),file=args.file)
        print("-" * 88,file=args.file)
    for category in set(e.category for e in efuses):
        if human_output:
            print("%s fuses:" % category.title(),file=args.file)
        for e in (e for e in efuses if e.category == category):
            raw = e.get_raw()
            try:
                raw = "(0x%x)" % raw
            except TypeError:
                raw = ""
            (readable, writeable) = (e.is_readable(), e.is_writeable())
            if readable and writeable:
                perms = "R/W"
            elif readable:
                perms = "R/-"
            elif writeable:
                perms = "-/W"
            else:
                perms = "-/-"
            base_value = e.get()
            value = str(base_value)
            if not readable:
                value = value.replace("0", "?")
            if human_output:
                print(ROW_FORMAT % (e.register_name, e.description, "\n  " if len(value) > 20 else "", value, perms, raw),file=args.file)
            if args.format == 'json':
                json_efuse[e.register_name] = {
                    'value': base_value if readable else value,
                    'readable':readable,
                    'writeable':writeable}
        if human_output:
            print("",file=args.file)
    if human_output:
        sdio_force = efuses["XPD_SDIO_FORCE"]
        sdio_tieh = efuses["XPD_SDIO_TIEH"]
        sdio_reg = efuses["XPD_SDIO_REG"]
        if sdio_force.get() == 0:
            print("Flash voltage (VDD_SDIO) determined by GPIO12 on reset (High for 1.8V, Low/NC for 3.3V).",file=args.file)
        elif sdio_reg.get() == 0:
            print("Flash voltage (VDD_SDIO) internal regulator disabled by efuse.",file=args.file)
        elif sdio_tieh.get() == 0:
            print("Flash voltage (VDD_SDIO) set to 1.8V by efuse.",file=args.file)
        else:
            print("Flash voltage (VDD_SDIO) set to 3.3V by efuse.",file=args.file)
        warnings = efuses.get_coding_scheme_warnings()
        if warnings:
            print("WARNING: Coding scheme has encoding bit error warnings (0x%x)" % warnings,file=args.file)
        if args.file != sys.stdout:
            args.file.close()
            print("Done")
    if args.format == 'json':
        json.dump(json_efuse,args.file,sort_keys=True,indent=4)
        print("")


def burn_efuse(esp, efuses, args):
    efuse = efuses[args.efuse_name]
    old_value = efuse.get()
    if efuse.efuse_type == "flag":
        if args.new_value not in [None, 1]:
            raise esptool.FatalError("Efuse %s is type 'flag'. New value is not accepted for this efuse (will always burn 0->1)" % efuse.register_name)
        args.new_value = 1
        if old_value:
            print("Efuse %s is already burned." % efuse.register_name)
            return
    elif efuse.efuse_type == "int":
        if args.new_value is None:
            raise esptool.FatalError("New value required for efuse %s" % efuse.register_name)
    elif efuse.efuse_type == "spipin":
        if args.new_value is None or args.new_value == 0:
            raise esptool.FatalError("New value required for efuse %s" % efuse.register_name)
    elif efuse.efuse_type == "bitcount":
        if args.new_value is None:  # find the first unset bit and set it
            args.new_value = old_value
            bit = 1
            while args.new_value == old_value:
                args.new_value = bit | old_value
                bit <<= 1

    if args.new_value & (efuse.mask >> efuse.shift) != args.new_value:
        raise esptool.FatalError("Value mask for efuse %s is 0x%x. Value 0x%x is too large." % (efuse.register_name, efuse.mask >> efuse.shift, args.new_value))
    if args.new_value | old_value != args.new_value:
        print("WARNING: New value contains some bits that cannot be cleared (value will be 0x%x)" % (old_value | args.new_value))

    confirm("Burning efuse %s (%s) 0x%x -> 0x%x" % (efuse.register_name, efuse.description, old_value, args.new_value | old_value), args)
    burned_value = efuse.burn(args.new_value)
    if burned_value == old_value:
        raise esptool.FatalError("Efuse %s failed to burn. Protected?" % efuse.register_name)


def read_protect_efuse(esp, efuses, args):
    efuse = efuses[args.efuse_name]
    if not efuse.is_readable():
        print("Efuse %s is already read protected" % efuse.register_name)
    else:
        # make full list of which efuses will be disabled (ie share a read disable bit)
        all_disabling = [e for e in efuses if e.read_disable_bit == efuse.read_disable_bit]
        names = ", ".join(e.register_name for e in all_disabling)
        confirm("Permanently read-disabling efuse%s %s" % ("s" if len(all_disabling) > 1 else "",names), args)
        efuse.disable_read()


def write_protect_efuse(esp, efuses, args):
    efuse = efuses[args.efuse_name]
    if not efuse.is_writeable():
        print("]fuse %s is already write protected" % efuse.register_name)
    else:
        # make full list of which efuses will be disabled (ie share a write disable bit)
        all_disabling = [e for e in efuses if e.write_disable_bit == efuse.write_disable_bit]
        names = ", ".join(e.register_name for e in all_disabling)
        confirm("Permanently write-disabling efuse%s %s" % ("s" if len(all_disabling) > 1 else "",names), args)
        efuse.disable_write()


def burn_key(esp, efuses, args):
    # check block choice
    if args.block in ["flash_encryption", "BLK1"]:
        block_num = 1
    elif args.block in ["secure_boot", "BLK2"]:
        block_num = 2
    elif args.block == "BLK3":
        block_num = 3
    else:
        raise RuntimeError("args.block argument not in list!")

    num_bytes = efuses.get_block_len()

    # check keyfile
    keyfile = args.keyfile
    keyfile.seek(0,2)  # seek t oend
    size = keyfile.tell()
    keyfile.seek(0)
    if size != num_bytes:
        raise esptool.FatalError("Incorrect key file size %d. Key file must be %d bytes (%d bits) of raw binary key data." %
                                 (size, num_bytes, num_bytes * 8))

    # check existing data
    efuse = [e for e in efuses if e.register_name == "BLK%d" % block_num][0]
    original = efuse.get_raw()
    EMPTY_KEY = b'\x00' * num_bytes
    if original != EMPTY_KEY:
        if not args.force_write_always:
            raise esptool.FatalError("Key block already has value %s." % efuse.get())
        else:
            print("WARNING: Key appears to have a value already. Trying anyhow, due to --force-write-always (result will be bitwise OR of new and old values.)")
    if not efuse.is_writeable():
        if not args.force_write_always:
            raise esptool.FatalError("The efuse block has already been write protected.")
        else:
            print("WARNING: Key appears to be write protected. Trying anyhow, due to --force-write-always")
    msg = "Write key in efuse block %d. " % block_num
    if args.no_protect_key:
        msg += "The key block will left readable and writeable (due to --no-protect-key)"
    else:
        msg += "The key block will be read and write protected (no further changes or readback)"
    confirm(msg, args)

    new_value = keyfile.read(num_bytes)
    new = efuse.burn_key(new_value)
    print("Burned key data. New value: %s" % (new,))
    if not args.no_protect_key:
        print("Disabling read/write to key efuse block...")
        efuse.disable_write()
        efuse.disable_read()
        if efuse.is_readable():
            print("WARNING: Key does not appear to have been read protected. Perhaps read disable efuse is write protected?")
        if efuse.is_writeable():
            print("WARNING: Key does not appear to have been write protected. Perhaps write disable efuse is write protected?")
    else:
        print("Key is left unprotected as per --no-protect-key argument.")


def burn_block_data(esp, efuses, args):
    num_bytes = efuses.get_block_len()
    offset = args.offset
    data = args.datafile.read()

    if offset >= num_bytes:
        raise RuntimeError("Invalid offset: Key block only holds %d bytes." % num_bytes)
    if len(data) > num_bytes - offset:
        raise RuntimeError("Data will not fit: Key block size %d bytes, data file is %d bytes" % (num_bytes, len(data)))
    if efuses.coding_scheme == CODING_SCHEME_34:
        if offset % 6 != 0:
            raise RuntimeError("Device has 3/4 Coding Scheme. Can only write at offsets which are a multiple of 6.")
        if len(data) % 6 != 0:
            raise RuntimeError("Device has 3/4 Coding Scheme. Can only write data lengths which are a multiple of 6 (data is %d bytes)" % len(data))

    efuse = [e for e in efuses if e.register_name == args.block.upper()][0]

    if not args.force_write_always and \
       efuse.get_raw() != b'\x00' * num_bytes:
        raise esptool.FatalError("Efuse block already has values written.")

    if efuses.coding_scheme == CODING_SCHEME_NONE:
        pad = offset % 4
        if pad != 0:  # left-pad to a word boundary
            data = (b'\x00' * pad) + data
            offset -= pad
        pad = len(data) % 4
        if pad != 0:  # right-pad to a word boundary
            data += (b'\x00' * (4 - pad))
        words = struct.unpack("<" + "I" * (len(data) // 4), data)
        word_offset = offset // 4
    else:  # CODING_SCHEME_34
        words = efuse.apply_34_encoding(data)
        word_offset = (offset // 6) * 2

    confirm("Burning efuse %s (%s) with %d bytes of data at offset %d in the block" % (efuse.register_name, efuse.description, len(data), offset), args)
    efuse.burn_words(words, word_offset)


def set_flash_voltage(esp, efuses, args):
    sdio_force = efuses["XPD_SDIO_FORCE"]
    sdio_tieh = efuses["XPD_SDIO_TIEH"]
    sdio_reg = efuses["XPD_SDIO_REG"]

    # check efuses aren't burned in a way which makes this impossible
    if args.voltage == 'OFF' and sdio_reg.get() != 0:
        raise esptool.FatalError("Can't set flash regulator to OFF as XPD_SDIO_REG efuse is already burned")

    if args.voltage == '1.8V' and sdio_tieh.get() != 0:
        raise esptool.FatalError("Can't set regulator to 1.8V is XPD_SDIO_TIEH efuse is already burned")

    if args.voltage == 'OFF':
        msg = """
Disable internal flash voltage regulator (VDD_SDIO). SPI flash will need to be powered from an external source.
The following efuse is burned: XPD_SDIO_FORCE.
It is possible to later re-enable the internal regulator (%s) by burning an additional efuse
""" % ("to 3.3V" if sdio_tieh.get() != 0 else "to 1.8V or 3.3V")
    elif args.voltage == '1.8V':
        msg = """
Set internal flash voltage regulator (VDD_SDIO) to 1.8V.
The following efuses are burned: XPD_SDIO_FORCE, XPD_SDIO_REG.
It is possible to later increase the voltage to 3.3V (permanently) by burning additional efuse XPD_SDIO_TIEH
"""
    elif args.voltage == '3.3V':
        msg = """
Enable internal flash voltage regulator (VDD_SDIO) to 3.3V.
The following efuses are burned: XPD_SDIO_FORCE, XPD_SDIO_REG, XPD_SDIO_TIEH.
"""

    confirm(msg, args)

    sdio_force.burn(1)   # Disable GPIO12
    if args.voltage != 'OFF':
        sdio_reg.burn(1)  # Enable internal regulator
    if args.voltage == '3.3V':
        sdio_tieh.burn(1)
    print("VDD_SDIO setting complete.")


def adc_info(esp, efuses, args):
    adc_vref = efuses["ADC_VREF"]
    blk3_reserve = efuses["BLK3_PART_RESERVE"]

    vref_raw = adc_vref.get_raw()
    if vref_raw == 0:
        print("ADC VRef calibration: None (1100mV nominal)")
    else:
        print("ADC VRef calibration: %dmV" % adc_vref.get())

    if blk3_reserve.get():
        print("ADC readings stored in efuse BLK3:")
        print("    ADC1 Low reading  (150mV): %d" % efuses["ADC1_TP_LOW"].get())
        print("    ADC1 High reading (850mV): %d" % efuses["ADC1_TP_HIGH"].get())
        print("    ADC2 Low reading  (150mV): %d" % efuses["ADC2_TP_LOW"].get())
        print("    ADC2 High reading (850mV): %d" % efuses["ADC2_TP_HIGH"].get())


class CustomMacAddressField(object):
    """
    The custom MAC field uses the formatting according to the specification for version 1
    """
    def __init__(self, efuses):
        self.efuse = [e for e in efuses if e.register_name == 'BLK3'][0]
        self.parent = self.efuse.parent

    def get_raw(self):
        words = [self.parent.read_efuse(self.efuse.data_reg_offs + word) for word in [0, 1]]
        bitstring = struct.pack("<II", *words)
        return bitstring[1:-1]  # trim a byte from the beginning and one (CRC) from the end

    def get_stored_crc(self):
        return self.parent.read_efuse(self.efuse.data_reg_offs) & 0xFF

    @staticmethod
    def calc_crc(raw_mac):
        return EfuseMacField.calc_crc(raw_mac)

    def get(self):
        return EfuseMacField.get_and_check(self.get_raw(), self.get_stored_crc())

    def get_version(self):
        """
        Returns the version of the MAC field

        The version is stored in the block at the [191:184] bit positions. That is in the 5th 4-byte word, the most
        significant byte (3 * 8 = 24)
        """
        return (self.parent.read_efuse(self.efuse.data_reg_offs + 5) >> 24) & 0xFF

    def get_block(self, new_mac, new_version):
        """
        Returns a byte array which can be written directly to BLK3
        """
        num_words = self.parent.get_block_len() // 4
        words = [self.parent.read_efuse(self.efuse.data_reg_offs + word) for word in range(num_words)]
        B = sum([x << (i * 32) for i, x in enumerate(words)])  # integer representation of the whole BLK content

        new_mac_b = struct.pack(">Q", new_mac)[2:]  # Q has 8-bytes. Removing two MSB bytes to get a 6-byte MAC
        new_mac_rev = struct.unpack("<Q", new_mac_b + b'\x00\x00')[0]  # bytes in reversed order
        crc = self.calc_crc(new_mac_b)

        # MAC fields according to esp_efuse_table.c:
        # - CRC - offset 0 bits, length 8 bits
        # - MAC - offset 8 bits, length 48 bits
        # - MAC version - offset 184 bits, length 8 bits
        B |= (crc & ((1 << 8) - 1)) << 0
        B |= (new_mac_rev & ((1 << 48) - 1)) << 8
        B |= (new_version & ((1 << 8) - 1)) << 184

        return bytearray([(B >> i * 8) & 0xFF for i in range(self.parent.get_block_len())])


def burn_custom_mac(esp, efuses, args):
    write_always = args.force_write_always
    c = CustomMacAddressField(efuses)
    old_version = c.get_version()
    new_version = old_version | 1  # Only version 1 MAC Addresses are supported yet
    if (not write_always and old_version != 0) or (write_always and old_version not in [0, new_version]):
        raise esptool.FatalError("The version of the custom MAC Address is already burned ({})!".format(old_version))
    old_mac_b = c.get_raw()
    old_mac = struct.unpack(">Q", b'\x00\x00' + old_mac_b)[0]
    new_mac_b = struct.pack(">Q", args.mac)[2:]  # Q has 8-bytes. Removing two MSB bytes to get a 6-byte MAC
    new_mac = args.mac
    if (not write_always and old_mac != 0) or (write_always and new_mac | old_mac != new_mac):
        raise esptool.FatalError("Custom MAC Address was previously burned ({})!".format(hexify(old_mac_b, ":")))
    old_crc = c.get_stored_crc()
    new_crc = c.calc_crc(new_mac_b)
    if (not write_always and old_crc != 0) or (write_always and new_crc | old_crc != new_crc):
        raise esptool.FatalError("The CRC of the custom MAC Address was previously burned ({})!".format(old_crc))
    confirm("Burning efuse for custom MAC address {} (version {}, CRC 0x{:x}) -> {} (version {}, CRC 0x{:x})"
            "".format(hexify(old_mac_b, ":"), old_version, old_crc, hexify(new_mac_b, ":"), new_version, new_crc), args)
    with io.BytesIO(c.get_block(new_mac, new_version)) as buf:
        args.do_not_confirm = True  # Custom MAC burning was already confirmed. No need to ask twice.
        # behavour of burn_block_data() for args.force_write_always is compatible
        args.offset = 0
        args.datafile = buf
        args.block = 'BLK3'
        burn_block_data(esp, efuses, args)


def get_custom_mac(esp, efuses, args):
    c = CustomMacAddressField(efuses)
    version = c.get_version()

    if version > 0:
        print("Custom MAC Address version {}: {}".format(version, c.get()))
    else:
        print("Custom MAC Address is not set in the device.")


def hexify(bitstring, separator=""):
    try:
        as_bytes = tuple(ord(b) for b in bitstring)
    except TypeError:  # python 3, items in bitstring already ints
        as_bytes = tuple(b for b in bitstring)
    return separator.join(("%02x" % b) for b in as_bytes)


def arg_auto_int(x):
    return int(x, 0)


def mac_int(string):
    if string.count(":") != 5:
        raise argparse.ArgumentTypeError("MAC Address needs to be a 6-byte hexadecimal format separated by colons (:)!")
    hexad = string.replace(":", "")
    if len(hexad) != 12:
        raise argparse.ArgumentTypeError("MAC Address needs to be a 6-byte hexadecimal number (12 hexadecimal characters)!")
    return int(hexad, 16)


def main():
    parser = argparse.ArgumentParser(description='espefuse.py v%s - ESP32 efuse get/set tool' % esptool.__version__, prog='espefuse')

    parser.add_argument(
        '--baud', '-b',
        help='Serial port baud rate used when flashing/reading',
        type=arg_auto_int,
        default=os.environ.get('ESPTOOL_BAUD', esptool.ESPLoader.ESP_ROM_BAUD))

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default=os.environ.get('ESPTOOL_PORT', esptool.ESPLoader.DEFAULT_PORT))

    parser.add_argument(
        '--before',
        help='What to do before connecting to the chip',
        choices=['default_reset', 'no_reset', 'esp32r1', 'no_reset_no_sync'],
        default='default_reset')

    parser.add_argument('--do-not-confirm',
                        help='Do not pause for confirmation before permanently writing efuses. Use with caution.', action='store_true')

    def add_force_write_always(p):
        p.add_argument('--force-write-always', help="Write the efuse even if it looks like it's already been written, or is write protected. " +
                       "Note that this option can't disable write protection, or clear any bit which has already been set.", action='store_true')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run espefuse.py {command} -h for additional help')

    subparsers.add_parser('dump', help='Dump raw hex values of all efuses')
    p = subparsers.add_parser('summary',
                              help='Print human-readable summary of efuse values')
    p.add_argument('--format', help='Select the summary format',choices=['summary','json'],default='summary')
    p.add_argument('--file', help='File to save the efuse summary',type=argparse.FileType('w'),default=sys.stdout)

    p = subparsers.add_parser('burn_efuse',
                              help='Burn the efuse with the specified name')
    p.add_argument('efuse_name', help='Name of efuse register to burn',
                   choices=[efuse[0] for efuse in EFUSES])
    p.add_argument('new_value', help='New value to burn (not needed for flag-type efuses', nargs='?', type=esptool.arg_auto_int)

    p = subparsers.add_parser('read_protect_efuse',
                              help='Disable readback for the efuse with the specified name')
    p.add_argument('efuse_name', help='Name of efuse register to burn',
                   choices=[efuse[0] for efuse in EFUSES if efuse[6] is not None])  # only allow if read_disable_bit is not None

    p = subparsers.add_parser('write_protect_efuse',
                              help='Disable writing to the efuse with the specified name')
    p.add_argument('efuse_name', help='Name of efuse register to burn',
                   choices=[efuse[0] for efuse in EFUSES])

    p = subparsers.add_parser('burn_key',
                              help='Burn a 256-bit AES key to EFUSE BLK1,BLK2 or BLK3 (flash_encryption, secure_boot).')
    p.add_argument('--no-protect-key', help='Disable default read- and write-protecting of the key. ' +
                   'If this option is not set, once the key is flashed it cannot be read back or changed.', action='store_true')
    add_force_write_always(p)
    p.add_argument('block', help='Key block to burn. "flash_encryption" is an alias for BLK1, ' +
                   '"secure_boot" is an alias for BLK2.', choices=["secure_boot", "flash_encryption","BLK1","BLK2","BLK3"])
    p.add_argument('keyfile', help='File containing 256 bits of binary key data', type=argparse.FileType('rb'))

    p = subparsers.add_parser('burn_block_data',
                              help="Burn non-key data to EFUSE BLK1, BLK2 or BLK3. " +
                              " Don't use this command to burn key data for Flash Encryption or Secure Boot, " +
                              "as the byte order of keys is swapped (use burn_key).")
    p.add_argument('--offset', '-o', help='Byte offset in the efuse block', type=int, default=0)
    add_force_write_always(p)
    p.add_argument('block', help='Efuse block to burn.', choices=["BLK1","BLK2","BLK3"])
    p.add_argument('datafile', help='File containing data to burn into the efuse block', type=argparse.FileType('rb'))

    p = subparsers.add_parser('set_flash_voltage',
                              help='Permanently set the internal flash voltage regulator to either 1.8V, 3.3V or OFF. ' +
                              'This means GPIO12 can be high or low at reset without changing the flash voltage.')
    p.add_argument('voltage', help='Voltage selection',
                   choices=['1.8V', '3.3V', 'OFF'])

    p = subparsers.add_parser('adc_info',
                              help='Display information about ADC calibration data stored in efuse.')

    p = subparsers.add_parser('burn_custom_mac',
                              help='Burn a 48-bit Custom MAC Address to EFUSE BLK3.')
    p.add_argument('mac', help='Custom MAC Address to burn given in hexadecimal format with bytes separated by colons' +
                               ' (e.g. AB:CD:EF:01:02:03).', type=mac_int)
    add_force_write_always(p)

    p = subparsers.add_parser('get_custom_mac',
                              help='Prints the Custom MAC Address.')

    args = parser.parse_args()
    print('espefuse.py v%s' % esptool.__version__)
    if args.operation is None:
        parser.print_help()
        parser.exit(1)

    # each 'operation' is a module-level function of the same name
    operation_func = globals()[args.operation]

    esp = esptool.ESP32ROM(args.port, baud=args.baud)
    esp.connect(args.before)

    # dict mapping register name to its efuse object
    efuses = EspEfuses(esp)
    operation_func(esp, efuses, args)


def _main():
    try:
        main()
    except esptool.FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)


if __name__ == '__main__':
    _main()
