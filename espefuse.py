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
import os
import struct
import sys
import time

import esptool

# Table of efuse values - (category, block, word in block, mask, write disable bit, read disable bit, register name, type, description)
# Match values in efuse_reg.h & Efuse technical reference chapter
EFUSES = [
    ('WR_DIS',               "efuse",       0, 0, 0x0000FFFF, 1, None, "int", "Efuse write disable mask"),
    ('RD_DIS',               "efuse",       0, 0, 0x000F0000, 0, None, "int", "Efuse read disablemask"),
    ('FLASH_CRYPT_CNT',      "security",    0, 0, 0x0FF00000, 2, None, "bitcount", "Flash encryption mode counter"),
    ('MAC',                  "identity",    0, 1, 0xFFFFFFFF, 3, None, "mac", "MAC Address"),
    ('XPD_SDIO_FORCE',       "config",      0, 4, 1 << 16,    5, None, "flag", "Ignore MTDI pin (GPIO12) for VDD_SDIO on reset"),
    ('XPD_SDIO_REG',         "config",      0, 4, 1 << 14,    5, None, "flag", "If XPD_SDIO_FORCE, enable VDD_SDIO reg on reset"),
    ('XPD_SDIO_TIEH',        "config",      0, 4, 1 << 15,    5, None, "flag", "If XPD_SDIO_FORCE & XPD_SDIO_REG, 1=3.3V 0=1.8V"),
    ('SPI_PAD_CONFIG_CLK',   "config",      0, 5, 0x1F << 0,  6, None, "spipin", "Override SD_CLK pad (GPIO6/SPICLK)"),
    ('SPI_PAD_CONFIG_Q',     "config",      0, 5, 0x1F << 5,  6, None, "spipin", "Override SD_DATA_0 pad (GPIO7/SPIQ)"),
    ('SPI_PAD_CONFIG_D',     "config",      0, 5, 0x1F << 10, 6, None, "spipin", "Override SD_DATA_1 pad (GPIO8/SPID)"),
    ('SPI_PAD_CONFIG_HD',    "config",      0, 3, 0x1F << 4,  3, None, "spipin", "Override SD_DATA_2 pad (GPIO9/SPIHD)"),
    ('SPI_PAD_CONFIG_CS0',   "config",      0, 5, 0x1F << 15, 6, None, "spipin", "Override SD_CMD pad (GPIO11/SPICS0)"),
    ('FLASH_CRYPT_CONFIG',   "security",    0, 5, 0x0F << 28, 10, 3, "int", "Flash encryption config (key tweak bits)"),
    ('CHIP_VER_REV1',        "identity",    0, 3, 1 << 15,    0,  0, "flag", "Silicon Revision 1"),
    ('BLK3_PART_RESERVE',    "calibration", 0, 3, 1 << 14,    0,  0, "flag", "BLOCK3 partially served for ADC calibration data"),
    ('CHIP_VERSION',         "identity",    0, 3, 0x03 << 12, 0,  0, "int", "Reserved for future chip versions"),
    ('CHIP_PACKAGE',         "identity",    0, 3, 0x07 << 9,  0,  0, "int", "Chip package identifier"),
    ('CODING_SCHEME',        "efuse",       0, 6, 0x3,        10, 3, "int", "Efuse variable block length scheme"),
    ('CONSOLE_DEBUG_DISABLE',"security",    0, 6, 1 << 2,     15, None, "flag", "Disable ROM BASIC interpreter fallback"),
    ('DISABLE_SDIO_HOST',    "config",      0, 6, 1 << 3,     None, None, "flag", "Disable SDIO host"),
    ('ABS_DONE_0',           "security",    0, 6, 1 << 4,     12, None, "flag", "secure boot enabled for bootloader"),
    ('ABS_DONE_1',           "security",    0, 6, 1 << 5,     13, None, "flag", "secure boot abstract 1 locked"),
    ('JTAG_DISABLE',         "security",    0, 6, 1 << 6,     14, None, "flag", "Disable JTAG"),
    ('DISABLE_DL_ENCRYPT',   "security",    0, 6, 1 << 7,     15, None, "flag", "Disable flash encryption in UART bootloader"),
    ('DISABLE_DL_DECRYPT',   "security",    0, 6, 1 << 8,     15, None, "flag", "Disable flash decryption in UART bootloader"),
    ('DISABLE_DL_CACHE',     "security",    0, 6, 1 << 9,     15, None, "flag", "Disable flash cache in UART bootloader"),
    ('KEY_STATUS',           "efuse",       0, 6, 1 << 10,    10, 3, "flag", "Usage of efuse block 3 (reserved)"),
    ('ADC_VREF',             "calibration", 0, 4, 0x1F << 8,  0,  0, "vref", "Voltage reference calibration"),
    ('BLK1',                 "security",    1, 0, 0xFFFFFFFF, 7,  0, "keyblock", "Flash encryption key"),
    ('BLK2',                 "security",    2, 0, 0xFFFFFFFF, 8,  1, "keyblock", "Secure boot key"),
    ('BLK3',                 "security",    3, 0, 0xFFFFFFFF, 9,  2, "keyblock", "Variable Block 3"),
]

# if BLK3_PART_RESERVE is set, these efuse fields are in BLK3:
BLK3_PART_EFUSES = [
    ('ADC1_TP_LOW',  "calibration", 3, 3, 0x7F << 0,   9, 2, "adc_tp", "ADC1 150mV reading"),
    ('ADC1_TP_HIGH', "calibration", 3, 3, 0x1FF << 7,  9, 2, "adc_tp", "ADC1 850mV reading"),
    ('ADC2_TP_LOW',  "calibration", 3, 3, 0x7F << 16,  9, 2, "adc_tp", "ADC2 150mV reading"),
    ('ADC2_TP_HIGH', "calibration", 3, 3, 0x1FF << 23, 9, 2, "adc_tp", "ADC2 850mV reading"),
]

# Offsets and lengths of each of the 4 efuse blocks
#
# These offsets/lens are for esptool.read_efuse(X) which takes
# a word offset not a byte offset.
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

EFUSE_BURN_TIMEOUT = 0.250  # seconds


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


def efuse_perform_write(esp):
    """ Write the values in the efuse write registers to
    the efuse hardware, then refresh the efuse read registers.
    """
    esp.write_reg(EFUSE_REG_CONF, EFUSE_CONF_WRITE)
    esp.write_reg(EFUSE_REG_CMD, EFUSE_CMD_WRITE)

    def wait_idle():
        deadline = time.time() + EFUSE_BURN_TIMEOUT
        while time.time() < deadline:
            if esp.read_reg(EFUSE_REG_CMD) == 0:
                return
        raise esptool.FatalError("Timed out waiting for Efuse controller command to complete")
    wait_idle()
    esp.write_reg(EFUSE_REG_CONF, EFUSE_CONF_READ)
    esp.write_reg(EFUSE_REG_CMD, EFUSE_CMD_READ)
    wait_idle()


class EfuseField(object):
    @staticmethod
    def from_tuple(esp, efuse_tuple):
        category = efuse_tuple[7]
        return {
            "mac": EfuseMacField,
            "keyblock": EfuseKeyblockField,
            "spipin": EfuseSpiPinField,
            "vref": EfuseVRefField,
            "adc_tp": EfuseAdcPointCalibration,
        }.get(category, EfuseField)(esp, *efuse_tuple)

    def __init__(self, esp, register_name, category, block, word, mask, write_disable_bit, read_disable_bit, efuse_type, description):
        self.category = category
        self.esp = esp
        self.block = block
        self.word = word
        self.data_reg_offs = EFUSE_BLOCK_OFFS[self.block] + self.word
        self.mask = mask
        self.shift = 0
        # self.shift is the number of the least significant bit in the mask
        while mask & 0x1 == 0:
            self.shift += 1
            mask >>= 1
        self.write_disable_bit = write_disable_bit
        self.read_disable_bit = read_disable_bit
        self.register_name = register_name
        self.efuse_type = efuse_type
        self.description = description

    def get_raw(self):
        """ Return the raw (unformatted) numeric value of the efuse bits

        Returns a simple integer or (for some subclasses) a bitstring.
        """
        value = self.esp.read_efuse(self.data_reg_offs)
        return (value & self.mask) >> self.shift

    def get(self):
        """ Get a formatted version of the efuse value, suitable for display """
        return self.get_raw()

    def is_readable(self):
        """ Return true if the efuse is readable by software """
        if self.read_disable_bit is None:
            return True  # read cannot be disabled
        value = (self.esp.read_efuse(0) >> 16) & 0xF  # RD_DIS values
        return (value & (1 << self.read_disable_bit)) == 0

    def disable_read(self):
        if self.read_disable_bit is None:
            raise esptool.FatalError("This efuse cannot be read-disabled")
        rddis_reg_addr = efuse_write_reg_addr(0, 0)
        self.esp.write_reg(rddis_reg_addr, 1 << (16 + self.read_disable_bit))
        efuse_perform_write(self.esp)
        return self.get()

    def is_writeable(self):
        if self.write_disable_bit is None:
            return True  # write cannot be disabled
        value = self.esp.read_efuse(0) & 0xFFFF   # WR_DIS values
        return (value & (1 << self.write_disable_bit)) == 0

    def disable_write(self):
        wrdis_reg_addr = efuse_write_reg_addr(0, 0)
        self.esp.write_reg(wrdis_reg_addr, 1 << self.write_disable_bit)
        efuse_perform_write(self.esp)
        return self.get()

    def burn(self, new_value):
        raw_value = (new_value << self.shift) & self.mask
        # don't both reading old value as we can only set bits 0->1
        write_reg_addr = efuse_write_reg_addr(self.block, self.word)
        self.esp.write_reg(write_reg_addr, raw_value)
        efuse_perform_write(self.esp)
        return self.get()


class EfuseMacField(EfuseField):
    def get_raw(self):
        # MAC values are high half of second efuse word, then first efuse word
        words = [self.esp.read_efuse(self.data_reg_offs + word) for word in [1,0]]
        # endian-swap into a bitstring
        bitstring = struct.pack(">II", *words)
        return bitstring[2:]  # trim 2 byte CRC from the beginning

    def get(self):
        stored_crc = self.get_stored_crc()
        calc_crc = self.calc_crc()
        if calc_crc == stored_crc:
            valid_msg = "(CRC %02x OK)" % stored_crc
        else:
            valid_msg = "(CRC %02x invalid - calculated 0x%02x)" % (stored_crc, calc_crc)
        return "%s %s" % (hexify(self.get_raw(), ":"), valid_msg)

    def burn(self, new_value):
        # Writing the BLK0 default MAC is not sensible, as it's written in the factory.
        #
        # TODO: support writing a new base MAC @ efuse BLK3
        raise esptool.FatalError("Writing MAC address is not supported")

    def get_stored_crc(self):
        return (self.esp.read_efuse(self.data_reg_offs + 1) >> 16) & 0xFF

    def calc_crc(self):
        """
        This algorithm is the equivalent of esp_crc8() in ESP32 ROM code

        This is CRC-8 w/ inverted polynomial value 0x8C & initial value 0x00.
        """
        mac = self.get_raw()
        result = 0x00
        for b in struct.unpack("B" * 6, mac):
            result ^= b
            for _ in range(8):
                lsb = result & 1
                result >>= 1
                if lsb != 0:
                    result ^= 0x8c
        return result


class EfuseKeyblockField(EfuseField):
    def get_raw(self):
        words = [self.esp.read_efuse(self.data_reg_offs + word) for word in range(8)]
        # Reading EFUSE registers to a key string:
        # endian swap each word, and also reverse
        # the overall word order.
        bitstring = struct.pack(">" + ("I" * 8), *words[::-1])
        return bitstring

    def get(self):
        return hexify(self.get_raw(), " ")

    def burn(self, new_value):
        words = struct.unpack(">" + ("I" * 8), new_value)  # endian-swap
        words = words[::-1]  # reverse from natural key order
        write_reg_addr = efuse_write_reg_addr(self.block, self.word)
        for word in words:
            self.esp.write_reg(write_reg_addr, word)
            write_reg_addr += 4
        efuse_perform_write(self.esp)
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
    for category in set(e.category for e in efuses):
        print("%s fuses:" % category.title())
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
            value = str(e.get())
            print("%-22s %-50s%s= %s %s %s" % (e.register_name, e.description, "\n  " if len(value) > 20 else "", value, perms, raw))
        print("")
    sdio_force = _get_efuse(efuses, "XPD_SDIO_FORCE")
    sdio_tieh = _get_efuse(efuses, "XPD_SDIO_TIEH")
    sdio_reg = _get_efuse(efuses, "XPD_SDIO_REG")
    if sdio_force.get() == 0:
        print("Flash voltage (VDD_SDIO) determined by GPIO12 on reset (High for 1.8V, Low/NC for 3.3V).")
    elif sdio_reg.get() == 0:
        print("Flash voltage (VDD_SDIO) internal regulator disabled by efuse.")
    elif sdio_tieh.get() == 0:
        print("Flash voltage (VDD_SDIO) set to 1.8V by efuse.")
    else:
        print("Flash voltage (VDD_SDIO) set to 3.3V by efuse.")


def burn_efuse(esp, efuses, args):
    efuse = _get_efuse(efuses, args.efuse_name)
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
    efuse = _get_efuse(efuses, args.efuse_name)
    if not efuse.is_readable():
        print("Efuse %s is already read protected" % efuse.register_name)
    else:
        # make full list of which efuses will be disabled (ie share a read disable bit)
        all_disabling = [e for e in efuses if e.read_disable_bit == efuse.read_disable_bit]
        names = ", ".join(e.register_name for e in all_disabling)
        confirm("Permanently read-disabling efuse%s %s" % ("s" if len(all_disabling) > 1 else "",names), args)
        efuse.disable_read()


def write_protect_efuse(esp, efuses, args):
    efuse = _get_efuse(efuses, args.efuse_name)
    if not efuse.is_writeable():
        print("Efuse %s is already write protected" % efuse.register_name)
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

    # check keyfile
    keyfile = args.keyfile
    keyfile.seek(0,2)  # seek t oend
    size = keyfile.tell()
    keyfile.seek(0)
    if size != 32:
        raise esptool.FatalError("Incorrect key file size %d. Key file must be 32 bytes (256 bits) of raw binary key data." % size)

    # check existing data
    efuse = [e for e in efuses if e.register_name == "BLK%d" % block_num][0]
    original = efuse.get_raw()
    EMPTY_KEY = b'\x00' * 32
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

    new_value = keyfile.read(32)
    new = efuse.burn(new_value)
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


def set_flash_voltage(esp, efuses, args):
    sdio_force = _get_efuse(efuses, "XPD_SDIO_FORCE")
    sdio_tieh = _get_efuse(efuses, "XPD_SDIO_TIEH")
    sdio_reg = _get_efuse(efuses, "XPD_SDIO_REG")

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
    adc_vref = _get_efuse(efuses, "ADC_VREF")
    blk3_reserve = _get_efuse(efuses, "BLK3_PART_RESERVE")

    vref_raw = adc_vref.get_raw()
    if vref_raw == 0:
        print("ADC VRef calibration: None (1100mV nominal)")
    else:
        print("ADC VRef calibration: %dmV" % adc_vref.get())

    if blk3_reserve.get():
        print("ADC readings stored in efuse BLK3:")
        print("    ADC1 Low reading  (150mV): %d" % _get_efuse(efuses, "ADC1_TP_LOW").get())
        print("    ADC1 High reading (850mV): %d" % _get_efuse(efuses, "ADC1_TP_HIGH").get())
        print("    ADC2 Low reading  (150mV): %d" % _get_efuse(efuses, "ADC2_TP_LOW").get())
        print("    ADC2 High reading (850mV): %d" % _get_efuse(efuses, "ADC2_TP_HIGH").get())


def hexify(bitstring, separator):
    try:
        as_bytes = tuple(ord(b) for b in bitstring)
    except TypeError:  # python 3, items in bitstring already ints
        as_bytes = tuple(b for b in bitstring)
    return separator.join(("%02x" % b) for b in as_bytes)


def main():
    parser = argparse.ArgumentParser(description='espefuse.py v%s - ESP32 efuse get/set tool' % esptool.__version__, prog='espefuse')

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default=os.environ.get('ESPTOOL_PORT', esptool.ESPLoader.DEFAULT_PORT))

    parser.add_argument(
        '--before',
        help='What to do before connecting to the chip',
        choices=['default_reset', 'no_reset', 'esp32r1'],
        default='default_reset')

    parser.add_argument('--do-not-confirm',
                        help='Do not pause for confirmation before permanently writing efuses. Use with caution.', action='store_true')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run espefuse.py {command} -h for additional help')

    subparsers.add_parser('dump', help='Dump raw hex values of all efuses')
    subparsers.add_parser('summary',
                          help='Print human-readable summary of efuse values')

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
    p.add_argument('--force-write-always', help="Write the key even if it looks like it's already been written, or is write protected. " +
                   "Note that this option can't disable write protection, or clear any bit which has already been set.", action='store_true')
    p.add_argument('block', help='Key block to burn. "flash_encryption" is an alias for BLK1, ' +
                   '"secure_boot" is an alias for BLK2.', choices=["secure_boot", "flash_encryption","BLK1","BLK2","BLK3"])
    p.add_argument('keyfile', help='File containing 256 bits of binary key data', type=argparse.FileType('rb'))

    p = subparsers.add_parser('set_flash_voltage',
                              help='Permanently set the internal flash voltage regulator to either 1.8V, 3.3V or OFF. ' +
                              'This means GPIO12 can be high or low at reset without changing the flash voltage.')
    p.add_argument('voltage', help='Voltage selection',
                   choices=['1.8V', '3.3V', 'OFF'])

    p = subparsers.add_parser('adc_info',
                              help='Display information about ADC calibration data stored in efuse.')

    args = parser.parse_args()
    print('espefuse.py v%s' % esptool.__version__)
    if args.operation is None:
        parser.print_help()
        parser.exit(1)

    # each 'operation' is a module-level function of the same name
    operation_func = globals()[args.operation]

    esp = esptool.ESP32ROM(args.port)
    esp.connect(args.before)

    # dict mapping register name to its efuse object
    efuses = [EfuseField.from_tuple(esp, efuse) for efuse in EFUSES]
    if _get_efuse(efuses, "BLK3_PART_RESERVE").get():
        # add these BLK3 efuses, if the BLK3_PART_RESERVE flag is set...
        efuses += [EfuseField.from_tuple(esp, efuse) for efuse in BLK3_PART_EFUSES]
    operation_func(esp, efuses, args)


def _get_efuse(efuses, efuse_name):
    return [e for e in efuses if efuse_name == e.register_name][0]


def _main():
    try:
        main()
    except esptool.FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)


if __name__ == '__main__':
    _main()
