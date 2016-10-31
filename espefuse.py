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
import esptool
import argparse
import sys
import os
import struct

# Table of efuse values - (category, block, word in block, mask, write disable bit, read disable bit, register name, type, description)
# Match values in efuse_reg.h & Efuse technical reference chapter
EFUSES = [
    ('WR_DIS',               "efuse",    0, 0, 0x0000FFFF, 1, None, "int", "EFUSE write disable"),
    ('RD_DIS',               "efuse",    0, 0, 0x000F0000, 0, None, "int", "EFUSE read disable"),
    ('RD_FLASH_CRYPT_CNT',   "security", 0, 0, 0x0FF00000, 2, None, "bitcount", "Flash encryption bit counter"),
    ('MAC',                  "identity", 0, 1, 0xFFFFFFFF, 3, None, "mac", "MAC Address"),
    ('SPI_PAD_CONFIG_HD',    "config",   0, 3, 0x1F<<4,    3, None, "int", "SPI pad config hd"),
    ('XPD_SDIO_REG',         "config",   0, 4, 1<<14,      5, None, "flag", "?"),
    ('XPD_SDIO_TIEH',        "config",   0, 4, 1<<15,      5, None, "flag", "?"),
    ('XPD_SDIO_FORCE',       "config",   0, 4, 1<<16,      5, None, "flag", "?"),
    ('SPI_PAD_CONFIG_CLK',   "config",   0, 5, 0x1F<<0,    6, None, "int", "Override SPI flash CLK pad"),
    ('SPI_PAD_CONFIG_Q',     "config",   0, 5, 0x1F<<5,    6, None, "int", "Override SPI flash Q pad"),
    ('SPI_PAD_CONFIG_D',     "config",   0, 5, 0x1F<<10,   6, None, "int", "Override SPI flash D pad"),
    ('SPI_PAD_CONFIG_CS0',   "config",   0, 5, 0x1F<<15,   6, None, "int", "Override SPI flash CS pad"),
    ('FLASH_CRYPT_CONFIG',   "config",   0, 5, 0x0F<<15,   10, 3, "int", "Flash encryption config"),
    ('CODING_SCHEME',        "efuse",    0, 6, 0x3,        10, 3, "int", "efuse controller coding scheme"),
    ('CONSOLE_DEBUG_DISABLE',"security", 0, 6, 1<<2,       15, None, "flag", "disable console debug output"),
    ('ABS_DONE_0',           "security", 0, 6, 1<<4,       12, None, "flag", "secure boot enabled for bootloader"),
    ('ABS_DONE_1',           "security", 0, 6, 1<<5,       13, None, "flag", "secure boot abstract 1 locked"),
    ('JTAG_DISABLE',         "security", 0, 6, 1<<6,       14, None, "flag", "JTAG disabled"),
    ('DISABLE_DL_ENCRYPT',   "security", 0, 6, 1<<7,       15, None, "flag", "Disable encrypted download"),
    ('DISABLE_DL_DECRYPT',   "security", 0, 6, 1<<8,       15, None, "flag", "Disable decrypted download?"),
    ('DISABLE_DL_CACHE',     "security", 0, 7, 1<<9,       15, None, "flag", "Disable cache when boot mode is download"),
    ('KEY_STATUS',           "efuse",    0, 8, 1<<10,      10, 3, "flag", "Key status of efuse block 3"),
    ('BLK1',                 "security", 1, 0, 0xFFFFFFFF, 7,  0, "keyblock", "Block holding flash encryption key"),
    ('BLK2',                 "security", 2, 0, 0xFFFFFFFF, 8,  1, "keyblock", "Block holding secure boot key"),
    ('BLK3',                 "security", 3, 0, 0xFFFFFFFF, 9,  2, "keyblock", "Variable Block 3"),
]

# These offsets/lens are for read_efuse(X) which takes
# a word offset not a byte offset.
EFUSE_BLOCK_OFFS = [ 0, 14, 22, 30 ]
EFUSE_BLOCK_LEN  = [ 7, 8, 8, 8 ]

# EFUSE registers & command/conf values
EFUSE_REG_CONF = 0x3FF5A0FC
EFUSE_CONF_WRITE = 0x5A5A
EFUSE_CONF_READ =  0x5AA5
EFUSE_REG_CMD  = 0x3FF5A104
EFUSE_CMD_WRITE = 0x2
EFUSE_CMD_READ  = 0x1
# address of first word of write registers for each efuse
EFUSE_REG_WRITE = [ 0x3FF5A01C, 0x3FF5A098, 0x3FF5A0B8, 0x3FF5A0D8 ]

def confirm(action, args):
    print("%s. This is an irreversible operation." % action)
    print("Type 'BURN' (all capitals) to continue.")
    yes = raw_input()
    if yes != "BURN":
        print "Aborting."
        sys.exit(0)


def efuse_write_reg_addr(block, word):
    """
    Return the physical address of the efuse write data register
    block X word X.
    """
    return EFUSE_REG_WRITE[block] + 4*word


def efuse_perform_write(esp):
    """ Write the values in the efuse write registers to
    the efuse hardware, then refresh the efuse read registers.
    """
    esp.write_reg(EFUSE_REG_CONF, EFUSE_CONF_WRITE)
    esp.write_reg(EFUSE_REG_CMD, EFUSE_CMD_WRITE)
    def wait_idle():
        for _ in range(10):
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
            "mac" : EfuseMacField,
            "bitcount" : EfuseBitcountField,
            "keyblock" : EfuseKeyblockField,
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
        return (value & self.read_disable_bit) == 0

    def is_writeable(self):
        value = self.esp.read_efuse(0) & 0xFFFF   # WR_DIS values
        return (value & self.write_disable_bit) == 0

    def burn(self, new_value):
        raw_value = (new_value << self.shift) & self.mask
        # don't both reading old value as we can only set bits 0->1
        write_reg_addr = efuse_write_reg_addr(self.block, self.word)
        self.esp.write_reg(write_reg_addr, raw_value)
        efuse_perform_write(self.esp)
        return self.get()


class EfuseMacField(EfuseField):
    def get_raw(self):
        words = [ self.esp.read_efuse(self.data_reg_offs + word) for word in range(2) ]
        # endian-swap into a bitstring
        bitstring = struct.pack(">II", *words)
        return bitstring[:6]  # currently trims 2 byte CRC

    def get(self):
        return ":".join("%02x" % ord(b) for b in self.get_raw())

    def burn(self, new_value):
        # need to calculate the CRC before we can write the MAC
        raise FatalError("Writing MAC address is not yet supported")


class EfuseKeyblockField(EfuseField):
    def get_raw(self):
        words = [ self.esp.read_efuse(self.data_reg_offs + word) for word in range(8) ]
        # Reading EFUSE registers to a key string:
        # endian swap each word, and also reverse
        # the overall word order.
        bitstring = struct.pack(">"+"I"*8, *words[::-1])
        return bitstring

    def get(self):
        return " ".join("%02x" % ord(b) for b in self.get_raw())

    def burn(self, new_value):
        words = struct.unpack(">"+"I"*8, new_value)  # endian-swap
        words = words[::-1]  # reverse from natural key order
        write_reg_addr = efuse_write_reg_addr(self.block, self.word)
        for word in words:
            self.esp.write_reg(write_reg_addr, word)
            write_reg_addr += 4
        efuse_perform_write(self.esp)
        return self.get()


class EfuseBitcountField(EfuseField):
    def get(self):
        return bin(self.get_raw()).count('1')


def dump(esp, _efuses, args):
    """ Dump raw efuse data registers """
    for block in range(len(EFUSE_BLOCK_OFFS)):
        print "EFUSE block %d:" % block
        offsets = [x+EFUSE_BLOCK_OFFS[block] for x in range(EFUSE_BLOCK_LEN[block])]
        print(offsets)
        print " ".join(["%08x" % esp.read_efuse(offs) for offs in offsets])


def summary(esp, efuses, args):
    """ Print a human-readable summary of efuse contents """
    for category in set(e.category for e in efuses):
        print "%s fuses:" % category.title()
        for e in (e for e in efuses if e.category == category):
            raw = e.get_raw()
            try:
                raw = "(0x%x)" % raw
            except:
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
            print "%-22s %-40s%s= %s %s %s" % (e.register_name, e.description, "\n  " if len(value) > 20 else "", value, perms, raw)
        print ""

def burn_efuse(esp, efuses, args):
    efuse = [e for e in efuses if args.efuse_name == e.register_name][0]
    if efuse.efuse_type == "flag":
        old = efuse.get()
        if old:
            print "Efuse %s is already burned." % efuse.register_name
            return
        confirm("Burning efuse %s (%s)" % (efuse.register_name, efuse.description),
                args)
        new_value = efuse.burn(1)
        if not new_value:
            raise esptool.FatalError("Efuse %s failed to burn. Protected?" % efuse.register_name)

def burn_key(esp, efuses, args):
    # check block choice
    if args.block in ["flash_encrypt", "BLK1" ]:
        block_num = 1
    elif args.block in ["secure_boot", "BLK2" ]:
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
    # TODO: allow --force argument to turn these errors into warnings
    if original != '\x00'*32:
        raise esptool.FatalError("Key block already has value %s." % efuse.get())
    if not efuse.is_writeable:
        raise esptool.FatalError("The efuse block has already been write protected.")
    confirm("Write key in efuse block %d" % block_num, args)

    new_value = keyfile.read(32)
    new = efuse.burn(new_value)
    print "Burned key data. New value: %s" % (new,)

def main():
    parser = argparse.ArgumentParser(description='espefuse.py v%s - ESP32 efuse get/set tool' % esptool.__version__, prog='espefuse')

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default=os.environ.get('ESPTOOL_PORT', esptool.ESPLoader.DEFAULT_PORT))

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

    p = subparsers.add_parser('burn_key',
                              help='Burn a 256-bit AES key to EFUSE BLK1,BLK2 or BLK3 (flash_encrypt, secure_boot).')
    p.add_argument('--no-protect-key', help='Disable default read- and write-protecting of the key. If this option is not set, once the key is flashed it cannot be read back or changed.', action='store_true')
    p.add_argument('block', help='Key block to burn. "flash_encrypt" is an alias for BLK1, "secure_boot" is an alias for BLK2.', choices=["secure_boot","flash_encrypt","BLK1","BLK2","BLK3"])
    p.add_argument('keyfile', help='File containing 256 bits of binary key data', type=file)

    args = parser.parse_args()
    print 'espefuse.py v%s' % esptool.__version__
    # each 'operation' is a module-level function of the same name
    operation_func = globals()[args.operation]


    esp = esptool.ESP32ROM(args.port)

    # dict mapping register name to its efuse object
    efuses = [ EfuseField.from_tuple(esp, efuse) for efuse in EFUSES ]
    operation_func(esp, efuses, args)


if __name__ == '__main__':
    try:
        main()
    except esptool.FatalError as e:
        print '\nA fatal error occurred: %s' % e
        sys.exit(2)
