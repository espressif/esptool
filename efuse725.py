#!/usr/bin/env python
# Chip 7.2.2 temporary efuse utility
#
# Commands:
#
#
from __future__ import division, print_function

import argparse
import os
import reedsolo
import struct
import sys
import time
import hashlib

import esptool

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.utils import int_to_bytes

KEY_PURPOSES = [
    "USER",
    "RESERVED",
    "XTS_AES_256_KEY_1",
    "XTS_AES_256_KEY_2",
    "XTS_AES_128_KEY",
    "HMAC_DOWN_ALL",
    "HMAC_DOWN_JTAG",
    "HMAC_DOWN_DIGITAL_SIGNATURE",
    "HMAC_UP",
    "SECURE_BOOT_DIGEST0",
    "SECURE_BOOT_DIGEST1",
    "SECURE_BOOT_DIGEST2",
]

EFUSE_BASE = 0x60008800

# List of efuse blocks
#
# Name, Index, Read Address, Read Protect Bit, Write Protect Bit
BLOCKS = [
    # note: we include RD_WR_DIS_REG as part of BLOCK0, not its own block - so 0x2c not 0x30
    ("BLOCK0",         0, EFUSE_BASE + 0x02c, None, None),
    ("MAC_SPI_SYS",    1, EFUSE_BASE + 0x044, None, None),
    ("SYS_PART1",      2, EFUSE_BASE + 0x05c, None, 20),
    ("BLOCK_USR_DATA", 3, EFUSE_BASE + 0x07c, None, 22),
    ("BLOCK_KEY0",     4, EFUSE_BASE + 0x09c, 0,    23),
    ("BLOCK_KEY1",     5, EFUSE_BASE + 0x0bc, 1,    24),
    ("BLOCK_KEY2",     6, EFUSE_BASE + 0x0dc, 2,    25),
    ("BLOCK_KEY3",     7, EFUSE_BASE + 0x0fc, 3,    26),
    ("BLOCK_KEY4",     8, EFUSE_BASE + 0x11c, 4,    27),
    ("BLOCK_KEY5",     9, EFUSE_BASE + 0x13c, 5,    28),
    ("BLOCK_KEY6" ,   10, EFUSE_BASE + 0x15c, 6,    29),
]

EFUSE_RD_RS_ERR0_REG = EFUSE_BASE + 0x1c0
EFUSE_RD_RS_ERR1_REG = EFUSE_BASE + 0x1c4

# error reg, err num shift (0x7 << N), fail bit
BLOCK_ERRORS = [  # NOTE: THIS ORDER IS FROM REGISTERS BUT IT IS *WRONG*
    None,  # BLOCK0
    (EFUSE_RD_RS_ERR0_REG, 0,   3),
    (EFUSE_RD_RS_ERR0_REG, 4,   7),
    (EFUSE_RD_RS_ERR0_REG, 8,  11),
    (EFUSE_RD_RS_ERR0_REG, 12, 15),  # KEY 0
    (EFUSE_RD_RS_ERR0_REG, 16, 19),
    (EFUSE_RD_RS_ERR0_REG, 20, 23),
    (EFUSE_RD_RS_ERR0_REG, 24, 27),
    (EFUSE_RD_RS_ERR0_REG, 28, 31),  # KEY 4
    (EFUSE_RD_RS_ERR1_REG, 0,   3),
    (EFUSE_RD_RS_ERR1_REG, 4,   7),  # KEY 6
    ]

BLOCK_BY_NAME = dict((b[0], b) for b in BLOCKS)

# Table of some BLK0 efuses (name, word in block, mask, write disable bit)
#
# Block starts from RD_WR_DIS, so 1==EFUSE_RD_REPEAT_DATA0_REG, etc.
#
# INCOMPLETE - TODO is to add all remaining efuse types
BLK0_EFUSES = [
    ( 'WR_DIS',  0, 0xFFFFFFFF, None),
    ( 'DIS_DOWNLOAD_MANUAL_ENCRYPT', 1, (1<<19), 2),
    ( 'HARD_DIS_JTAG', 1, 1<<19, 2),
    ( 'SOFT_DIS_JTAG', 1, 7<<16, 31),
    ( 'DIS_USB',       1, 1<<13, 2),
    ( 'DIS_DOWNLOAD_DCACHE', 1, 1<<11, 2),
    ( 'DIS_DOWNLOAD_ICACHE', 1, 1<<10, 2),
    ( 'RD_DIS',           1, 0x7F, 0),
    ( 'KEY_PURPOSE_1',    2, 0xF<<28, 9),
    ( 'KEY_PURPOSE_0',    2, 0xF<<24, 8),
    ( 'SECURE_BOOT_KEY_REVOKE2', 2, 1<<23, 7),
    ( 'SECURE_BOOT_KEY_REVOKE1', 2, 1<<22, 6),
    ( 'SECURE_BOOT_KEY_REVOKE0', 2, 1<<21, 5),
    ( 'CRYPT_CNT',               2, 7<<18, 4),
    ( 'SECURE_BOOT_AGGRESSIVE_REVOKE', 3, 1<<21, 16),
    ( 'SECURE_BOOT_EN',                3, 1<<20, 15),
    ( 'FLASH_DELAY',                   3, 0xF<<28,18),
    ( 'KEY_PURPOSE_6',                 3, 0xF<<16, 14),
    ( 'KEY_PURPOSE_5',                 3, 0xF<<12, 13),
    ( 'KEY_PURPOSE_4',                 3, 0xF<<8,  12),
    ( 'KEY_PURPOSE_3',                 3, 0xF<<4,  11),
    ( 'KEY_PURPOSE_2',                 3, 0xF<<0,  10),
    ( 'UART_PRINT_CONTROL',            4, 0X3<<6, 18),
    ( 'ENABLE_SECURITY_DOWNLOAD',      4, 1<<5, 18),
    ( 'DIS_USB_DOWNLOAD_MODE',         4, 1<<4, 18),  # guessing write-protect for these
    ( 'DIS_TINY_BASIC',                4, 1<<3, 18),
    ( 'UART_PRINT_CHANNEL',            4, 1<<2, 18),
    ( 'DIS_LEGACY_SPI_BOOT',           4, 1<<1, 18),
    ( 'DIS_DOWNLOAD_MODE',             4, 1<<0, 18),
]

BLK0_BY_NAME = dict( (e[0], e) for e in BLK0_EFUSES )

EFUSE_CLK_REG =    EFUSE_BASE + 0x1c8
EFUSE_CONF_REG =   EFUSE_BASE + 0x1cc
EFUSE_STATUS_REG = EFUSE_BASE + 0x1d0
EFUSE_CMD_REG =    EFUSE_BASE + 0x1d4

EFUSE_WRITE_OP_CODE = 0x5a5a
EFUSE_READ_OP_CODE = 0x5aa5

EFUSE_PGM_CMD = 1<<1
EFUSE_READ_CMD = 1<<0

EFUSE_PGM_DATA0_REG = EFUSE_BASE
EFUSE_CHECK_VALUE0_REG = EFUSE_BASE + 0x020


def dump(esp, args):
    """ Dump raw efuse block contents """
    for (name,idx,read_addr,_,_) in BLOCKS:
        print("BLOCK%d (%s):" % (idx, name))
        addrs = range(read_addr, read_addr + 32, 4)
        print(" ".join(["%08x" % esp.read_reg(addr) for addr in addrs]))
    print("")
    print("RD_RS_ERR0_REG 0x%08x RD_RS_ERR1_REG 0x%08x" % (
        esp.read_reg(EFUSE_RD_RS_ERR0_REG),
        esp.read_reg(EFUSE_RD_RS_ERR1_REG)))

def _shift(mask):
    shift = 0
    while mask & 0x1 == 0:
        shift += 1
        mask >>= 1
    return shift


def summary(esp, args):
    rd_dis = _get_efuse_value(esp, "RD_DIS")
    wr_dis = _get_efuse_value(esp, "WR_DIS")
    print("BLOCK0:")
    for (name,_,_,wr_dis_bit) in BLK0_EFUSES:
        value = _get_efuse_value(esp, name)
        wr_disabled = wr_dis_bit and (wr_dis & (1<<wr_dis_bit))
        write = "WRITE DISABLED" if wr_disabled else ""
        print("%30s: value 0x%-8x %s" % (name, value, write))
    for name,idx,read_addr,rd_dis_bit,wr_dis_bit in BLOCKS[1:]:
        err_msg = "0 errors"
        errs, fail = _get_block_errors(esp, idx)
        if errs !=0 or fail:
            err_msg = "ERRORS:%d FAIL:%s" % (errs, fail)

        print("")
        print("BLOCK%d (%s) (%s):" % (idx, name, err_msg))
        if name.startswith("BLOCK_KEY"):
            key_num = idx - 4
            purpose = _get_efuse_value(esp, "KEY_PURPOSE_%d" % key_num)
            print("  Purpose: %s" % KEY_PURPOSES[purpose])
        if rd_dis_bit and (rd_dis & (1<<rd_dis_bit)):
            print("  READ DISABLED")
        if wr_dis_bit and (wr_dis & (1<<wr_dis_bit)):
            print("  WRITE DISABLED")
        addrs = range(read_addr, read_addr + 32, 4)
        print("  " + " ".join(["%08x" % esp.read_reg(addr) for addr in addrs]))


def _get_efuse_value(esp, name):
    blk0_read = BLOCKS[0][2]
    efuse = BLK0_BY_NAME[name]
    word = efuse[1]
    value = esp.read_reg(blk0_read + 4 * word)
    mask = efuse[2]
    value = value & mask
    value >>= _shift(mask)
    return value


def _clear_pgm_registers(esp):
    _wait_efuse_idle(esp)
    for r in range(EFUSE_PGM_DATA0_REG, EFUSE_PGM_DATA0_REG + 32, 4):
        esp.write_reg(r, 0)

def _wait_efuse_idle(esp):
    while esp.read_reg(EFUSE_STATUS_REG) & 0x7 != 1:
        pass


def _efuse_program(esp, block_num):
    _wait_efuse_idle(esp)
    esp.write_reg(EFUSE_CONF_REG, EFUSE_WRITE_OP_CODE)
    esp.write_reg(EFUSE_CMD_REG, EFUSE_PGM_CMD | (block_num << 2))  # block == 0

    while esp.read_reg(EFUSE_CMD_REG) & EFUSE_PGM_CMD != 0:
        pass
    _clear_pgm_registers(esp)
    _efuse_read(esp)


def _efuse_read(esp):
    _wait_efuse_idle(esp)
    esp.write_reg(EFUSE_CONF_REG, EFUSE_READ_OP_CODE)
    esp.write_reg(EFUSE_CMD_REG, EFUSE_READ_CMD)
    _wait_efuse_idle(esp)

def _get_block_errors(esp, block_num):
    """ Returns (error count, failure boolean flag) """
    read_reg, err_shift, fail_shift = BLOCK_ERRORS[block_num]

    raw = esp.read_reg(read_reg)
    return ((raw >> err_shift) & 0x7, (raw & 1<<fail_shift) != 0)

def burn_efuse(esp, args):
    efuse = BLK0_BY_NAME[args.efuse_name]
    mask = efuse[2]
    value = args.value << _shift(mask)
    if value & mask != value:
        raise esptool.FatalError("Value too long for field - 0x%x masks to 0x%x" % (args.value, (value & mask) >> _shift(mask)))

    _clear_pgm_registers(esp)
    _wait_efuse_idle(esp)

    word = efuse[1]
    esp.write_reg(EFUSE_PGM_DATA0_REG + 4 * word, value)
    _efuse_program(esp, 0)
    print("Done")

def burn_key(esp, args, data=None):
    block_num = args.key_block + BLOCK_BY_NAME["BLOCK_KEY0"][1]
    block = BLOCKS[block_num]
    purpose_num = KEY_PURPOSES.index(args.purpose)

    if data is None:
        data = args.file.read()
    if len(data) != 32:
        raise esptool.FatalError("File must be exactly 32 bytes (this file was %d)" % (len(data)))

    if args.purpose in [ "XTS_AES_256_KEY_1", "XTS_AES_256_KEY_2", "XTS_AES_128_KEY" ]:
        print("Reversing byte order for AES-XTS hardware peripheral...")
        data = data[::-1]

    # apply RS encoding
    rs = reedsolo.RSCodec(12)
    encoded_data = rs.encode([x for x in data]) # 32 byte of data + 12 bytes RS
    words = struct.unpack("<" + "I"*11, encoded_data)

    # write key data
    _clear_pgm_registers(esp)
    for i in range(8):
        esp.write_reg(EFUSE_PGM_DATA0_REG + 4 * i, words[i])
    for i in range(3):
        esp.write_reg(EFUSE_CHECK_VALUE0_REG + 4 * i, words[i+8])
    _efuse_program(esp, block_num)

    # write purpose register for the key block
    _clear_pgm_registers(esp)
    _,purpose_word,purpose_mask,purpose_wr_dis_bit = BLK0_BY_NAME["KEY_PURPOSE_%d" % args.key_block]
    esp.write_reg(EFUSE_PGM_DATA0_REG + 4 * purpose_word, purpose_num << _shift(purpose_mask))
    _efuse_program(esp, 0)

    print("Write protecting purpose efuse and key block...")
    _,_,_,blk_rd_dis_bit,blk_wr_dis_bit = block
    _clear_pgm_registers(esp)
    new_wr_dir = (1<<blk_wr_dis_bit) | (1<<purpose_wr_dis_bit)
    esp.write_reg(EFUSE_PGM_DATA0_REG, new_wr_dir)
    _efuse_program(esp, 0)

    errs, fail = _get_block_errors(esp, block_num)
    if errs == 0 and not fail:
        print("(No encoding errors in block)")
    else:
        print("WARNING: Block has %d errors (failed=%s)" % (errs, fail))

    print("Done")


def burn_key_digest(esp, args):
    digest = _digest_public_key(args.file)
    if not args.purpose.startswith("SECURE_BOOT_DIGEST"):
        raise esptool.FatalError("This option only works with purpose SECURE_BOOT_DIGESTx")
    return burn_key(esp, args, digest)


def _digest_public_key(keyfile):
    keydata = keyfile.read()
    try:
        private_key = serialization.load_pem_private_key(
            keydata,
            password=None,
            backend=default_backend()
        )
        public_key = private_key.public_key()
    except ValueError:
        public_key = serialization.load_pem_public_key(
            keydata, backend=default_backend())
    if public_key.key_size != 3072:
        raise esptool.FatalError("Key file %s has length %d bits. Secure Boot V2 only supports RSA-3072." % (keyfile.name,
                                                                                                             public_key.key_size))
    
    numbers = public_key.public_numbers()
    n = numbers.n  #
    e = numbers.e  # two public key components

    # Note: this cheats and calls a private 'rsa' method to get the modular
    # inverse calculation.
    m = - rsa._modinv(n, 1<<32)

    rr = 1 << (public_key.key_size * 2)
    rinv = rr % n

    # Encode in the same way it is represented in the signature block
    #
    # Note: the [::-1] is to byte swap all of the bignum
    # values (signatures, coefficients) to little endian
    # for use with the RSA peripheral, rather than big endian
    # which is conventionally used for RSA.
    binary_format = struct.pack("<384sI384sI",
                                int_to_bytes(n)[::-1],
                                e,
                                int_to_bytes(rinv)[::-1],
                                m & 0xFFFFFFFF)

    return hashlib.sha256(binary_format).digest()

def main():
    parser = argparse.ArgumentParser(description='efuse722.py v%s - Chip 7.2.2 efuse get/set tool' % esptool.__version__, prog='espefuse')

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default=os.environ.get('ESPTOOL_PORT', esptool.ESPLoader.DEFAULT_PORT))

    parser.add_argument(
        '--before',
        help='What to do before connecting to the chip',
        choices=['default_reset', 'no_reset', 'esp32r1'],
        default='default_reset')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run espefuse.py {command} -h for additional help')

    subparsers.add_parser('dump', help='Dump raw hex values of all efuses')

    subparsers.add_parser('summary', help='Summary of all known efuse values')

    p = subparsers.add_parser('burn_efuse',
                              help='Burn the efuse with the specified name')
    p.add_argument('efuse_name', help='Name of efuse register to burn',
                   choices=[efuse[0] for efuse in BLK0_EFUSES])
    p.add_argument('value', help='New value to burn',
                   type=esptool.arg_auto_int)

    p = subparsers.add_parser('burn_key',
                              help='Burn the key block with the specified name')
    p.add_argument('file', help='File to write (must be 32 bytes long)',
                   type=argparse.FileType('rb'))
    p.add_argument('key_block', help='Number of key block to burn',
                   type=int, choices=range(0,7))
    p.add_argument('purpose', help='Purpose to set)',
                   choices=KEY_PURPOSES)

    p = subparsers.add_parser('burn_key_digest',
                              help='Parse a RSA public key and burn the digest to key efuse block')
    p.add_argument('file', help='Key file to digest (PEM format)',
                   type=argparse.FileType('r'))
    p.add_argument('key_block', help='Number of key block to burn',
                   type=int, choices=range(0,7))
    p.add_argument('purpose', help='Purpose to set)',
                   choices=KEY_PURPOSES)

    args = parser.parse_args()

    # each 'operation' is a module-level function of the same name
    operation_func = globals()[args.operation]

    esp = esptool.ESP32ROM(args.port)
    esp.connect(args.before)

    operation_func(esp, args)

def _main():
    try:
        main()
    except esptool.FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)


if __name__ == '__main__':
    _main()
