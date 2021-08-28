#!/usr/bin/env python
# This file describes the common eFuses structures for chips
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

import argparse
import binascii
import re
import sys

from bitstring import BitArray, BitString

import esptool

from . import util


class CheckArgValue(object):
    def __init__(self, efuses, name):
        self.efuses = efuses
        self.name = name

    def __call__(self, new_value_str):
        def check_arg_value(efuse, new_value):
            if efuse.efuse_type.startswith("bool"):
                new_value = 1 if new_value is None else int(new_value, 0)
                if new_value != 1:
                    raise argparse.ArgumentTypeError("New value is not accepted for efuse '{}' (will always burn 0->1), given value={}"
                                                     .format(efuse.name, new_value))
            elif efuse.efuse_type.startswith(('int', 'uint')):
                if efuse.efuse_class == "bitcount":
                    if new_value is None:
                        # find the first unset bit and set it
                        old_value = efuse.get_raw()
                        new_value = old_value
                        bit = 1
                        while new_value == old_value:
                            new_value = bit | old_value
                            bit <<= 1
                    else:
                        new_value = int(new_value, 0)
                else:
                    if new_value is None:
                        raise argparse.ArgumentTypeError("New value required for efuse '{}' (given None)".format(efuse.name))
                    new_value = int(new_value, 0)
                    if new_value == 0:
                        raise argparse.ArgumentTypeError("New value should not be 0 for '{}' (given value= {})".format(efuse.name, new_value))
            elif efuse.efuse_type.startswith("bytes"):
                if new_value is None:
                    raise argparse.ArgumentTypeError("New value required for efuse '{}' (given None)".format(efuse.name))
                if len(new_value) * 8 != efuse.bitarray.len:
                    raise argparse.ArgumentTypeError("The length of efuse '{}' ({} bits) (given len of the new value= {} bits)"
                                                     .format(efuse.name, efuse.bitarray.len, len(new_value) * 8))
            else:
                raise argparse.ArgumentTypeError("The '{}' type for the '{}' efuse is not supported yet.".format(efuse.efuse_type, efuse.name))
            return new_value

        efuse = self.efuses[self.name]
        new_value = efuse.check_format(new_value_str)
        return check_arg_value(efuse, new_value)


class EfuseProtectBase(object):
    # This class is used by EfuseBlockBase and EfuseFieldBase
    def is_readable(self):
        """ Return true if the efuse is readable by software """
        num_bit = self.read_disable_bit
        if num_bit is None:
            return True  # read cannot be disabled
        return (self.parent["RD_DIS"].get() & (1 << num_bit)) == 0

    def disable_read(self):
        num_bit = self.read_disable_bit
        if num_bit is None:
            raise esptool.FatalError("This efuse cannot be read-disabled")
        if not self.parent["RD_DIS"].is_writeable():
            raise esptool.FatalError("This efuse cannot be read-disabled due the to RD_DIS field is already write-disabled")
        self.parent["RD_DIS"].save(1 << num_bit)

    def is_writeable(self):
        num_bit = self.write_disable_bit
        if num_bit is None:
            return True  # write cannot be disabled
        return (self.parent["WR_DIS"].get() & (1 << num_bit)) == 0

    def disable_write(self):
        num_bit = self.write_disable_bit
        if not self.parent["WR_DIS"].is_writeable():
            raise esptool.FatalError("This efuse cannot be write-disabled due to the WR_DIS field is already write-disabled")
        self.parent["WR_DIS"].save(1 << num_bit)

    def check_wr_rd_protect(self):
        if not self.is_readable():
            error_msg = "\t{} is read-protected. The written value can not be read, the efuse/block looks as all 0.\n".format(self.name)
            error_msg += "\tBurn in this case may damage an already written value."
            self.parent.print_error_msg(error_msg)
        if not self.is_writeable():
            error_msg = "\t{} is write-protected. Burn is not possible.".format(self.name)
            self.parent.print_error_msg(error_msg)


class EfuseBlockBase(EfuseProtectBase):
    def __init__(self, parent, param, skip_read=False):
        self.parent = parent
        self.name = param.name
        self.alias = param.alias
        self.id = param.id
        self.rd_addr = param.rd_addr
        self.wr_addr = param.wr_addr
        self.write_disable_bit = param.write_disable_bit
        self.read_disable_bit = param.read_disable_bit
        self.len = param.len
        self.key_purpose_name = param.key_purpose
        bit_block_len = self.get_block_len() * 8
        self.bitarray = BitString(bit_block_len)
        self.bitarray.set(0)
        self.wr_bitarray = BitString(bit_block_len)
        self.wr_bitarray.set(0)
        self.fail = False
        self.num_errors = 0
        if self.id == 0:
            self.err_bitarray = BitString(bit_block_len)
            self.err_bitarray.set(0)
        else:
            self.err_bitarray = None

        if not skip_read:
            self.read()

    def get_block_len(self):
        coding_scheme = self.get_coding_scheme()
        if coding_scheme == self.parent.REGS.CODING_SCHEME_NONE:
            return self.len * 4
        elif coding_scheme == self.parent.REGS.CODING_SCHEME_34:
            return (self.len * 3 // 4) * 4
        elif coding_scheme == self.parent.REGS.CODING_SCHEME_RS:
            return self.len * 4
        else:
            raise esptool.FatalError("Coding scheme (%d) not supported" % (coding_scheme))

    def get_coding_scheme(self):
        if self.id == 0:
            return self.parent.REGS.CODING_SCHEME_NONE
        else:
            return self.parent.coding_scheme

    def get_raw(self, from_read=True):
        if from_read:
            return self.bitarray.bytes
        else:
            return self.wr_bitarray.bytes

    def get(self, from_read=True):
        self.get_bitstring(from_read=from_read)

    def get_bitstring(self, from_read=True):
        if from_read:
            return self.bitarray
        else:
            return self.wr_bitarray

    def convert_to_bitstring(self, new_data):
        if isinstance(new_data, BitArray):
            return new_data
        else:
            return BitArray(bytes=new_data, length=len(new_data) * 8)

    def get_words(self):
        def get_offsets(self):
            return [x + self.rd_addr for x in range(0, self.get_block_len(), 4)]
        return [self.parent.read_reg(offs) for offs in get_offsets(self)]

    def read(self):
        words = self.get_words()
        data = BitArray()
        for word in reversed(words):
            data.append("uint:32=%d" % word)
        self.bitarray.overwrite(data, pos=0)
        self.print_block(self.bitarray, "read_regs")

    def print_block(self, bit_string, comment, debug=False):
        if self.parent.debug or debug:
            bit_string.pos = 0
            print("%-15s (%-16s) [%-2d] %s:" % (self.name, " ".join(self.alias)[:16], self.id, comment),
                  " ".join(["%08x" % word for word in bit_string.readlist('%d*uint:32' % (bit_string.len / 32))[::-1]]))

    def check_wr_data(self):
        wr_data = self.wr_bitarray
        if wr_data.all(False):
            # nothing to burn
            if self.parent.debug:
                print("[{:02}] {:20} nothing to burn".format(self.id, self.name))
            return False
        if len(wr_data.bytes) != len(self.bitarray.bytes):
            raise esptool.FatalError("Data does not fit: the block%d size is %d bytes, data is %d bytes" %
                                     (self.id, len(self.bitarray.bytes), len(wr_data.bytes)))
        self.check_wr_rd_protect()

        if self.get_bitstring().all(False):
            print("[{:02}] {:20} is empty, will burn the new value".format(self.id, self.name))
        else:
            # the written block in chip is not empty
            if self.get_bitstring() == wr_data:
                print("[{:02}] {:20} is already written the same value, continue with EMPTY_BLOCK".format(self.id, self.name))
                wr_data.set(0)
            else:
                print("[{:02}] {:20} is not empty".format(self.id, self.name))
                print("\t(written ):", self.get_bitstring())
                print("\t(to write):", wr_data)
                mask = self.get_bitstring() & wr_data
                if mask == wr_data:
                    print("\tAll wr_data bits are set in the written block, continue with EMPTY_BLOCK.")
                    wr_data.set(0)
                else:
                    coding_scheme = self.get_coding_scheme()
                    if coding_scheme == self.parent.REGS.CODING_SCHEME_NONE:
                        print("\t(coding scheme = NONE)")
                    elif coding_scheme == self.parent.REGS.CODING_SCHEME_RS:
                        print("\t(coding scheme = RS)")
                        error_msg = "\tBurn into %s is forbidden (RS coding scheme does not allow this)." % (self.name)
                        self.parent.print_error_msg(error_msg)
                    elif coding_scheme == self.parent.REGS.CODING_SCHEME_34:
                        print("\t(coding scheme = 3/4)")
                        data_can_not_be_burn = False
                        for i in range(0, self.get_bitstring().len, 6 * 8):
                            rd_chunk = self.get_bitstring()[i:i + 6 * 8:]
                            wr_chunk = wr_data[i:i + 6 * 8:]
                            if rd_chunk.any(True):
                                if wr_chunk.any(True):
                                    print("\twritten chunk [%d] and wr_chunk are not empty. " % (i // (6 * 8)), end="")
                                    if rd_chunk == wr_chunk:
                                        print("wr_chunk == rd_chunk. Countinue with empty chunk.")
                                        wr_data[i:i + 6 * 8:].set(0)
                                    else:
                                        print("wr_chunk != rd_chunk. Can not burn.")
                                        print("\twritten ", rd_chunk)
                                        print("\tto write", wr_chunk)
                                        data_can_not_be_burn = True
                        if data_can_not_be_burn:
                            error_msg = "\tBurn into %s is forbidden (3/4 coding scheme does not allow this)." % (self.name)
                            self.parent.print_error_msg(error_msg)
                    else:
                        raise esptool.FatalError("The coding scheme ({}) is not supported".format(coding_scheme))

    def save(self, new_data):
        # new_data will be checked by check_wr_data() during burn_all()
        # new_data (bytes)  = [0][1][2] ... [N]             (original data)
        # in string format  = [0] [1] [2] ... [N]           (util.hexify(data, " "))
        # in hex format     = 0x[N]....[2][1][0]            (from bitstring print(data))
        # in reg format     = [3][2][1][0] ... [N][][][]    (as it will be in the device)
        # in bitstring      = [N] ... [2][1][0]             (to get a correct bitstring need to reverse new_data)
        # *[x] - means a byte.
        data = BitString(bytes=new_data[::-1], length=len(new_data) * 8)
        if self.parent.debug:
            print("\twritten : {} ->\n\tto write: {}".format(self.get_bitstring(), data))
        self.wr_bitarray.overwrite(self.wr_bitarray | data, pos=0)

    def burn_words(self, words):
        for burns in range(3):
            self.parent.efuse_controller_setup()
            if self.parent.debug:
                print("Write data to BLOCK%d" % (self.id))
            write_reg_addr = self.wr_addr
            for word in words:
                # for ep32s2: using EFUSE_PGM_DATA[0..7]_REG for writing data
                #   32 bytes to EFUSE_PGM_DATA[0..7]_REG
                #   12 bytes to EFUSE_CHECK_VALUE[0..2]_REG. These regs are next after EFUSE_PGM_DATA_REG
                # for esp32:
                #   each block has the special regs EFUSE_BLK[0..3]_WDATA[0..7]_REG for writing data
                if self.parent.debug:
                    print("Addr 0x%08x, data=0x%08x" % (write_reg_addr, word))
                self.parent.write_reg(write_reg_addr, word)
                write_reg_addr += 4

            self.parent.write_efuses(self.id)
            for _ in range(5):
                self.parent.efuse_read()
                self.parent.get_coding_scheme_warnings(silent=True)
                if self.fail or self.num_errors:
                    print("Error in BLOCK%d, re-burn it again (#%d), to fix it. fail_bit=%d, num_errors=%d" % (self.id, burns, self.fail, self.num_errors))
                    break
            if not self.fail and self.num_errors == 0:
                break

    def burn(self):
        if self.wr_bitarray.all(False):
            # nothing to burn
            return
        before_burn_bitarray = self.bitarray[:]
        assert before_burn_bitarray is not self.bitarray
        self.print_block(self.wr_bitarray, "to_write")
        words = self.apply_coding_scheme()
        self.burn_words(words)
        self.read()
        if not self.is_readable():
            print("{} ({}) is read-protected. Read back the burn value is not possible.".format(self.name, self.alias))
            if self.bitarray.all(False):
                print("Read all '0'")
            else:
                # Should never happen
                raise esptool.FatalError("The {} is read-protected but not all '0' ({})".format(self.name, self.bitarray.hex))
        else:
            if self.wr_bitarray == self.bitarray:
                print("BURN BLOCK%-2d - OK (write block == read block)" % self.id)
            elif self.wr_bitarray & self.bitarray == self.wr_bitarray and self.bitarray & before_burn_bitarray == before_burn_bitarray:
                print("BURN BLOCK%-2d - OK (all write block bits are set)" % self.id)
            else:
                # Happens only when an efuse is written and read-protected in one command
                self.print_block(self.wr_bitarray, "Expected")
                self.print_block(self.bitarray, "Real    ")
                # Read-protected BLK0 values are reported back as zeros, raise error only for other blocks
                if self.id != 0:
                    raise esptool.FatalError("Burn {} ({}) was not successful".format(self.name, self.alias))
        self.wr_bitarray.set(0)


class EspEfusesBase(object):
    """
    Wrapper object to manage the efuse fields in a connected ESP bootloader
    """

    _esp    = None
    blocks  = []
    efuses  = []
    coding_scheme = None
    force_write_always = None

    def __iter__(self):
        return self.efuses.__iter__()

    def get_crystal_freq(self):
        return self._esp.get_crystal_freq()

    def read_efuse(self, n):
        """ Read the nth word of the ESP3x EFUSE region. """
        return self._esp.read_efuse(n)

    def read_reg(self, addr):
        return self._esp.read_reg(addr)

    def write_reg(self, addr, value, mask=0xFFFFFFFF, delay_us=0, delay_after_us=0):
        return self._esp.write_reg(addr, value, mask, delay_us, delay_after_us)

    def update_reg(self, addr, mask, new_val):
        return self._esp.update_reg(addr, mask, new_val)

    def efuse_controller_setup(self):
        pass

    def get_index_block_by_name(self, name):
        for block in self.blocks:
            if block.name == name or name in block.alias:
                return block.id
        return None

    def read_blocks(self):
        for block in self.blocks:
            block.read()

    def update_efuses(self):
        for efuse in self.efuses:
            efuse.update(self.blocks[efuse.block].bitarray)

    def burn_all(self):
        print("\nCheck all blocks for burn...")
        print("idx, BLOCK_NAME,          Conclusion")
        have_wr_data_for_burn = False
        for block in self.blocks:
            block.check_wr_data()
            if not have_wr_data_for_burn and block.get_bitstring(from_read=False).any(True):
                have_wr_data_for_burn = True
        if not have_wr_data_for_burn:
            print("Nothing to burn, see messages above.")
            return
        EspEfusesBase.confirm("", self.do_not_confirm)

        # Burn from BLKn -> BLK0. Because BLK0 can set rd or/and wr protection bits.
        for block in reversed(self.blocks):
            old_fail = block.fail
            old_num_errors = block.num_errors
            block.burn()
            if (block.fail and old_fail != block.fail) or (block.num_errors and block.num_errors > old_num_errors):
                raise esptool.FatalError("Error(s) were detected in eFuses")
        print("Reading updated efuses...")
        self.read_coding_scheme()
        self.read_blocks()
        self.update_efuses()

    @staticmethod
    def confirm(action, do_not_confirm):
        print("%s%s\nThis is an irreversible operation!" % (action, "" if action.endswith("\n") else ". "))
        if not do_not_confirm:
            print("Type 'BURN' (all capitals) to continue.")
            sys.stdout.flush()  # required for Pythons which disable line buffering, ie mingw in mintty
            try:
                yes = raw_input()  # raw_input renamed to input in Python 3
            except NameError:
                yes = input()
            if yes != "BURN":
                print("Aborting.")
                sys.exit(0)

    def print_error_msg(self, error_msg):
        if self.force_write_always is not None:
            if not self.force_write_always:
                error_msg += "(use '--force-write-always' option to ignore it)"
        if self.force_write_always:
            print(error_msg, "Skipped because '--force-write-always' option.")
        else:
            raise esptool.FatalError(error_msg)


class EfuseFieldBase(EfuseProtectBase):
    def __init__(self, parent, param):
        self.category = param.category
        self.parent = parent
        self.block = param.block
        self.word = param.word
        self.pos = param.pos
        self.write_disable_bit = param.write_disable_bit
        self.read_disable_bit = param.read_disable_bit
        self.name = param.name
        self.efuse_class = param.class_type
        self.efuse_type = param.type
        self.description = param.description
        self.dict_value = param.dictionary
        self.fail = False
        self.num_errors = 0
        if self.efuse_type.startswith("bool"):
            field_len = 1
        else:
            field_len = int(re.search(r'\d+', self.efuse_type).group())
            if self.efuse_type.startswith("bytes"):
                field_len *= 8
        self.bitarray = BitString(field_len)
        self.bit_len = field_len
        self.bitarray.set(0)
        self.update(self.parent.blocks[self.block].bitarray)

    def check_format(self, new_value_str):
        if new_value_str is None:
            return new_value_str
        else:
            if self.efuse_type.startswith("bytes"):
                if new_value_str.startswith("0x"):
                    # cmd line: 0x0102030405060708 .... 112233ff      (hex)
                    # regs: 112233ff ... 05060708 01020304
                    # BLK: ff 33 22 11 ... 08 07 06 05 04 03 02 01
                    return binascii.unhexlify(new_value_str[2:])[::-1]
                else:
                    # cmd line: 0102030405060708 .... 112233ff        (string)
                    # regs: 04030201 08070605 ... ff332211
                    # BLK: 01 02 03 04 05 06 07 08 ... 11 22 33 ff
                    return binascii.unhexlify(new_value_str)
            else:
                return new_value_str

    def convert_to_bitstring(self, new_value):
        if isinstance(new_value, BitArray):
            return new_value
        else:
            if self.efuse_type.startswith("bytes"):
                # new_value (bytes) = [0][1][2] ... [N]             (original data)
                # in string format  = [0] [1] [2] ... [N]           (util.hexify(data, " "))
                # in hex format     = 0x[N]....[2][1][0]            (from bitstring print(data))
                # in reg format     = [3][2][1][0] ... [N][][][]    (as it will be in the device)
                # in bitstring      = [N] ... [2][1][0]             (to get a correct bitstring need to reverse new_value)
                # *[x] - means a byte.
                return BitArray(bytes=new_value[::-1], length=len(new_value) * 8)
            else:
                return BitArray(self.efuse_type + "={}".format(new_value))

    def check_new_value(self, bitarray_new_value):
        bitarray_old_value = self.get_bitstring() | self.get_bitstring(from_read=False)
        if bitarray_new_value.len != bitarray_old_value.len:
            raise esptool.FatalError("For {} efuse, the length of the new value is wrong, expected {} bits, was {} bits."
                                     .format(self.name, bitarray_old_value.len, bitarray_new_value.len))
        if bitarray_new_value == bitarray_old_value:
            error_msg = "\tThe same value for {} is already burned. Do not change the efuse.".format(self.name)
            print(error_msg)
            bitarray_new_value.set(0)
        elif bitarray_new_value == self.get_bitstring(from_read=False):
            error_msg = "\tThe same value for {} is already prepared for the burn operation.".format(self.name)
            print(error_msg)
            bitarray_new_value.set(0)
        else:
            if self.name not in ["WR_DIS", "RD_DIS"]:
                # WR_DIS, RD_DIS fields can have already set bits.
                # Do not neeed to check below condition for them.
                if bitarray_new_value | bitarray_old_value != bitarray_new_value:
                    error_msg = "\tNew value contains some bits that cannot be cleared (value will be {})".format(bitarray_old_value | bitarray_new_value)
                    self.parent.print_error_msg(error_msg)
            self.check_wr_rd_protect()

    def save_to_block(self, bitarray_field):
        block = self.parent.blocks[self.block]
        wr_bitarray_temp = block.wr_bitarray.copy()
        position = wr_bitarray_temp.length - (self.word * 32 + self.pos + bitarray_field.len)
        wr_bitarray_temp.overwrite(bitarray_field, pos=position)
        block.wr_bitarray |= wr_bitarray_temp

    def save(self, new_value):
        bitarray_field = self.convert_to_bitstring(new_value)
        self.check_new_value(bitarray_field)
        self.save_to_block(bitarray_field)

    def update(self, bit_array_block):
        field_len = self.bitarray.len
        bit_array_block.pos = bit_array_block.length - (self.word * 32 + self.pos + field_len)
        self.bitarray.overwrite(bit_array_block.read(field_len), pos=0)
        err_bitarray = self.parent.blocks[self.block].err_bitarray
        if err_bitarray is not None:
            err_bitarray.pos = err_bitarray.length - (self.word * 32 + self.pos + field_len)
            self.fail = not err_bitarray.read(field_len).all(False)
        else:
            self.fail = self.parent.blocks[self.block].fail
            self.num_errors = self.parent.blocks[self.block].num_errors

    def get_raw(self, from_read=True):
        """ Return the raw (unformatted) numeric value of the efuse bits

        Returns a simple integer or (for some subclasses) a bitstring.
        type: int or bool -> int
        type: bytes -> bytearray
        """
        return self.get_bitstring(from_read).read(self.efuse_type)

    def get(self, from_read=True):
        """ Get a formatted version of the efuse value, suitable for display
        type: int or bool -> int
        type: bytes -> string  "01 02 03 04 05 06 07 08 ... ". Byte order [0] ... [N]. dump regs: 0x04030201 0x08070605 ...
        """
        if self.efuse_type.startswith("bytes"):
            return util.hexify(self.get_bitstring(from_read).bytes[::-1], " ")
        else:
            return self.get_raw(from_read)

    def get_meaning(self, from_read=True):
        """ Get the meaning of efuse from dict if possible, suitable for display """
        if self.dict_value:
            try:
                return self.dict_value[self.get_raw(from_read)]
            except KeyError:
                pass
        return self.get(from_read)

    def get_bitstring(self, from_read=True):
        if from_read:
            self.bitarray.pos = 0
            return self.bitarray
        else:
            field_len = self.bitarray.len
            block = self.parent.blocks[self.block]
            block.wr_bitarray.pos = block.wr_bitarray.length - (self.word * 32 + self.pos + field_len)
            return block.wr_bitarray.read(self.bitarray.len)

    def burn(self, new_value):
        # Burn a efuse. Added for compatibility reason.
        self.save(new_value)
        self.parent.burn_all()
