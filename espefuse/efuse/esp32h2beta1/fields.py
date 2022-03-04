#!/usr/bin/env python
#
# This file describes eFuses for ESP32-H2 chip
#
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import division, print_function

import binascii
import struct
import time

from bitstring import BitArray

import esptool

import reedsolo

from .mem_definition import EfuseDefineBlocks, EfuseDefineFields, EfuseDefineRegisters
from .. import base_fields
from .. import util


class EfuseBlock(base_fields.EfuseBlockBase):
    def len_of_burn_unit(self):
        # The writing register window is 8 registers for any blocks.
        # len in bytes
        return 8 * 4

    def __init__(self, parent, param, skip_read=False):
        parent.read_coding_scheme()
        super(EfuseBlock, self).__init__(parent, param, skip_read=skip_read)

    def apply_coding_scheme(self):
        data = self.get_raw(from_read=False)[::-1]
        if len(data) < self.len_of_burn_unit():
            add_empty_bytes = self.len_of_burn_unit() - len(data)
            data = data + (b"\x00" * add_empty_bytes)
        if self.get_coding_scheme() == self.parent.REGS.CODING_SCHEME_RS:
            # takes 32 bytes
            # apply RS encoding
            rs = reedsolo.RSCodec(12)
            # 32 byte of data + 12 bytes RS
            encoded_data = rs.encode([x for x in data])
            words = struct.unpack("<" + "I" * 11, encoded_data)
            # returns 11 words (8 words of data + 3 words of RS coding)
        else:
            # takes 32 bytes
            words = struct.unpack("<" + ("I" * (len(data) // 4)), data)
            # returns 8 words
        return words


class EspEfuses(base_fields.EspEfusesBase):
    """
    Wrapper object to manage the efuse fields in a connected ESP bootloader
    """

    Blocks = EfuseDefineBlocks()
    Fields = EfuseDefineFields()
    REGS = EfuseDefineRegisters
    BURN_BLOCK_DATA_NAMES = Blocks.get_burn_block_data_names()
    BLOCKS_FOR_KEYS = Blocks.get_blocks_for_keys()

    debug = False
    do_not_confirm = False

    def __init__(self, esp, skip_connect=False, debug=False, do_not_confirm=False):
        self._esp = esp
        self.debug = debug
        self.do_not_confirm = do_not_confirm
        if esp.CHIP_NAME != "ESP32-H2(beta1)":
            raise esptool.FatalError(
                "Expected the 'esp' param for ESP32-H2(beta1) chip but got for '%s'."
                % (esp.CHIP_NAME)
            )
        if not skip_connect:
            flags = self._esp.get_security_info()["flags"]
            GET_SECURITY_INFO_FLAG_SECURE_DOWNLOAD_ENABLE = 1 << 2
            if flags & GET_SECURITY_INFO_FLAG_SECURE_DOWNLOAD_ENABLE:
                raise esptool.FatalError(
                    "Secure Download Mode is enabled. The tool can not read eFuses."
                )
        self.blocks = [
            EfuseBlock(self, self.Blocks.get(block), skip_read=skip_connect)
            for block in self.Blocks.BLOCKS
        ]
        if not skip_connect:
            self.get_coding_scheme_warnings()
        self.efuses = [
            EfuseField.from_tuple(
                self, self.Fields.get(efuse), self.Fields.get(efuse).class_type
            )
            for efuse in self.Fields.EFUSES
        ]
        self.efuses += [
            EfuseField.from_tuple(
                self, self.Fields.get(efuse), self.Fields.get(efuse).class_type
            )
            for efuse in self.Fields.KEYBLOCKS
        ]
        if skip_connect:
            self.efuses += [
                EfuseField.from_tuple(
                    self, self.Fields.get(efuse), self.Fields.get(efuse).class_type
                )
                for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES
            ]
        else:
            if self["BLOCK2_VERSION"].get() == 1:
                self.efuses += [
                    EfuseField.from_tuple(
                        self, self.Fields.get(efuse), self.Fields.get(efuse).class_type
                    )
                    for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES
                ]

    def __getitem__(self, efuse_name):
        """Return the efuse field with the given name"""
        for e in self.efuses:
            if efuse_name == e.name:
                return e
        new_fields = False
        for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES:
            e = self.Fields.get(efuse)
            if e.name == efuse_name:
                self.efuses += [
                    EfuseField.from_tuple(
                        self, self.Fields.get(efuse), self.Fields.get(efuse).class_type
                    )
                    for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES
                ]
                new_fields = True
        if new_fields:
            for e in self.efuses:
                if efuse_name == e.name:
                    return e
        raise KeyError

    def read_coding_scheme(self):
        self.coding_scheme = self.REGS.CODING_SCHEME_RS

    def print_status_regs(self):
        print("")
        self.blocks[0].print_block(self.blocks[0].err_bitarray, "err__regs", debug=True)
        print(
            "{:27} 0x{:08x}".format(
                "EFUSE_RD_RS_ERR0_REG", self.read_reg(self.REGS.EFUSE_RD_RS_ERR0_REG)
            )
        )
        print(
            "{:27} 0x{:08x}".format(
                "EFUSE_RD_RS_ERR1_REG", self.read_reg(self.REGS.EFUSE_RD_RS_ERR1_REG)
            )
        )

    def get_block_errors(self, block_num):
        """Returns (error count, failure boolean flag)"""
        return self.blocks[block_num].num_errors, self.blocks[block_num].fail

    def efuse_controller_setup(self):
        self.set_efuse_timing()
        self.clear_pgm_registers()
        self.wait_efuse_idle()

    def write_efuses(self, block):
        self.efuse_program(block)
        return self.get_coding_scheme_warnings(silent=True)

    def clear_pgm_registers(self):
        self.wait_efuse_idle()
        for r in range(
            self.REGS.EFUSE_PGM_DATA0_REG, self.REGS.EFUSE_PGM_DATA0_REG + 32, 4
        ):
            self.write_reg(r, 0)

    def wait_efuse_idle(self):
        deadline = time.time() + self.REGS.EFUSE_BURN_TIMEOUT
        while time.time() < deadline:
            # if self.read_reg(self.REGS.EFUSE_CMD_REG) == 0:
            if self.read_reg(self.REGS.EFUSE_STATUS_REG) & 0x7 == 1:
                return
        raise esptool.FatalError(
            "Timed out waiting for Efuse controller command to complete"
        )

    def efuse_program(self, block):
        self.wait_efuse_idle()
        self.write_reg(self.REGS.EFUSE_CONF_REG, self.REGS.EFUSE_WRITE_OP_CODE)
        self.write_reg(self.REGS.EFUSE_CMD_REG, self.REGS.EFUSE_PGM_CMD | (block << 2))
        self.wait_efuse_idle()
        self.clear_pgm_registers()
        self.efuse_read()

    def efuse_read(self):
        self.wait_efuse_idle()
        self.write_reg(self.REGS.EFUSE_CONF_REG, self.REGS.EFUSE_READ_OP_CODE)
        # need to add a delay after triggering EFUSE_READ_CMD, as ROM loader checks some
        # efuse registers after each command is completed
        self.write_reg(
            self.REGS.EFUSE_CMD_REG, self.REGS.EFUSE_READ_CMD, delay_after_us=1000
        )
        self.wait_efuse_idle()

    def set_efuse_timing(self):
        """Set timing registers for burning efuses"""
        # Configure clock
        apb_freq = self.get_crystal_freq()
        if apb_freq != 32:
            raise esptool.FatalError(
                "The eFuse supports only xtal=32M (xtal was %d)" % apb_freq
            )

        self.update_reg(
            self.REGS.EFUSE_WR_TIM_CONF2_REG, self.REGS.EFUSE_PWR_OFF_NUM_M, 0x190
        )

    def get_coding_scheme_warnings(self, silent=False):
        """Check if the coding scheme has detected any errors."""
        old_addr_reg = 0
        reg_value = 0
        ret_fail = False
        for block in self.blocks:
            if block.id == 0:
                words = [
                    self.read_reg(self.REGS.EFUSE_RD_REPEAT_ERR0_REG + offs * 4)
                    for offs in range(5)
                ]
                data = BitArray()
                for word in reversed(words):
                    data.append("uint:32=%d" % word)
                # pos=32 because EFUSE_WR_DIS goes first it is 32bit long
                # and not under error control
                block.err_bitarray.overwrite(data, pos=32)
                block.num_errors = block.err_bitarray.count(True)
                block.fail = block.num_errors != 0
            else:
                addr_reg, err_num_mask, err_num_offs, fail_bit = self.REGS.BLOCK_ERRORS[
                    block.id
                ]
                if err_num_mask is None or err_num_offs is None or fail_bit is None:
                    continue
                if addr_reg != old_addr_reg:
                    old_addr_reg = addr_reg
                    reg_value = self.read_reg(addr_reg)
                block.fail = reg_value & (1 << fail_bit) != 0
                block.num_errors = (reg_value >> err_num_offs) & err_num_mask
            ret_fail |= block.fail
            if not silent and (block.fail or block.num_errors):
                print(
                    "Error(s) in BLOCK%d [ERRORS:%d FAIL:%d]"
                    % (block.id, block.num_errors, block.fail)
                )
        if (self.debug or ret_fail) and not silent:
            self.print_status_regs()
        return ret_fail

    def summary(self):
        # TODO add support set_flash_voltage - "Flash voltage (VDD_SPI)"
        return ""


class EfuseField(base_fields.EfuseFieldBase):
    @staticmethod
    def from_tuple(parent, efuse_tuple, type_class):
        return {
            "mac": EfuseMacField,
            "keypurpose": EfuseKeyPurposeField,
            "t_sensor": EfuseTempSensor,
            "adc_tp": EfuseAdcPointCalibration,
        }.get(type_class, EfuseField)(parent, efuse_tuple)

    def get_info(self):
        output = "%s (BLOCK%d)" % (self.name, self.block)
        errs, fail = self.parent.get_block_errors(self.block)
        if errs != 0 or fail:
            output += (
                "[FAIL:%d]" % (fail)
                if self.block == 0
                else "[ERRS:%d FAIL:%d]" % (errs, fail)
            )
        if self.efuse_class == "keyblock":
            name = self.parent.blocks[self.block].key_purpose_name
            if name is not None:
                output += "\n  Purpose: %s\n " % (self.parent[name].get())
        return output


class EfuseTempSensor(EfuseField):
    def get(self, from_read=True):
        value = self.get_bitstring(from_read)
        sig = -1 if value[0] else 1
        return sig * value[1:].uint * 0.1


class EfuseAdcPointCalibration(EfuseField):
    def get(self, from_read=True):
        STEP_SIZE = 4
        value = self.get_bitstring(from_read)
        sig = -1 if value[0] else 1
        return sig * value[1:].uint * STEP_SIZE


class EfuseMacField(EfuseField):
    def check_format(self, new_value_str):
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

    def check(self):
        errs, fail = self.parent.get_block_errors(self.block)
        if errs != 0 or fail:
            output = "Block%d has ERRORS:%d FAIL:%d" % (self.block, errs, fail)
        else:
            output = "OK"
        return "(" + output + ")"

    def get(self, from_read=True):
        if self.name == "CUSTOM_MAC":
            mac = self.get_raw(from_read)[::-1] + self.parent["MAC_EXT"].get_raw(
                from_read
            )
        elif self.name == "MAC":
            mac = self.get_raw(from_read) + self.parent["MAC_EXT"].get_raw(from_read)
        else:
            mac = self.get_raw(from_read)
        return "%s %s" % (util.hexify(mac, ":"), self.check())

    def save(self, new_value):
        def print_field(e, new_value):
            print(
                "    - '{}' ({}) {} -> {}".format(
                    e.name, e.description, e.get_bitstring(), new_value
                )
            )

        if self.name == "CUSTOM_MAC":
            bitarray_mac = self.convert_to_bitstring(new_value)
            print_field(self, bitarray_mac)
            super(EfuseMacField, self).save(new_value)
        else:
            # Writing the BLOCK1 (MAC_SPI_8M_0) default MAC is not possible,
            # as it's written in the factory.
            raise esptool.FatalError("Writing Factory MAC address is not supported")


# fmt: off
class EfuseKeyPurposeField(EfuseField):
    KEY_PURPOSES = [
        ("USER",                         0,  None,       None,      "no_need_rd_protect"),   # User purposes (software-only use)
        ("RESERVED",                     1,  None,       None,      "no_need_rd_protect"),   # Reserved
        ("XTS_AES_256_KEY_1",            2,  None,       "Reverse", "need_rd_protect"),      # XTS_AES_256_KEY_1 (flash/PSRAM encryption)
        ("XTS_AES_256_KEY_2",            3,  None,       "Reverse", "need_rd_protect"),      # XTS_AES_256_KEY_2 (flash/PSRAM encryption)
        ("XTS_AES_128_KEY",              4,  None,       "Reverse", "need_rd_protect"),      # XTS_AES_128_KEY (flash/PSRAM encryption)
        ("HMAC_DOWN_ALL",                5,  None,       None,      "need_rd_protect"),      # HMAC Downstream mode
        ("HMAC_DOWN_JTAG",               6,  None,       None,      "need_rd_protect"),      # JTAG soft enable key (uses HMAC Downstream mode)
        ("HMAC_DOWN_DIGITAL_SIGNATURE",  7,  None,       None,      "need_rd_protect"),      # Digital Signature peripheral key (uses HMAC Downstream mode)
        ("HMAC_UP",                      8,  None,       None,      "need_rd_protect"),      # HMAC Upstream mode
        ("SECURE_BOOT_DIGEST0",          9,  "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST0 (Secure Boot key digest)
        ("SECURE_BOOT_DIGEST1",          10, "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST1 (Secure Boot key digest)
        ("SECURE_BOOT_DIGEST2",          11, "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST2 (Secure Boot key digest)
    ]
# fmt: on

    KEY_PURPOSES_NAME = [name[0] for name in KEY_PURPOSES]
    DIGEST_KEY_PURPOSES = [name[0] for name in KEY_PURPOSES if name[2] == "DIGEST"]

    def check_format(self, new_value_str):
        # str convert to int: "XTS_AES_128_KEY" - > str(4)
        # if int: 4 -> str(4)
        raw_val = new_value_str
        for purpose_name in self.KEY_PURPOSES:
            if purpose_name[0] == new_value_str:
                raw_val = str(purpose_name[1])
                break
        return raw_val

    def need_reverse(self, new_key_purpose):
        for key in self.KEY_PURPOSES:
            if key[0] == new_key_purpose:
                return key[3] == "Reverse"

    def need_rd_protect(self, new_key_purpose):
        for key in self.KEY_PURPOSES:
            if key[0] == new_key_purpose:
                return key[4] == "need_rd_protect"

    def get(self, from_read=True):
        try:
            return self.KEY_PURPOSES[self.get_raw(from_read)][0]
        except IndexError:
            return " "

    def save(self, new_value):
        raw_val = new_value
        for purpose_name in self.KEY_PURPOSES:
            if purpose_name[0] == new_value:
                raw_val = purpose_name[1]
                break
        return super(EfuseKeyPurposeField, self).save(raw_val)
