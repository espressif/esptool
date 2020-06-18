#!/usr/bin/env python
# This file describes eFuses for ESP32S2 chip
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

import reedsolo
import struct
import time
import esptool
from .. import base_fields
from .. import util
from .mem_definition import EfuseDefineBlocks, EfuseDefineFields, EfuseDefineRegisters


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
            data = data + (b'\x00' * add_empty_bytes)
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

    Blocks  = EfuseDefineBlocks()
    Fields  = EfuseDefineFields()
    REGS    = EfuseDefineRegisters
    BURN_BLOCK_DATA_NAMES = Blocks.get_burn_block_data_names()
    BLOCKS_FOR_KEYS = Blocks.get_blocks_for_keys()

    debug = False
    do_not_confirm = False

    def __init__(self, esp, skip_connect=False, debug=False, do_not_confirm=False):
        self._esp = esp
        self.debug = debug
        self.do_not_confirm = do_not_confirm
        if esp.CHIP_NAME != "ESP32-S2":
            raise esptool.FatalError("Expected the 'esp' param for ESP32-S2 chip but got for '%s'." % (esp.CHIP_NAME))
        self.blocks = [EfuseBlock(self, self.Blocks.get(block), skip_read=skip_connect) for block in self.Blocks.BLOCKS]
        self.efuses = [EfuseField.from_tuple(self, self.Fields.get(efuse), self.Fields.get(efuse).class_type) for efuse in self.Fields.EFUSES]
        self.efuses += [EfuseField.from_tuple(self, self.Fields.get(efuse), self.Fields.get(efuse).class_type) for efuse in self.Fields.KEYBLOCKS]
        if skip_connect:
            self.efuses += [EfuseField.from_tuple(self, self.Fields.get(efuse), self.Fields.get(efuse).class_type)
                            for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES]
        else:
            if self["BLOCK2_VERSION"].get() == 1:
                self.efuses += [EfuseField.from_tuple(self, self.Fields.get(efuse), self.Fields.get(efuse).class_type)
                                for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES]

    def __getitem__(self, efuse_name):
        """ Return the efuse field with the given name """
        for e in self.efuses:
            if efuse_name == e.name:
                return e
        new_fields = False
        for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES:
            e = self.Fields.get(efuse)
            if e.name == efuse_name:
                self.efuses += [EfuseField.from_tuple(self, self.Fields.get(efuse), self.Fields.get(efuse).class_type)
                                for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES]
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
        print("RD_RS_ERR0_REG 0x%08x RD_RS_ERR1_REG 0x%08x" % (
              self.read_reg(self.REGS.EFUSE_RD_RS_ERR0_REG),
              self.read_reg(self.REGS.EFUSE_RD_RS_ERR1_REG)))

    def get_block_errors(self, block_num):
        """ Returns (error count, failure boolean flag) """
        read_reg, err_num_mask, fail_bit_mask = self.REGS.BLOCK_ERRORS[block_num]
        if read_reg is None:
            return 0, False
        reg_value = self.read_reg(read_reg)
        err_num_shift = esptool._mask_to_shift(err_num_mask)
        err_num_val = (reg_value & err_num_mask) >> err_num_shift
        fail_bit_val = (reg_value & (1 << fail_bit_mask)) != 0
        return err_num_val, fail_bit_val

    def efuse_controller_setup(self):
        self.set_efuse_timing()
        self.clear_pgm_registers()
        self.wait_efuse_idle()

    def write_efuses(self, block):
        self.efuse_program(block)
        return self.get_coding_scheme_warnings()

    def clear_pgm_registers(self):
        self.wait_efuse_idle()
        for r in range(self.REGS.EFUSE_PGM_DATA0_REG, self.REGS.EFUSE_PGM_DATA0_REG + 32, 4):
            self.write_reg(r, 0)

    def wait_efuse_idle(self):
        deadline = time.time() + self.REGS.EFUSE_BURN_TIMEOUT
        while time.time() < deadline:
            # if self.read_reg(self.EFUSE_CMD_REG) == 0:
            if self.read_reg(self.REGS.EFUSE_STATUS_REG) & 0x7 == 1:
                return
        raise esptool.FatalError("Timed out waiting for Efuse controller command to complete")

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
        self.write_reg(self.REGS.EFUSE_CMD_REG, self.REGS.EFUSE_READ_CMD, delay_after_us=1000)
        self.wait_efuse_idle()

    def set_efuse_timing(self):
        """ Set timing registers for burning efuses """
        # Configure clock
        apb_freq = self.get_crystal_freq()
        EFUSE_TSUP_A, EFUSE_TPGM, EFUSE_THP_A, EFUSE_TPGM_INACTIVE = self.REGS.EFUSE_PROGRAMMING_TIMING_PARAMETERS[apb_freq]
        self.update_reg(self.REGS.EFUSE_WR_TIM_CONF1_REG, self.REGS.EFUSE_TSUP_A_M,        EFUSE_TSUP_A)
        self.update_reg(self.REGS.EFUSE_WR_TIM_CONF0_REG, self.REGS.EFUSE_TPGM_M,          EFUSE_TPGM)
        self.update_reg(self.REGS.EFUSE_WR_TIM_CONF0_REG, self.REGS.EFUSE_THP_A_M,         EFUSE_THP_A)
        self.update_reg(self.REGS.EFUSE_WR_TIM_CONF0_REG, self.REGS.EFUSE_TPGM_INACTIVE_M, EFUSE_TPGM_INACTIVE)

        EFUSE_DAC_CLK_DIV, EFUSE_PWR_ON_NUM, EFUSE_PWR_OFF_NUM = self.REGS.VDDQ_TIMING_PARAMETERS[apb_freq]
        self.update_reg(self.REGS.EFUSE_DAC_CONF_REG,     self.REGS.EFUSE_DAC_CLK_DIV_M,   EFUSE_DAC_CLK_DIV)
        self.update_reg(self.REGS.EFUSE_WR_TIM_CONF1_REG, self.REGS.EFUSE_PWR_ON_NUM_M,    EFUSE_PWR_ON_NUM)
        self.update_reg(self.REGS.EFUSE_WR_TIM_CONF2_REG, self.REGS.EFUSE_PWR_OFF_NUM_M,   EFUSE_PWR_OFF_NUM)

        EFUSE_TSUR_A, EFUSE_TRD, EFUSE_THR_A = self.REGS.EFUSE_READING_PARAMETERS[apb_freq]
        #  self.update_reg(self.REGS.EFUSE_RD_TIM_CONF_REG,  self.REGS.EFUSE_TSUR_A_M,        EFUSE_TSUR_A)
        self.update_reg(self.REGS.EFUSE_RD_TIM_CONF_REG,  self.REGS.EFUSE_TRD_M,           EFUSE_TRD)
        self.update_reg(self.REGS.EFUSE_RD_TIM_CONF_REG,  self.REGS.EFUSE_THR_A_M,         EFUSE_THR_A)

    def get_coding_scheme_warnings(self):
        """ Check if the coding scheme has detected any errors.
        Meaningless for default coding scheme (0)
        """
        warning = False
        for block in self.blocks:
            errs, fail = self.get_block_errors(block.id)
            if errs != 0 or fail:
                print("Block %d has ERRORS:%d FAIL:%d" % (block.id, errs, fail))
                warning = True
        return warning

    def summary(self):
        if self["VDD_SPI_FORCE"].get() == 0:
            output = "Flash voltage (VDD_SPI) determined by GPIO45 on reset (GPIO45=High: VDD_SPI pin is powered from internal 1.8V LDO\n"
            output += "GPIO45=Low or NC: VDD_SPI pin is powered directly from VDD3P3_RTC_IO via resistor Rspi. Typically this voltage is 3.3 V)."
        elif self["VDD_SPI_XPD"].get() == 0:
            output = "Flash voltage (VDD_SPI) internal regulator disabled by efuse."
        elif self["VDD_SPI_TIEH"].get() == 0:
            output = "Flash voltage (VDD_SPI) set to 1.8V by efuse."
        else:
            output = "Flash voltage (VDD_SPI) set to 3.3V by efuse."
        return output


class EfuseField(base_fields.EfuseFieldBase):
    @staticmethod
    def from_tuple(parent, efuse_tuple, type_class):
        return {
            "mac":          EfuseMacField,
            "keypurpose":   EfuseKeyPurposeField,
            "t_sensor":     EfuseTempSensor,
            "adc_tp":       EfuseAdcPointCalibration,
        }.get(type_class, EfuseField)(parent, efuse_tuple)

    def get_info(self):
        output = "%s (BLOCK%d)" % (self.name, self.block)
        if self.efuse_class == "keyblock":
            err_msg = "0 errors"
            errs, fail = self.parent.get_block_errors(self.block)
            if errs != 0 or fail:
                err_msg = "ERRORS:%d FAIL:%d" % (errs, fail)
            output += "(%s):" % err_msg
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
    def check(self):
        errs, fail = self.parent.get_block_errors(self.block)
        if errs != 0 or fail:
            output = "Block%d has ERRORS:%d FAIL:%d" % (self.block, errs, fail)
        else:
            output = "OK"
        return "(" + output + ")"

    def get(self, from_read=True):
        return "%s: %s" % (util.hexify(self.get_raw(from_read), ":"), self.check())

    def burn(self, new_value):
        # Writing the BLOCK1 (MAC_SPI_8M_0) default MAC is not sensible, as it's written in the factory.
        raise esptool.FatalError("Writing Factory MAC address is not supported")


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
                return True if key[3] == "Reverse" else False
        return None

    def need_rd_protect(self, new_key_purpose):
        for key in self.KEY_PURPOSES:
            if key[0] == new_key_purpose:
                return True if key[4] == "need_rd_protect" else False
        return None

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
