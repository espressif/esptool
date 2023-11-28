# This file describes eFuses for ESP32-C2 chip
#
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import binascii
import struct
import sys
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

    debug = False
    do_not_confirm = False

    def __init__(self, esp, skip_connect=False, debug=False, do_not_confirm=False):
        self.Blocks = EfuseDefineBlocks()
        self.Fields = EfuseDefineFields()
        self.REGS = EfuseDefineRegisters
        self.BURN_BLOCK_DATA_NAMES = self.Blocks.get_burn_block_data_names()
        self.BLOCKS_FOR_KEYS = self.Blocks.get_blocks_for_keys()
        self._esp = esp
        self.debug = debug
        self.do_not_confirm = do_not_confirm
        if esp.CHIP_NAME != "ESP32-C2":
            raise esptool.FatalError(
                "Expected the 'esp' param for ESP32-C2 chip but got for '%s'."
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
        self.efuses = [EfuseField.convert(self, efuse) for efuse in self.Fields.EFUSES]
        self.efuses += [
            EfuseField.convert(self, efuse) for efuse in self.Fields.KEYBLOCKS
        ]
        if skip_connect:
            self.efuses += [
                EfuseField.convert(self, efuse)
                for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES
            ]
        else:
            if self["BLK_VERSION_MINOR"].get() == 1:
                self.efuses += [
                    EfuseField.convert(self, efuse)
                    for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES
                ]

    def __getitem__(self, efuse_name):
        """Return the efuse field with the given name"""
        for e in self.efuses:
            if efuse_name == e.name or any(x == efuse_name for x in e.alt_names):
                return e
        new_fields = False
        for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES:
            if efuse.name == efuse_name or any(
                x == efuse_name for x in efuse.alt_names
            ):
                self.efuses += [
                    EfuseField.convert(self, efuse)
                    for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES
                ]
                new_fields = True
        if new_fields:
            for e in self.efuses:
                if efuse_name == e.name or any(x == efuse_name for x in e.alt_names):
                    return e
        raise KeyError

    def read_coding_scheme(self):
        self.coding_scheme = self.REGS.CODING_SCHEME_RS

    def print_status_regs(self):
        print("")
        self.blocks[0].print_block(self.blocks[0].err_bitarray, "err__regs", debug=True)
        print(
            "{:27} 0x{:08x}".format(
                "EFUSE_RD_RS_ERR_REG", self.read_reg(self.REGS.EFUSE_RD_RS_ERR_REG)
            )
        )

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
            cmds = self.REGS.EFUSE_PGM_CMD | self.REGS.EFUSE_READ_CMD
            if self.read_reg(self.REGS.EFUSE_CMD_REG) & cmds == 0:
                if self.read_reg(self.REGS.EFUSE_CMD_REG) & cmds == 0:
                    # Due to a hardware error, we have to read READ_CMD again
                    # to make sure the efuse clock is normal.
                    # For PGM_CMD it is not necessary.
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
        # if ENABLE_SECURITY_DOWNLOAD or DIS_DOWNLOAD_MODE is enabled by the current cmd, then we need to try to reconnect to the chip.
        try:
            self.write_reg(
                self.REGS.EFUSE_CMD_REG, self.REGS.EFUSE_READ_CMD, delay_after_us=1000
            )
            self.wait_efuse_idle()
        except esptool.FatalError:
            secure_download_mode_before = self._esp.secure_download_mode

            try:
                self._esp = self.reconnect_chip(self._esp)
            except esptool.FatalError:
                print("Can not re-connect to the chip")
                if not self["DIS_DOWNLOAD_MODE"].get() and self[
                    "DIS_DOWNLOAD_MODE"
                ].get(from_read=False):
                    print(
                        "This is the correct behavior as we are actually burning "
                        "DIS_DOWNLOAD_MODE which disables the connection to the chip"
                    )
                    print("DIS_DOWNLOAD_MODE is enabled")
                    print("Successful")
                    sys.exit(0)  # finish without errors
                raise

            print("Established a connection with the chip")
            if self._esp.secure_download_mode and not secure_download_mode_before:
                print("Secure download mode is enabled")
                if not self["ENABLE_SECURITY_DOWNLOAD"].get() and self[
                    "ENABLE_SECURITY_DOWNLOAD"
                ].get(from_read=False):
                    print(
                        "espefuse tool can not continue to work in Secure download mode"
                    )
                    print("ENABLE_SECURITY_DOWNLOAD is enabled")
                    print("Successful")
                    sys.exit(0)  # finish without errors
            raise

    def set_efuse_timing(self):
        """Set timing registers for burning efuses"""
        # Configure clock
        xtal_freq = self.get_crystal_freq()
        if xtal_freq not in [26, 40]:
            raise esptool.FatalError(
                "The eFuse supports only xtal=26M and 40M (xtal was %d)" % xtal_freq
            )

        self.update_reg(self.REGS.EFUSE_DAC_CONF_REG, self.REGS.EFUSE_DAC_NUM_M, 0xFF)
        self.update_reg(
            self.REGS.EFUSE_DAC_CONF_REG, self.REGS.EFUSE_DAC_CLK_DIV_M, 0x28
        )
        self.update_reg(
            self.REGS.EFUSE_WR_TIM_CONF1_REG, self.REGS.EFUSE_PWR_ON_NUM_M, 0x3000
        )
        self.update_reg(
            self.REGS.EFUSE_WR_TIM_CONF2_REG, self.REGS.EFUSE_PWR_OFF_NUM_M, 0x190
        )

        tpgm_inactive_val = 200 if xtal_freq == 40 else 130
        self.update_reg(
            self.REGS.EFUSE_WR_TIM_CONF0_REG,
            self.REGS.EFUSE_TPGM_INACTIVE_M,
            tpgm_inactive_val,
        )

    def get_coding_scheme_warnings(self, silent=False):
        """Check if the coding scheme has detected any errors."""
        old_addr_reg = 0
        reg_value = 0
        ret_fail = False
        for block in self.blocks:
            if block.id == 0:
                words = [
                    self.read_reg(self.REGS.EFUSE_RD_REPEAT_ERR_REG + offs * 4)
                    for offs in range(1)
                ]
                block.err_bitarray.pos = 0
                for word in reversed(words):
                    block.err_bitarray.overwrite(BitArray("uint:32=%d" % word))
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
    def convert(parent, efuse):
        return {
            "mac": EfuseMacField,
            "keypurpose": EfuseKeyPurposeField,
            "t_sensor": EfuseTempSensor,
            "adc_tp": EfuseAdcPointCalibration,
        }.get(efuse.class_type, EfuseField)(parent, efuse)


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
            mac = self.get_raw(from_read)[::-1]
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
            raise esptool.FatalError("Writing Factory MAC address is not supported")


class EfuseKeyPurposeField(EfuseField):
    KEY_PURPOSES = [
        # fmt: off
        ("USER",                                        0, None),      # User purposes (software-only use)
        ("XTS_AES_128_KEY",                             1, None),      # (whole 256bits) flash/PSRAM encryption
        ("XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS", 2, None),      # (lo 128bits) flash/PSRAM encryption
        ("SECURE_BOOT_DIGEST",                          3, "DIGEST"),
        # (hi 128bits) Secure Boot key digest
        # fmt: on
    ]

    KEY_PURPOSES_NAME = [name[0] for name in KEY_PURPOSES]
    DIGEST_KEY_PURPOSES = [name[0] for name in KEY_PURPOSES if name[2] == "DIGEST"]
