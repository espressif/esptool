# This file describes eFuses for ESP32-S3 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import struct
import sys
import time

from bitstring import BitArray
from esptool.logger import log

import esptool

import reedsolo

from .mem_definition import EfuseDefineBlocks, EfuseDefineFields, EfuseDefineRegisters
from .. import base_fields
from ..mem_definition_base import Field


class EfuseBlock(base_fields.EfuseBlockBase):
    def len_of_burn_unit(self):
        # The writing register window is 8 registers for any blocks.
        # len in bytes
        return 8 * 4

    def __init__(self, parent, param, skip_read=False):
        parent.read_coding_scheme()
        super().__init__(parent, param, skip_read=skip_read)

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
        if esp.CHIP_NAME != "ESP32-S3":
            raise esptool.FatalError(
                f"Expected the 'esp' param for ESP32-S3 chip but got for '{esp.CHIP_NAME}'."
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
        self.efuses = self._convert_efuse_defs(self.Fields.EFUSES)
        self.efuses += self._convert_efuse_defs(self.Fields.KEYBLOCKS)
        if skip_connect:
            self.efuses += self._convert_efuse_defs(
                self.Fields.BLOCK2_CALIBRATION_EFUSES
            )
        else:
            if self.get_block_version() >= 100:
                self.efuses += self._convert_efuse_defs(
                    self.Fields.BLOCK2_CALIBRATION_EFUSES
                )
            self.efuses += self._convert_efuse_defs(self.Fields.CALC)

    def _convert_efuse_defs(self, efuse_defs):
        return [EfuseField.convert(self, efuse) for efuse in efuse_defs]

    def _get_lazy_efuse_groups(self):
        return [self.Fields.BLOCK2_CALIBRATION_EFUSES]

    def read_coding_scheme(self):
        self.coding_scheme = self.REGS.CODING_SCHEME_RS

    def print_status_regs(self):
        log.print("")
        self.blocks[0].print_block(self.blocks[0].err_bitarray, "err__regs", debug=True)
        log.print(
            "{:27} 0x{:08x}".format(
                "EFUSE_RD_RS_ERR0_REG", self.read_reg(self.REGS.EFUSE_RD_RS_ERR0_REG)
            )
        )
        log.print(
            "{:27} 0x{:08x}".format(
                "EFUSE_RD_RS_ERR1_REG", self.read_reg(self.REGS.EFUSE_RD_RS_ERR1_REG)
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
            "Timed out waiting for eFuse controller command to complete"
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
                log.print("Can not re-connect to the chip.")
                if not self["DIS_DOWNLOAD_MODE"].get() and self[
                    "DIS_DOWNLOAD_MODE"
                ].get(from_read=False):
                    log.print(
                        "This is the correct behavior as we are actually burning "
                        "DIS_DOWNLOAD_MODE which disables the connection to the chip."
                    )
                    log.print("DIS_DOWNLOAD_MODE is enabled.")
                    log.print("Successful.")
                    sys.exit(0)  # finish without errors
                raise

            log.print("Established a connection with the chip.")
            if self._esp.secure_download_mode and not secure_download_mode_before:
                log.print("Secure download mode is enabled.")
                if not self["ENABLE_SECURITY_DOWNLOAD"].get() and self[
                    "ENABLE_SECURITY_DOWNLOAD"
                ].get(from_read=False):
                    log.print(
                        "espefuse can not continue to work in Secure download mode."
                    )
                    log.print("ENABLE_SECURITY_DOWNLOAD is enabled.")
                    log.print("Successful.")
                    sys.exit(0)  # finish without errors
            raise

    def set_efuse_timing(self):
        """Set timing registers for burning efuses"""
        # Configure clock
        apb_freq = self.get_crystal_freq()
        if apb_freq != 40:
            raise esptool.FatalError(
                f"The eFuse supports only xtal=40M (xtal was {apb_freq}"
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
                block.err_bitarray.pos = 0
                for word in reversed(words):
                    block.err_bitarray.overwrite(BitArray(f"uint:32={word}"))
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
                log.print(
                    f"Error(s) in BLOCK{block.id} "
                    f"[ERRORS:{block.num_errors} FAIL:{block.fail}]."
                )
        if (self.debug or ret_fail) and not silent:
            self.print_status_regs()
        return ret_fail

    def summary(self):
        if self["VDD_SPI_FORCE"].get() == 0:
            output = "Flash voltage (VDD_SPI) determined by GPIO45 on reset "
            output += "(GPIO45=High: VDD_SPI pin is powered from internal 1.8V LDO\n"
            output += "GPIO45=Low or NC: VDD_SPI pin is powered directly from "
            output += "VDD3P3_RTC_IO via resistor Rspi. "
            output += "Typically this voltage is 3.3 V)."
        elif self["VDD_SPI_XPD"].get() == 0:
            output = "Flash voltage (VDD_SPI) internal regulator disabled by efuse."
        elif self["VDD_SPI_TIEH"].get() == 0:
            output = "Flash voltage (VDD_SPI) set to 1.8V by efuse."
        else:
            output = "Flash voltage (VDD_SPI) set to 3.3V by efuse."
        return output

    def is_efuses_incompatible_for_burn(self):
        # getting chip version: self._esp.get_chip_revision()
        if (
            (
                self["DIS_USB_JTAG"].get()
                and self["DIS_USB_SERIAL_JTAG"].get(from_read=False)
            )
            or (
                self["DIS_USB_JTAG"].get(from_read=False)
                and self["DIS_USB_SERIAL_JTAG"].get()
            )
            or (
                self["DIS_USB_JTAG"].get(from_read=False)
                and self["DIS_USB_SERIAL_JTAG"].get(from_read=False)
            )
        ):
            log.print(
                "DIS_USB_JTAG and DIS_USB_SERIAL_JTAG cannot be set together "
                "due to a bug in the ROM bootloader!"
            )
            return True
        return False


class EfuseField(base_fields.EfuseFieldBase):
    @staticmethod
    def convert(parent: base_fields.EspEfusesBase, efuse: Field) -> "EfuseField":
        return {
            "mac": EfuseMacField,
            "keypurpose": EfuseKeyPurposeField,
            "t_sensor": EfuseTempSensor,
            "adc_tp": EfuseAdcPointCalibration,
            "wafer": EfuseWafer,
            "psram_cap": EfusePsramCap,
        }.get(efuse.class_type, EfuseField)(parent, efuse)


class EfuseTempSensor(base_fields.EfuseTempSensor, EfuseField):
    pass


class EfuseAdcPointCalibration(base_fields.EfuseAdcPointCalibration, EfuseField):
    pass


class EfuseMacField(base_fields.EfuseMacFieldBase, EfuseField):
    pass


class EfusePsramCap(EfuseField):
    def get(self, from_read=True):
        hi_bits = self.parent["PSRAM_CAP_3"].get(from_read)
        assert self.parent["PSRAM_CAP_3"].bit_len == 1
        lo_bits = self.parent["PSRAM_CAP"].get(from_read)
        assert self.parent["PSRAM_CAP"].bit_len == 2
        return (hi_bits << 2) + lo_bits

    def save(self, new_value):
        raise esptool.FatalError(f"Burning {self.name} is not supported")


class EfuseWafer(base_fields.EfuseWaferBase, EfuseField):
    def get(self, from_read=True):
        hi_bits = self.parent["WAFER_VERSION_MINOR_HI"].get(from_read)
        assert self.parent["WAFER_VERSION_MINOR_HI"].bit_len == 1
        lo_bits = self.parent["WAFER_VERSION_MINOR_LO"].get(from_read)
        assert self.parent["WAFER_VERSION_MINOR_LO"].bit_len == 3
        return (hi_bits << 3) + lo_bits


class EfuseKeyPurposeField(base_fields.EfuseKeyPurposeFieldBase, EfuseField):
    # fmt: off
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
        ("XTS_AES_256_KEY",              -1, "VIRTUAL",  None,      "no_need_rd_protect"),   # Virtual purpose splits to XTS_AES_256_KEY_1 and XTS_AES_256_KEY_2
    ]
    # fmt: on

    def save(self, new_value):
        raw_val = int(self.check_format(str(new_value)))
        str_new_value = self.get_name(raw_val)
        if self.name == "KEY_PURPOSE_5" and str_new_value.startswith("XTS_AES"):
            # see SOC_EFUSE_BLOCK9_KEY_PURPOSE_QUIRK in esp-idf
            raise esptool.FatalError(
                f"{self.name} can not have {str_new_value} key due to a hardware bug (please see TRM for more details)"
            )
        return super().save(raw_val)
