# This file describes eFuses for ESP32-H4 chip
#
# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import binascii
import struct
import time

from bitstring import BitArray
from esptool.logger import log

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
        if esp.CHIP_NAME != "ESP32-H4":
            raise esptool.FatalError(
                f"Expected the 'esp' param for ESP32-H4 chip but got for '{esp.CHIP_NAME}'."
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
            if False:  # self["BLK_VERSION_MINOR"].get() == 1:
                self.efuses += [
                    EfuseField.convert(self, efuse)
                    for efuse in self.Fields.BLOCK2_CALIBRATION_EFUSES
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
                    exit(0)  # finish without errors
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
                    exit(0)  # finish without errors
            raise

    def set_efuse_timing(self):
        """Set timing registers for burning efuses"""
        # Configure clock
        apb_freq = self.get_crystal_freq()
        if apb_freq != 32:
            raise esptool.FatalError(
                f"The eFuse supports only xtal=32M (xtal was {apb_freq}"
            )

        # TODO: [ESP32H4] IDF-12268

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
            "wafer": EfuseWafer,
        }.get(efuse.class_type, EfuseField)(parent, efuse)


class EfuseWafer(EfuseField):
    def get(self, from_read=True):
        # TODO: [ESP32H4] IDF-12268
        return 0

    def save(self, new_value):
        raise esptool.FatalError(f"Burning {self.name} is not supported")


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
        num_bytes = 8 if self.name == "MAC_EUI64" else 6
        if new_value_str.count(":") != num_bytes - 1:
            raise esptool.FatalError(
                f"MAC Address needs to be a {num_bytes}-byte hexadecimal format "
                "separated by colons (:)!"
            )
        hexad = new_value_str.replace(":", "").split(" ", 1)[0]
        hexad = hexad.split(" ", 1)[0] if self.is_field_calculated() else hexad
        if len(hexad) != num_bytes * 2:
            raise esptool.FatalError(
                f"MAC Address needs to be a {num_bytes}-byte hexadecimal number "
                f"({num_bytes * 2} hexadecimal characters)!"
            )
        # order of bytearray = b'\xaa\xcd\xef\x01\x02\x03',
        bindata = binascii.unhexlify(hexad)

        if not self.is_field_calculated():
            # unicast address check according to
            # https://tools.ietf.org/html/rfc7042#section-2.1
            if esptool.util.byte(bindata, 0) & 0x01:
                raise esptool.FatalError("Custom MAC must be a unicast MAC!")
        return bindata

    def check(self):
        errs, fail = self.parent.get_block_errors(self.block)
        if errs != 0 or fail:
            output = f"Block{self.block} has ERRORS:{errs} FAIL:{fail}"
        else:
            output = "OK"
        return "(" + output + ")"

    def get(self, from_read=True):
        if self.name == "CUSTOM_MAC":
            mac = self.get_raw(from_read)[::-1]
        elif self.name == "MAC":
            mac = self.get_raw(from_read)
        elif self.name == "MAC_EUI64":
            mac = self.parent["MAC"].get_bitstring(from_read).copy()
            mac_ext = self.parent["MAC_EXT"].get_bitstring(from_read)
            mac.insert(mac_ext, 24)
            mac = mac.bytes
        else:
            mac = self.get_raw(from_read)
        return " ".join([util.hexify(mac, ":"), self.check()])

    def save(self, new_value):
        def print_field(e, new_value):
            log.print(
                f"    - '{e.name}' ({e.description}) {e.get_bitstring()} -> {new_value}"
            )

        if self.name == "CUSTOM_MAC":
            bitarray_mac = self.convert_to_bitstring(new_value)
            print_field(self, bitarray_mac)
            super().save(new_value)
        else:
            # Writing the BLOCK1 (MAC_SPI_8M_0) default MAC is not possible,
            # as it's written in the factory.
            raise esptool.FatalError(f"Burning {self.name} is not supported")


# fmt: off
class EfuseKeyPurposeField(EfuseField):
    key_purpose_len = 5  # bits for key purpose
    KeyPurposeType = tuple[str, int, str | None, str | None, str]
    KEY_PURPOSES: list[KeyPurposeType] = [
        ("USER",                         0,  None,       None,      "no_need_rd_protect"),   # User purposes (software-only use)
        ("ECDSA_KEY_P256",               1,  None,       "Reverse", "need_rd_protect"),      # ECDSA key P256 (NIST P-256)
        ("ECDSA_KEY",                    1,  None,       "Reverse", "need_rd_protect"),      # ECDSA key (alias for P256)
        ("XTS_AES_128_KEY",              4,  None,       "Reverse", "need_rd_protect"),      # XTS_AES_128_KEY (flash/PSRAM encryption)
        ("HMAC_DOWN_ALL",                5,  None,       None,      "need_rd_protect"),      # HMAC Downstream mode
        ("HMAC_DOWN_JTAG",               6,  None,       None,      "need_rd_protect"),      # JTAG soft enable key (uses HMAC Downstream mode)
        ("HMAC_DOWN_DIGITAL_SIGNATURE",  7,  None,       None,      "need_rd_protect"),      # Digital Signature peripheral key (uses HMAC Downstream mode)
        ("HMAC_UP",                      8,  None,       None,      "need_rd_protect"),      # HMAC Upstream mode
        ("SECURE_BOOT_DIGEST0",          9,  "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST0 (Secure Boot key digest)
        ("SECURE_BOOT_DIGEST1",          10, "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST1 (Secure Boot key digest)
        ("SECURE_BOOT_DIGEST2",          11, "DIGEST",   None,      "no_need_rd_protect"),   # SECURE_BOOT_DIGEST2 (Secure Boot key digest)
        ("KM_INIT_KEY",                  12, None,       None,      "need_rd_protect"),      # init key that is used for the generation of AES/ECDSA key
        ("ECDSA_KEY_P192",               16, None,       "Reverse", "need_rd_protect"),      # ECDSA key P192 (NIST P-192)
        ("ECDSA_KEY_P384_L",             17, None,       "Reverse", "need_rd_protect"),      # ECDSA key P384 low half
        ("ECDSA_KEY_P384_H",             18, None,       "Reverse", "need_rd_protect"),      # ECDSA key P384 high half
        ("ECDSA_KEY_P384",               -3, "VIRTUAL",  None,      "need_rd_protect"),      # Virtual: one key file -> ECDSA_KEY_P384_L + ECDSA_KEY_P384_H
    ]
    CUSTOM_KEY_PURPOSES: list[KeyPurposeType] = []
    for id in range(0, 1 << key_purpose_len):
        if id not in [p[1] for p in KEY_PURPOSES]:
            CUSTOM_KEY_PURPOSES.append((f"CUSTOM_{id}", id, None, None, "no_need_rd_protect"))
            CUSTOM_KEY_PURPOSES.append((f"CUSTOM_DIGEST_{id}", id, "DIGEST", None, "no_need_rd_protect"))
    CUSTOM_KEY_PURPOSES.append(("CUSTOM_MAX", (1 << key_purpose_len) - 1, None, None, "no_need_rd_protect"))
    CUSTOM_KEY_PURPOSES.append(("CUSTOM_DIGEST_MAX", (1 << key_purpose_len) - 1, "DIGEST", None, "no_need_rd_protect"))
    KEY_PURPOSES += CUSTOM_KEY_PURPOSES
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
        if raw_val.isdigit():
            if int(raw_val) not in [p[1] for p in self.KEY_PURPOSES if p[1] > 0]:
                raise esptool.FatalError(f"'{raw_val}' can not be set (value out of range)")
        else:
            raise esptool.FatalError(f"'{raw_val}' unknown name")
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
        for p in self.KEY_PURPOSES:
            if p[1] == self.get_raw(from_read):
                return p[0]
        return "FORBIDDEN_STATE"

    def get_name(self, raw_val):
        for key in self.KEY_PURPOSES:
            if key[1] == raw_val:
                return key[0]

    def save(self, new_value):
        raw_val = int(self.check_format(str(new_value)))
        str_new_value = self.get_name(raw_val)
        if self.name == "KEY_PURPOSE_5" and str_new_value.startswith("XTS_AES"):
            # see SOC_EFUSE_BLOCK9_KEY_PURPOSE_QUIRK in esp-idf
            raise esptool.FatalError(f"{self.name} can not have {str_new_value} key due to a hardware bug (please see TRM for more details)")
        return super().save(raw_val)
