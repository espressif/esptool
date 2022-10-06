# This file describes eFuses fields and registers for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from collections import namedtuple


class EfuseRegistersBase(object):
    # Coding Scheme values
    CODING_SCHEME_NONE = 0
    CODING_SCHEME_34 = 1
    CODING_SCHEME_REPEAT = 2
    CODING_SCHEME_NONE_RECOVERY = 3
    CODING_SCHEME_RS = 4

    EFUSE_BURN_TIMEOUT = 0.250  # seconds


class EfuseBlocksBase(object):
    BLOCKS = None
    NamedtupleBlock = namedtuple(
        "Block",
        "name alias id rd_addr wr_addr write_disable_bit "
        "read_disable_bit len key_purpose",
    )

    @staticmethod
    def get(tuple_block):
        return EfuseBlocksBase.NamedtupleBlock._make(tuple_block)

    def get_blocks_for_keys(self):
        list_of_names = []
        for block in self.BLOCKS:
            blk = self.get(block)
            if blk.id > 0:
                if blk.name:
                    list_of_names.append(blk.name)
                if blk.alias:
                    for alias in blk.alias:
                        list_of_names.append(alias)
        return list_of_names


class Field:
    name = ""
    block = 0
    word = None
    pos = None
    bit_len = 0
    alt_names = []
    type = ""
    write_disable_bit = None
    read_disable_bit = None
    category = "config"
    class_type = ""
    description = ""
    dictionary = None


class EfuseFieldsBase(object):
    def __init__(self, e_desc) -> None:
        self.ALL_EFUSES = []

        def set_category_and_class_type(efuse, name):
            def includes(name, names):
                return any([word in name for word in names])

            if name.startswith("SPI_PAD_CONFIG"):
                efuse.category = "spi pad"

            elif "USB" in name:
                efuse.category = "usb"

            elif "WDT" in name:
                efuse.category = "wdt"

            elif "JTAG" in name:
                efuse.category = "jtag"

            elif includes(name, ["FLASH", "FORCE_SEND_RESUME"]):
                efuse.category = "flash"

            elif includes(name, ["VDD_SPI_", "XPD"]):
                efuse.category = "vdd"

            elif "MAC" in name:
                efuse.category = "MAC"
                if name in ["MAC", "CUSTOM_MAC", "MAC_EXT"]:
                    efuse.class_type = "mac"

            elif includes(
                name,
                [
                    "BLOCK_KEY0",
                    "BLOCK_KEY1",
                    "BLOCK_KEY2",
                    "BLOCK_KEY3",
                    "BLOCK_KEY4",
                    "BLOCK_KEY5",
                    "BLOCK1",
                    "BLOCK2",
                ],
            ):
                efuse.category = "security"
                efuse.class_type = "keyblock"

            elif includes(
                name,
                [
                    "KEY",
                    "SECURE",
                    "DOWNLOAD",
                    "SPI_BOOT_CRYPT_CNT",
                    "KEY_PURPOSE",
                    "SECURE_VERSION",
                    "DPA",
                    "ECDSA",
                    "FLASH_CRYPT_CNT",
                    "ENCRYPT",
                    "DECRYPT",
                    "ABS_DONE",
                ],
            ):
                efuse.category = "security"
                if name.startswith("KEY_PURPOSE"):
                    efuse.class_type = "keypurpose"
                elif includes(
                    name, ["FLASH_CRYPT_CNT", "SPI_BOOT_CRYPT_CNT", "SECURE_VERSION"]
                ):
                    efuse.class_type = "bitcount"

            elif includes(name, ["VERSION", "WAFER", "_ID", "PKG", "PACKAGE", "REV"]):
                efuse.category = "identity"
                if name == "OPTIONAL_UNIQUE_ID":
                    efuse.class_type = "keyblock"

            elif includes(name, ["ADC", "LDO", "DBIAS", "_HVT", "CALIB", "OCODE"]):
                efuse.category = "calibration"
                if name == "ADC_VREF":
                    efuse.class_type = "vref"
                    return
                if includes(name, ["ADC", "LDO", "DBIAS", "_HVT"]):
                    efuse.class_type = "adc_tp"
                elif name == "TEMP_CALIB":
                    efuse.class_type = "t_sensor"

        for e_name in e_desc["EFUSES"]:
            data_dict = e_desc["EFUSES"][e_name]
            if data_dict["show"] == "y":
                d = Field()
                d.name = e_name
                d.block = data_dict["blk"]
                d.word = data_dict["word"]
                d.pos = data_dict["pos"]
                d.bit_len = data_dict["len"]
                d.type = data_dict["type"]
                d.write_disable_bit = data_dict["wr_dis"]
                d.read_disable_bit = (
                    [int(x) for x in data_dict["rd_dis"].split(" ")]
                    if isinstance(data_dict["rd_dis"], str)
                    else data_dict["rd_dis"]
                )
                d.description = data_dict["desc"]
                d.alt_names = data_dict["alt"].split(" ") if data_dict["alt"] else []
                d.dictionary = (
                    eval(data_dict["dict"]) if data_dict["dict"] != "" else None
                )
                set_category_and_class_type(d, e_name)
                self.ALL_EFUSES.append(d)
