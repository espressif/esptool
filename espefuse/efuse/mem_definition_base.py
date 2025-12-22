# This file describes eFuses fields and registers for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from collections import Counter
from dataclasses import dataclass, field
import esptool
from esptool.logger import log

from .csv_table_parser import CSVFuseTable


class EfuseRegistersBase:
    EFUSE_MEM_SIZE: int
    DR_REG_EFUSE_BASE: int

    # Coding Scheme values
    CODING_SCHEME_NONE = 0
    CODING_SCHEME_34 = 1
    CODING_SCHEME_REPEAT = 2
    CODING_SCHEME_NONE_RECOVERY = 3
    CODING_SCHEME_RS = 4

    EFUSE_BURN_TIMEOUT = 0.250  # seconds


@dataclass
class BlockDefinition:
    name: str
    alias: list[str]
    id: int
    rd_addr: int
    wr_addr: int
    write_disable_bit: int | None
    read_disable_bit: int | list[int] | None
    len: int
    key_purpose: str | None


class EfuseBlocksBase:
    BLOCKS: list[tuple] = []

    @staticmethod
    def get(tuple_block: tuple) -> BlockDefinition:
        return BlockDefinition(*tuple_block)

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


@dataclass
class Field:
    name: str = ""
    block: int = 0
    word: int | None = None
    pos: int | None = None
    bit_len: int = 0
    alt_names: list[str] = field(default_factory=list)
    type: str = ""
    write_disable_bit: int | None = None
    read_disable_bit: int | list[int] | None = None
    category: str = "config"
    class_type: str = ""
    description: str = ""
    dictionary: dict | None = None

    def __post_init__(self):
        """Automatically generate type string from type prefix if provided."""
        if self.type and ":" not in self.type:
            self.type = self._make_type_string(self.type, self.bit_len)

    @staticmethod
    def _make_type_string(type_prefix: str, bit_len: int) -> str:
        """Generate a type string for a Field based on type prefix and bit length.

        Args:
            type_prefix: The base type ("bytes", "uint", "bool")
            bit_len: The length in bits

        Returns:
            A formatted type string (e.g., "bytes:8", "uint:64", "bool")
        """
        if type_prefix == "bytes":
            if bit_len % 8 != 0:
                raise ValueError(
                    f"bit_len ({bit_len}) must be divisible by 8 for bytes type"
                )
            return f"bytes:{bit_len // 8}"
        elif type_prefix == "uint":
            return f"uint:{bit_len}"
        elif type_prefix == "bool":
            if bit_len != 1:
                raise ValueError(f"bit_len must be 1 for bool type, got {bit_len}")
            return "bool"
        else:
            raise ValueError(
                f"Unknown type prefix: {type_prefix}. Must be bytes, uint, or bool"
            )


class EfuseFieldsBase:
    EFUSES: list[Field] = []

    def __init__(self, e_desc, extend_efuse_table_file) -> None:
        self.ALL_EFUSES: list = []

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

            elif includes(
                name,
                [
                    "ADC",
                    "LDO",
                    "DBIAS",
                    "_HVT",
                    "CALIB",
                    "OCODE",
                    "TEMPERATURE",
                    "LSLP",
                    "DSLP",
                ],
            ):
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
                d = Field(
                    name=e_name,
                    block=data_dict["blk"],
                    word=data_dict["word"],
                    pos=data_dict["pos"],
                    bit_len=data_dict["len"],
                    type=data_dict["type"],
                    write_disable_bit=data_dict["wr_dis"],
                    read_disable_bit=(
                        [int(x) for x in data_dict["rd_dis"].split(" ")]
                        if isinstance(data_dict["rd_dis"], str)
                        else data_dict["rd_dis"]
                    ),
                    description=data_dict["desc"],
                    alt_names=data_dict["alt"].split(" ") if data_dict["alt"] else [],
                    dictionary=eval(data_dict["dict"])
                    if data_dict["dict"] != ""
                    else None,
                )
                set_category_and_class_type(d, e_name)
                self.ALL_EFUSES.append(d)

        if self.extend_efuses(extend_efuse_table_file):
            self.check_name_duplicates()

    def check_name_duplicates(self):
        names = [n.name for n in self.ALL_EFUSES]
        for n in self.ALL_EFUSES:
            if n.alt_names:
                names.extend(n.alt_names)

        name_counts = Counter(names)
        duplicates = {name for name, count in name_counts.items() if count > 1}
        if duplicates:
            log.print("Names that are not unique: " + ", ".join(duplicates))
            raise esptool.FatalError("Duplicate names found in eFuses")

    def extend_efuses(self, extend_efuse_table_file):
        if extend_efuse_table_file:
            table = CSVFuseTable.from_csv(extend_efuse_table_file.read())
            for p in table:
                item = Field(
                    name=p.field_name,
                    block=p.efuse_block,
                    word=p.bit_start // 32,
                    pos=p.bit_start % 32,
                    bit_len=p.bit_count,
                )
                if p.bit_count == 1:
                    str_type = "bool"
                else:
                    if p.bit_count > 32 and p.bit_count % 8 == 0:
                        str_type = f"bytes:{p.bit_count // 8}"
                    else:
                        str_type = f"uint:{p.bit_count}"
                item.type = str_type
                item.write_disable_bit = None
                item.read_disable_bit = None
                if item.block != 0:
                    # look for an already configured field associated with this field
                    # to take the WR_DIS and RID_DIS bits
                    for field in self.ALL_EFUSES:
                        if field.block == item.block:
                            if field.write_disable_bit is not None:
                                item.write_disable_bit = field.write_disable_bit
                            if field.read_disable_bit is not None:
                                item.read_disable_bit = field.read_disable_bit
                            if (
                                item.read_disable_bit is not None
                                and item.write_disable_bit is not None
                            ):
                                break
                item.category = "User"
                item.description = p.comment
                item.alt_names = p.alt_names.split(" ") if p.alt_names else []
                item.dictionary = ""
                self.ALL_EFUSES.append(item)
            return True
        return False
