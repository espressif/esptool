# This file describes the common eFuses structures for chips
#
# SPDX-FileCopyrightText: 2020-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import binascii
import sys
import typing as t
from abc import ABC, abstractmethod

from bitstring import BitArray, Bits, BitStream, CreationError

import esptool
from espefuse.efuse.mem_definition_base import (
    BlockDefinition,
    EfuseBlocksBase,
    EfuseRegistersBase,
    Field,
)
from esptool.logger import log

from . import util


class CheckArgValue:
    def __init__(self, efuses: "EspEfusesBase", name: str) -> None:
        self.efuses = efuses
        self.name = name

    # This function reports a lot of false positives with mypy because it is
    # using 'efuse_type' for field type checks. Ignore the whole function from mypy.
    @t.no_type_check
    @staticmethod
    def check_arg_value(
        efuse: "EfuseFieldBase", new_value: int | bytes | None
    ) -> int | bytes:
        if efuse.efuse_type.startswith("bool"):
            new_value = 1 if new_value is None else int(new_value, 0)
            if new_value != 1:
                raise esptool.FatalError(
                    f"New value is not accepted for eFuse '{efuse.name}' "
                    f"(will always burn 0->1), given value={new_value}"
                )
        elif efuse.efuse_type.startswith(("int", "uint")):
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
                    raise esptool.FatalError(
                        f"New value required for eFuse '{efuse.name}' (given None)"
                    )
                new_value = int(new_value, 0)
                if new_value == 0:
                    raise esptool.FatalError(
                        f"New value should not be 0 for '{efuse.name}' "
                        f"(given value= {new_value})"
                    )
        elif efuse.efuse_type.startswith("bytes"):
            if new_value is None:
                raise esptool.FatalError(
                    f"New value required for eFuse '{efuse.name}' (given None)"
                )
            if len(new_value) * 8 != efuse.bitarray.len:
                raise esptool.FatalError(
                    f"The length of eFuse '{efuse.name}' ({efuse.bitarray.len} bits) "
                    f"(given len of the new value= {len(new_value) * 8} bits)"
                )
        else:
            raise esptool.FatalError(
                f"The '{efuse.efuse_type}' type for the '{efuse.name}' "
                "eFuse is not supported yet."
            )
        return new_value

    def __call__(self, new_value_str: str | None) -> int | bytes:
        efuse = self.efuses[self.name]
        new_value = efuse.check_format(new_value_str)
        # cast is for type check; used because check_arg_value is not type checked
        return t.cast(int | bytes, self.check_arg_value(efuse, new_value))


class EfuseProtectBase(ABC):
    # This class is used by EfuseBlockBase and EfuseFieldBase
    read_disable_bit: int | list[int] | None
    write_disable_bit: int | None
    parent: "EspEfusesBase"
    name: str

    def get_read_disable_mask(self, blk_part: int | None = None) -> int:
        """Returns mask of read protection bits
        blk_part:
            - None: Calculate mask for all read protection bits.
            - a number: Calculate mask only for specific item in read protection list.
        """
        mask = 0
        if isinstance(self.read_disable_bit, list):
            if blk_part is None:
                for i in self.read_disable_bit:
                    mask |= 1 << i
            else:
                mask |= 1 << self.read_disable_bit[blk_part]
        elif self.read_disable_bit is None:
            raise esptool.FatalError("This eFuse cannot be read-disabled")
        else:
            mask = 1 << self.read_disable_bit
        return mask

    def get_count_read_disable_bits(self) -> int:
        """Returns the number of read protection bits used by the field"""
        # On the C2 chip, BLOCK_KEY0 has two read protection bits [0, 1].
        return bin(self.get_read_disable_mask()).count("1")

    def is_readable(self, blk_part: int | None = None) -> bool:
        """Check if the eFuse is readable by software

        Args:
            blk_part: The part of the block to check.
                If None, check all parts.

        Returns:
            bool: True if the eFuse is readable by software
        """
        num_bit = self.read_disable_bit
        if num_bit is None:
            return True  # read cannot be disabled
        rd_dis = int(self.parent["RD_DIS"].get())
        return (rd_dis & self.get_read_disable_mask(blk_part)) == 0

    def disable_read(self) -> None:
        num_bit = self.read_disable_bit
        if num_bit is None:
            raise esptool.FatalError("This eFuse cannot be read-disabled")
        if not self.parent["RD_DIS"].is_writeable():
            raise esptool.FatalError(
                "This eFuse cannot be read-disabled due to the RD_DIS field being "
                "already write-disabled"
            )
        self.parent["RD_DIS"].save(self.get_read_disable_mask())

    def is_writeable(self) -> bool:
        """Check if the eFuse is writeable by software

        Returns:
            bool: True if the eFuse is writeable by software
        """
        num_bit = self.write_disable_bit
        if num_bit is None:
            return True  # write cannot be disabled
        return (int(self.parent["WR_DIS"].get()) & (1 << num_bit)) == 0

    def disable_write(self) -> None:
        num_bit = self.write_disable_bit
        if num_bit is None:
            raise esptool.FatalError("This eFuse cannot be write-disabled")
        if not self.parent["WR_DIS"].is_writeable():
            raise esptool.FatalError(
                "This eFuse cannot be write-disabled due to the WR_DIS field being "
                "already write-disabled"
            )
        self.parent["WR_DIS"].save(1 << num_bit)

    def check_wr_rd_protect(self) -> None:
        if not self.is_readable():
            error_msg = f"\t{self.name} is read-protected. The written value "
            error_msg += "can not be read, the eFuse/block looks as all 0.\n"
            error_msg += "\tBurn in this case may damage an already written value."
            self.parent.print_error_msg(error_msg)
        if not self.is_writeable():
            error_msg = f"\t{self.name} is write-protected. Burn is not possible."
            self.parent.print_error_msg(error_msg)


class EfuseBlockBase(EfuseProtectBase):
    def __init__(
        self, parent: "EspEfusesBase", param: BlockDefinition, skip_read: bool = False
    ) -> None:
        self.parent: EspEfusesBase = parent
        self.name: str = param.name
        self.alias: list[str] = param.alias
        self.id: int = param.id
        self.rd_addr: int = param.rd_addr
        self.wr_addr: int = param.wr_addr
        self.write_disable_bit: int | None = param.write_disable_bit
        self.read_disable_bit: int | list[int] | None = param.read_disable_bit
        self.len: int = param.len
        self.key_purpose_name: str | None = param.key_purpose
        bit_block_len: int = self.get_block_len() * 8
        self.bitarray: BitStream = BitStream(bit_block_len)
        self.bitarray.set(0)
        self.wr_bitarray: BitStream = BitStream(bit_block_len)
        self.wr_bitarray.set(0)
        self.fail: bool = False
        self.num_errors: int = 0
        if self.id == 0:
            self.err_bitarray: BitStream | None = BitStream(bit_block_len)
            self.err_bitarray.set(0)
        else:
            self.err_bitarray = None

        if not skip_read:
            self.read()

    @abstractmethod
    def apply_coding_scheme(self):
        pass

    def get_block_len(self) -> int:
        coding_scheme = self.get_coding_scheme()
        if coding_scheme == self.parent.REGS.CODING_SCHEME_NONE:
            return self.len * 4
        elif coding_scheme == self.parent.REGS.CODING_SCHEME_34:
            return (self.len * 3 // 4) * 4
        elif coding_scheme == self.parent.REGS.CODING_SCHEME_RS:
            return self.len * 4
        else:
            raise esptool.FatalError(f"Coding scheme ({coding_scheme}) not supported")

    def get_coding_scheme(self) -> int | None:
        if self.id == 0:
            return self.parent.REGS.CODING_SCHEME_NONE
        else:
            return self.parent.coding_scheme

    def get_raw(self, from_read: bool = True) -> bytes:
        if from_read:
            return self.bitarray.bytes  # type: ignore
        else:
            return self.wr_bitarray.bytes  # type: ignore

    def get(self, from_read: bool = True) -> BitStream:
        return self.get_bitstring(from_read=from_read)

    def get_bitstring(self, from_read: bool = True) -> BitStream:
        if from_read:
            return self.bitarray
        else:
            return self.wr_bitarray

    def convert_to_bitstring(self, new_data: BitArray | bytes) -> BitArray:
        if isinstance(new_data, BitArray):
            return new_data
        else:
            return BitArray(bytes=new_data, length=len(new_data) * 8)

    def get_words(self) -> list[int]:
        def get_offsets() -> list[int]:
            return [x + self.rd_addr for x in range(0, self.get_block_len(), 4)]

        return [self.parent.read_reg(offs) for offs in get_offsets()]

    def read(self, print_info: bool = True) -> None:
        words = self.get_words()
        data = BitArray()
        for word in reversed(words):
            data.append(f"uint:32={word}")
        self.bitarray.overwrite(data, pos=0)
        if print_info:
            self.print_block(self.bitarray, "read_regs")

    def print_block(
        self, bit_string: BitStream, comment: str, debug: bool = False
    ) -> None:
        if self.parent.debug or debug:
            bit_string.pos = 0
            log.print(
                f"{self.name:<15s} ({' '.join(self.alias)[:16]:<16s}) "
                f"[{self.id:<2d}] {comment}:",
                " ".join(
                    [
                        f"{word:08x}"
                        for word in bit_string.readlist(
                            f"{int(bit_string.len / 32)}*uint:32"
                        )[::-1]
                    ]
                ),
            )

    def check_wr_data(self) -> None:
        wr_data = self.wr_bitarray
        if wr_data.all(False):
            # nothing to burn
            if self.parent.debug:
                log.print(f"[{self.id:02}] {self.name:20} nothing to burn")
            return
        if len(wr_data.bytes) != len(self.bitarray.bytes):
            raise esptool.FatalError(
                f"Data does not fit: block{self.id} size "
                f"{len(self.bitarray.bytes)} bytes, data {len(wr_data.bytes)} bytes"
            )
        self.check_wr_rd_protect()

        if self.get_bitstring().all(False):
            log.print(
                f"[{self.id:02}] {self.name:20} is empty, will burn the new value"
            )
        else:
            # the written block in chip is not empty
            if self.get_bitstring() == wr_data:
                log.print(
                    f"[{self.id:02}] {self.name:20} is already written the same value, "
                    "continue with EMPTY_BLOCK"
                )
                wr_data.set(0)
            else:
                log.print(f"[{self.id:02}] {self.name:20} is not empty")
                log.print("\t(written ):", self.get_bitstring())
                log.print("\t(to write):", wr_data)
                mask = self.get_bitstring() & wr_data
                if mask == wr_data:
                    log.print(
                        "\tAll wr_data bits are set in the written block, "
                        "continue with EMPTY_BLOCK."
                    )
                    wr_data.set(0)
                else:
                    coding_scheme = self.get_coding_scheme()
                    if coding_scheme == self.parent.REGS.CODING_SCHEME_NONE:
                        log.print("\t(coding scheme = NONE)")
                    elif coding_scheme == self.parent.REGS.CODING_SCHEME_RS:
                        log.print("\t(coding scheme = RS)")
                        error_msg = (
                            f"\tBurn into {self.name} is forbidden "
                            "(RS coding scheme does not allow this)."
                        )
                        self.parent.print_error_msg(error_msg)
                    elif coding_scheme == self.parent.REGS.CODING_SCHEME_34:
                        log.print("\t(coding scheme = 3/4)")
                        data_can_not_be_burn = False
                        for i in range(0, self.get_bitstring().len, 6 * 8):
                            rd_chunk = self.get_bitstring()[i : i + 6 * 8 :]
                            wr_chunk = wr_data[i : i + 6 * 8 :]
                            if rd_chunk.any(True):
                                if wr_chunk.any(True):
                                    log.print(
                                        f"\twritten chunk [{i // (6 * 8)}] and wr_chunk"
                                        " are not empty. ",
                                        end="",
                                    )
                                    if rd_chunk == wr_chunk:
                                        log.print(
                                            "wr_chunk == rd_chunk. "
                                            "Continue with empty chunk."
                                        )
                                        wr_data[i : i + 6 * 8 :].set(0)
                                    else:
                                        log.print("wr_chunk != rd_chunk. Can not burn.")
                                        log.print("\twritten ", rd_chunk)
                                        log.print("\tto write", wr_chunk)
                                        data_can_not_be_burn = True
                        if data_can_not_be_burn:
                            error_msg = (
                                f"\tBurn into {self.name} is forbidden "
                                "(3/4 coding scheme does not allow this)."
                            )
                            self.parent.print_error_msg(error_msg)
                    else:
                        raise esptool.FatalError(
                            f"The coding scheme ({coding_scheme}) is not supported."
                        )

    def save(self, new_data: bytes) -> None:
        # new_data will be checked by check_wr_data() during burn_all()
        # new_data (bytes)  = [0][1][2] ... [N]            (original data)
        # in string format  = [0] [1] [2] ... [N]          (util.hexify(data, " "))
        # in hex format     = 0x[N]....[2][1][0]           (from bitstring print(data))
        # in reg format     = [3][2][1][0] ... [N][][][]   (as it will be in the device)
        # in bitstring      = [N] ... [2][1][0]            (to get a correct bitstring
        #                                                   need to reverse new_data)
        # *[x] - means a byte.
        data = BitStream(bytes=new_data[::-1], length=len(new_data) * 8)
        if self.parent.debug:
            log.print(f"\twritten : {self.get_bitstring()} ->\n\tto write: {data}")
        self.wr_bitarray.overwrite(self.wr_bitarray | data, pos=0)

    def burn_words(self, words: list[int]) -> None:
        for burns in range(3):
            self.parent.efuse_controller_setup()
            if self.parent.debug:
                log.print(f"Write data to BLOCK{self.id}")
            write_reg_addr = self.wr_addr
            for word in words:
                # for ep32s2: using EFUSE_PGM_DATA[0..7]_REG for writing data
                #   32 bytes to EFUSE_PGM_DATA[0..7]_REG
                #   12 bytes to EFUSE_CHECK_VALUE[0..2]_REG. These regs are next after
                #   EFUSE_PGM_DATA_REG
                # for esp32:
                #   each block has the special regs EFUSE_BLK[0..3]_WDATA[0..7]_REG
                #   for writing data
                if self.parent.debug:
                    log.print(f"Addr {write_reg_addr:10x}, data={word:10x}")
                self.parent.write_reg(write_reg_addr, word)
                write_reg_addr += 4

            self.parent.write_efuses(self.id)
            for _ in range(5):
                self.parent.efuse_read()
                self.parent.get_coding_scheme_warnings(silent=True)
                if self.fail or self.num_errors:
                    log.print(
                        f"Error in BLOCK{self.id}, re-burn it again (#{burns}) to fix."
                        f" fail_bit={self.fail}, num_errors={self.num_errors}"
                    )
                    break
            if not self.fail and self.num_errors == 0:
                self.read(print_info=False)
                if self.wr_bitarray & self.bitarray != self.wr_bitarray:
                    # if the required bits are not set then we need to re-burn it again.
                    if burns < 2:
                        log.print(
                            f"\nRepeat burning BLOCK{self.id} (#{burns + 2}) "
                            "because not all bits were set"
                        )
                        continue
                    else:
                        log.print(
                            f"\nAfter {burns + 1} attempts, the required data was not "
                            f"set to BLOCK{self.id}"
                        )
                break

    def burn(self) -> None:
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
            log.print(
                f"{self.name} ({self.alias}) is read-protected. "
                "Read back the burn value is not possible."
            )
            if self.bitarray.all(False):
                log.print("Read all '0'")
            else:
                # Should never happen
                raise esptool.FatalError(
                    f"The {self.name} is read-protected but not all '0' "
                    f"({self.bitarray.hex})"
                )
        else:
            if self.wr_bitarray == self.bitarray:
                log.print(f"BURN BLOCK{self.id:<2d} - OK (write block == read block)")
            elif (
                self.wr_bitarray & self.bitarray == self.wr_bitarray
                and self.bitarray & before_burn_bitarray == before_burn_bitarray
            ):
                log.print(
                    f"BURN BLOCK{self.id:<2d} - OK (all write block bits are set)"
                )
            else:
                # Happens only when an efuse is written and read-protected
                # in one command
                self.print_block(self.wr_bitarray, "Expected")
                self.print_block(self.bitarray, "Real    ")
                # Read-protected BLK0 values are reported back as zeros,
                # raise error only for other blocks
                if self.id != 0:
                    raise esptool.FatalError(
                        f"Burn {self.name} ({self.alias}) was not successful."
                    )
        self.wr_bitarray.set(0)


class EspEfusesBase(ABC):
    """
    Wrapper object to manage the efuse fields in a connected ESP bootloader
    """

    _esp: esptool.ESPLoader
    blocks: list[EfuseBlockBase] = []
    efuses: list["EfuseFieldBase"] = []
    coding_scheme = None
    force_write_always = None
    batch_mode_cnt: int = 0
    postpone: bool = False
    BURN_BLOCK_DATA_NAMES: list[str] = []
    REGS: type[EfuseRegistersBase]
    Blocks: EfuseBlocksBase

    def __init__(
        self,
        esp: esptool.ESPLoader,
        skip_connect: bool = False,
        debug: bool = False,
        do_not_confirm: bool = False,
        extend_efuse_table: None = None,
    ) -> None:
        self._esp = esp
        self.debug = debug
        self.do_not_confirm = do_not_confirm

    def __iter__(self) -> t.Iterator["EfuseFieldBase"]:
        return self.efuses.__iter__()

    def __getitem__(self, efuse_name: str) -> "EfuseFieldBase":
        """Return the efuse field with the given name (by name or any alt_names)"""
        for e in self.efuses:
            if self._match_efuse_name(efuse_name, e):
                return e
        for lazy_group in self._get_lazy_efuse_groups():
            for efuse in lazy_group:
                if self._match_efuse_name(efuse_name, efuse):
                    self.efuses += self._convert_efuse_defs(lazy_group)
                    break
        for e in self.efuses:
            if self._match_efuse_name(efuse_name, e):
                return e
        raise KeyError(efuse_name)

    def _match_efuse_name(
        self, efuse_name: str, efuse: "Field | EfuseFieldBase"
    ) -> bool:
        """Return True if efuse_name matches the efuse name or any alt name."""
        return efuse_name == efuse.name or any(x == efuse_name for x in efuse.alt_names)

    @abstractmethod
    def _convert_efuse_defs(self, efuse_defs: list) -> list["EfuseFieldBase"]:
        """Convert a list of efuse definitions to field instances."""
        # Convert is different for each chip, as there are different field types.
        # The implementation of this method is usually the same for all chips,
        # only the source of convert method changes.
        pass

    @abstractmethod
    def _get_lazy_efuse_groups(self) -> list[list[Field]]:
        """Return a list of lazy-load groups. Each group is a sequence of efuse defs."""
        pass

    def get_crystal_freq(self) -> int:
        return self._esp.get_crystal_freq()  # type: ignore

    def read_efuse(self, n: int) -> int:
        """Read the nth word of the ESP3x EFUSE region."""
        return self._esp.read_efuse(n)  # type: ignore

    def read_reg(self, addr: int) -> t.Any:
        return self._esp.read_reg(addr)

    def write_reg(
        self,
        addr: int,
        value: int,
        mask: int = 0xFFFFFFFF,
        delay_us: int = 0,
        delay_after_us: int = 0,
    ) -> t.Any:
        return self._esp.write_reg(addr, value, mask, delay_us, delay_after_us)

    def update_reg(self, addr: int, mask: int, new_val: int) -> t.Any:
        return self._esp.update_reg(addr, mask, new_val)

    def efuse_controller_setup(self) -> None:
        pass

    @abstractmethod
    def write_efuses(self, block: int) -> int:
        pass

    @abstractmethod
    def efuse_read(self) -> None:
        pass

    @abstractmethod
    def read_coding_scheme(self) -> None:
        pass

    def reconnect_chip(self, esp: esptool.ESPLoader) -> esptool.ESPLoader:
        log.print("Re-connecting...")
        baudrate = esp._port.baudrate
        port = esp._port.port
        connect_mode = "usb-reset" if esp.uses_usb_jtag_serial() else "default-reset"
        log.print(f"Port: {port}, Baudrate: {baudrate}, Connect mode: {connect_mode}")
        esp._port.close()
        return esptool.detect_chip(port, baudrate, connect_mode)

    def get_index_block_by_name(self, name: str) -> int:
        for block in self.blocks:
            if block.name == name or name in block.alias:
                return block.id
        raise esptool.FatalError(f"Block {name} not found")

    def read_blocks(self) -> None:
        for block in self.blocks:
            block.read()

    def update_efuses(self) -> None:
        for efuse in self.efuses:
            efuse.update(self.blocks[efuse.block].bitarray)

    def postpone_efuses_from_block0_to_burn(
        self, block: "EfuseBlockBase"
    ) -> dict[str, BitStream]:
        postpone_efuses: dict[str, BitStream] = {}

        if block.id != 0:
            return postpone_efuses

        # We need to check this list of efuses. If we are going to burn an efuse
        # from this list, then we need to split the burn operation into two
        # steps. The first step involves burning efuses not in this list. In
        # case of an error during this step, we can recover by burning the
        # efuses from this list at the very end. This approach provides the
        # ability to recover efuses if an error occurs during the initial burn
        # operation.

        # List the efuses here that must be burned at the very end, such as read
        # and write protection fields, as well as efuses that disable
        # communication with the espefuse tool.
        efuses_list = ["WR_DIS", "RD_DIS"]
        if self._esp.CHIP_NAME == "ESP32":
            # Efuses below disables communication with the espefuse tool.
            efuses_list.append("UART_DOWNLOAD_DIS")
            # other efuses that are better to burn at the very end.
            efuses_list.append("ABS_DONE_1")
            efuses_list.append("FLASH_CRYPT_CNT")
        else:
            # Efuses below disables communication with the espefuse tool.
            efuses_list.append("ENABLE_SECURITY_DOWNLOAD")
            efuses_list.append("DIS_DOWNLOAD_MODE")
            # other efuses that are better to burn at the very end.
            efuses_list.append("SPI_BOOT_CRYPT_CNT")
            efuses_list.append("SECURE_BOOT_EN")

        def get_raw_value_from_write(efuse_name: str) -> BitStream | Bits:
            return self[efuse_name].get_bitstring(from_read=False)

        for efuse_name in efuses_list:
            postpone_efuses[efuse_name] = get_raw_value_from_write(efuse_name)

        if any(value != 0 for value in postpone_efuses.values()):
            if self.debug:
                log.print("These BLOCK0 eFuses will be burned later at the very end:")
                log.print(postpone_efuses)
            # exclude these efuses from the first burn (postpone them till the end).
            for key_name in postpone_efuses.keys():
                self[key_name].reset()
        return postpone_efuses

    def recover_postponed_efuses_from_block0_to_burn(
        self, postpone_efuses: dict[str, BitStream]
    ) -> None:
        if any(value != 0 for value in postpone_efuses.values()):
            log.print("Burn postponed eFuses from BLOCK0.")
            for key_name in postpone_efuses.keys():
                self[key_name].save(postpone_efuses[key_name])

    def burn_all(self, check_batch_mode: bool = False) -> bool:
        if check_batch_mode:
            if self.batch_mode_cnt != 0:
                log.print(
                    "\nBatch mode is enabled, "
                    "the burn will be done at the end of the command."
                )
                return False
        log.print("\nCheck all blocks for burn...")
        log.print("idx, BLOCK_NAME,          Conclusion")
        have_wr_data_for_burn = False
        for block in self.blocks:
            block.check_wr_data()
            if not have_wr_data_for_burn and block.get_bitstring(from_read=False).any(
                True
            ):
                have_wr_data_for_burn = True
        if not have_wr_data_for_burn:
            log.print("Nothing to burn, see messages above.")
            return True
        EspEfusesBase.confirm("", self.do_not_confirm)

        def burn_block(
            block: EfuseBlockBase, postponed_efuses: dict[str, BitStream] | None
        ) -> None:
            old_fail = block.fail
            old_num_errors = block.num_errors
            block.burn()
            if (block.fail and old_fail != block.fail) or (
                block.num_errors and block.num_errors > old_num_errors
            ):
                if postponed_efuses:
                    log.print("The postponed eFuses were not burned due to an error.")
                    log.print("\t1. Try to fix a coding error by this cmd:")
                    log.print("\t   'espefuse check-error --recovery'")
                    command_string = " ".join(
                        f"{key} {value}"
                        for key, value in postponed_efuses.items()
                        if value.any(True)
                    )
                    log.print("\t2. Then run the cmd to burn all postponed eFuses:")
                    log.print(f"\t   'espefuse burn-efuse {command_string}'")

                raise esptool.FatalError("Error(s) were detected in eFuses")

        # Burn from BLKn -> BLK0. Because BLK0 can set rd or/and wr protection bits.
        for block in reversed(self.blocks):
            postponed_efuses = (
                self.postpone_efuses_from_block0_to_burn(block)
                if self.postpone
                else None
            )

            burn_block(block, postponed_efuses)

            if postponed_efuses:
                self.recover_postponed_efuses_from_block0_to_burn(postponed_efuses)
                burn_block(block, postponed_efuses)

        log.print("Reading updated eFuses...")
        self.read_coding_scheme()
        self.read_blocks()
        self.update_efuses()
        return True

    @staticmethod
    def confirm(action: str, do_not_confirm: bool) -> None:
        log.print(
            "{}{}\nThis is an irreversible operation!".format(
                action, "" if action.endswith("\n") else ". "
            )
        )
        if not do_not_confirm:
            log.print("Type 'BURN' (all capitals) to continue.", flush=True)
            # Flush required for Pythons which disable line buffering,
            # ie mingw in mintty
            yes = input()
            if yes != "BURN":
                log.print("Aborting.")
                sys.exit(0)

    def print_error_msg(self, error_msg: str) -> None:
        if self.force_write_always is not None:
            if not self.force_write_always:
                error_msg += "(use '--force-write-always' option to ignore it)"
        if self.force_write_always:
            log.print(error_msg, "Skipped because '--force-write-always' option.")
        else:
            raise esptool.FatalError(error_msg)

    def get_block_errors(self, block_num: int) -> tuple[int, bool]:
        """Returns (error count, failure boolean flag)"""
        return self.blocks[block_num].num_errors, self.blocks[block_num].fail

    def is_efuses_incompatible_for_burn(self) -> bool:
        # Overwrite this function for a specific target if you want to check if a
        # certain eFuse(s) can be burned.
        return False

    def get_major_chip_version(self) -> int:
        try:
            return int(self["WAFER_VERSION_MAJOR"].get())
        except KeyError:
            return 0

    def get_minor_chip_version(self) -> int:
        try:
            return int(self["WAFER_VERSION_MINOR"].get())
        except KeyError:
            return 0

    def get_chip_version(self) -> int:
        return self.get_major_chip_version() * 100 + self.get_minor_chip_version()

    def get_major_block_version(self) -> int:
        try:
            return int(self["BLK_VERSION_MAJOR"].get())
        except KeyError:
            return 0

    def get_minor_block_version(self) -> int:
        try:
            return int(self["BLK_VERSION_MINOR"].get())
        except KeyError:
            return 0

    def get_block_version(self) -> int:
        return self.get_major_block_version() * 100 + self.get_minor_block_version()

    def get_pkg_version(self) -> int:
        try:
            return int(self["PKG_VERSION"].get())
        except KeyError:
            return 0

    @abstractmethod
    def summary(self) -> str:
        pass

    @abstractmethod
    def get_coding_scheme_warnings(self, silent: bool = False) -> bool:
        pass


class EfuseFieldBase(EfuseProtectBase):
    def __init__(self, parent: "EspEfusesBase", param: Field) -> None:
        self.category = param.category
        self.parent = parent
        self.block = param.block
        self.word = param.word
        self.pos = param.pos
        self.write_disable_bit = param.write_disable_bit
        self.read_disable_bit = param.read_disable_bit
        self.name = param.name
        self.efuse_class = param.class_type
        self.efuse_type: str = param.type
        self.description = param.description
        self.dict_value = param.dictionary
        self.bit_len = param.bit_len
        self.alt_names = param.alt_names
        self.fail = False
        self.num_errors = 0
        self.bitarray = BitStream(self.bit_len)
        self.bitarray.set(0)
        self.update(self.parent.blocks[self.block].bitarray)

    @property
    def all_names(self) -> list[str]:
        return [self.name] + [name for name in self.alt_names if name != ""]

    @staticmethod
    @abstractmethod
    def convert(parent: "EspEfusesBase", param: Field) -> "EfuseFieldBase":
        pass

    def is_field_calculated(self) -> bool:
        return self.word is None or self.pos is None

    def check_format(self, new_value_str: str | None) -> bytes | str | None:
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

    def convert_to_bitstring(self, new_value: BitArray | bytes | str | int) -> BitArray:
        if isinstance(new_value, BitArray):
            return new_value
        else:
            if self.efuse_type.startswith("bytes"):
                # new_value (bytes) = [0][1][2] ... [N]
                #                                                        (original data)
                # in string format  = [0] [1] [2] ... [N]
                #                                               (util.hexify(data, " "))
                # in hex format     = 0x[N]....[2][1][0]
                #                                           (from bitstring print(data))
                # in reg format     = [3][2][1][0] ... [N][][][]
                #                                          (as it will be in the device)
                # in bitstring      = [N] ... [2][1][0]
                #                 (to get a correct bitstring need to reverse new_value)
                # *[x] - means a byte.
                return BitArray(bytes=new_value[::-1], length=len(new_value) * 8)  # type: ignore
            else:
                try:
                    return BitArray(self.efuse_type + f"={new_value}")  # type: ignore[str-bytes-safe]
                except CreationError as err:
                    log.print(
                        f"New value '{new_value}' is not suitable for "  # type: ignore[str-bytes-safe]
                        f"{self.name} ({self.efuse_type})"
                    )
                    raise esptool.FatalError(err)

    def check_new_value(self, bitarray_new_value: BitArray) -> None:
        bitarray_old_value = self.get_bitstring() | self.get_bitstring(from_read=False)

        if not bitarray_new_value.any(True) and not bitarray_old_value.any(True):
            return

        if bitarray_new_value.len != bitarray_old_value.len:
            raise esptool.FatalError(
                f"For {self.name} eFuse, the length of the new value is wrong, "
                f"expected {bitarray_old_value.len} bits, "
                f"was {bitarray_new_value.len} bits."
            )
        if (
            bitarray_new_value == bitarray_old_value
            or bitarray_new_value & self.get_bitstring() == bitarray_new_value
        ):
            error_msg = f"\tThe same value for {self.name} "
            error_msg += "is already burned. Do not change the eFuse."
            log.print(error_msg)
            bitarray_new_value.set(0)
        elif bitarray_new_value == self.get_bitstring(from_read=False):
            error_msg = f"\tThe same value for {self.name} "
            error_msg += "is already prepared for the burn operation."
            log.print(error_msg)
            bitarray_new_value.set(0)
        else:
            if self.name not in ["WR_DIS", "RD_DIS"]:
                # WR_DIS, RD_DIS fields can have already set bits.
                # Do not need to check below condition for them.
                if bitarray_new_value | bitarray_old_value != bitarray_new_value:
                    error_msg = "\tNew value contains some bits that cannot be cleared "
                    error_msg += (
                        f"(value will be {bitarray_old_value | bitarray_new_value})"
                    )
                    self.parent.print_error_msg(error_msg)
            self.check_wr_rd_protect()

    def save_to_block(self, bitarray_field: BitArray) -> None:
        block = self.parent.blocks[self.block]
        wr_bitarray_temp = block.wr_bitarray.copy()
        position = wr_bitarray_temp.length - (
            self.word * 32 + self.pos + bitarray_field.len  # type: ignore
        )
        wr_bitarray_temp.overwrite(bitarray_field, pos=position)
        block.wr_bitarray |= wr_bitarray_temp

    def save(self, new_value: int | bytes | BitArray) -> None:
        bitarray_field = self.convert_to_bitstring(new_value)
        self.check_new_value(bitarray_field)
        self.save_to_block(bitarray_field)

    def update(self, bit_array_block: BitStream) -> None:
        if self.is_field_calculated():
            self.bitarray.overwrite(
                self.convert_to_bitstring(self.check_format(self.get())),  # type: ignore
                pos=0,
            )
            return
        field_len = self.bitarray.len
        bit_array_block.pos = bit_array_block.length - (
            self.word * 32 + self.pos + field_len  # type: ignore
        )
        self.bitarray.overwrite(bit_array_block.read(field_len), pos=0)
        err_bitarray = self.parent.blocks[self.block].err_bitarray
        if err_bitarray is not None:
            err_bitarray.pos = err_bitarray.length - (
                self.word * 32 + self.pos + field_len  # type: ignore
            )
            self.fail = not err_bitarray.read(field_len).all(False)
        else:
            self.fail = self.parent.blocks[self.block].fail
            self.num_errors = self.parent.blocks[self.block].num_errors

    def get_raw(self, from_read: bool = True) -> int | bool | bytes:
        """Return the raw (unformatted) numeric value of the eFuse bits

        Args:
            from_read: If True, read the eFuse value from the device.
                If False, use the cached value.

        Returns:
            int | bool | bytes: The raw value of the eFuse
        """
        return self.get_bitstring(from_read).read(self.efuse_type)  # type: ignore

    def get(self, from_read: bool = True) -> str | int | float | bool:
        """Get a formatted version of the eFuse value, suitable for display

        type: int -> int
        type: bool -> bool
        type: bytes -> str  "01 02 03 04 05 06 07 08 ... ".
        Byte order [0] ... [N]. dump regs: 0x04030201 0x08070605 ...

        Args:
            from_read: If True, read the eFuse value from the device.
                If False, use the cached value.

        Returns:
            str | int | float | bool: The formatted version of the eFuse value
        """
        if self.efuse_type.startswith("bytes"):
            return util.hexify(self.get_bitstring(from_read).bytes[::-1], " ")  # type: ignore
        else:
            return self.get_raw(from_read)  # type: ignore

    def get_meaning(self, from_read: bool = True) -> str | int | float | bool:
        """Get the meaning of eFuse from dict if possible, suitable for display

        Args:
            from_read: If True, read the eFuse value from the device.
                If False, use the cached value.

        Returns:
            str | int | bool: The meaning of the eFuse
        """
        if self.dict_value:
            try:
                return self.dict_value[self.get_raw(from_read)]  # type: ignore
            except KeyError:
                pass
        return self.get(from_read)

    def get_bitstring(self, from_read: bool = True) -> BitStream | Bits:
        if from_read:
            self.bitarray.pos = 0
            return self.bitarray
        else:
            field_len = self.bitarray.len
            block: EfuseBlockBase = self.parent.blocks[self.block]
            block.wr_bitarray.pos = block.wr_bitarray.length - (
                self.word * 32 + self.pos + field_len  # type: ignore
            )
            return block.wr_bitarray.read(self.bitarray.len)

    def burn(self, new_value):
        """Burn a eFuse. Added for compatibility reason."""
        self.save(new_value)
        self.parent.burn_all()

    def get_info(self):
        output = f"{self.name} (BLOCK{self.block})"
        if self.block == 0:
            if self.fail:
                output += "[error]"
        else:
            errs, fail = self.parent.get_block_errors(self.block)
            if errs != 0 or fail:
                output += "[error]"
        if self.efuse_class == "keyblock":
            name = self.parent.blocks[self.block].key_purpose_name
            if name is not None:
                output += f"\n  Purpose: {self.parent[name].get()}\n "
        return output

    def reset(self):
        """Resets a eFuse that is prepared for burning"""
        bitarray_field = self.convert_to_bitstring(0)
        block = self.parent.blocks[self.block]
        wr_bitarray_temp = block.wr_bitarray.copy()
        position = wr_bitarray_temp.length - (
            self.word * 32 + self.pos + bitarray_field.len
        )
        wr_bitarray_temp.overwrite(bitarray_field, pos=position)
        block.wr_bitarray = wr_bitarray_temp

    # The following methods are used for type checking.
    # The real implementation should be done in KeyPurposeField class.
    def need_reverse(self, key_purpose: str) -> bool:
        raise NotImplementedError("need_reverse is not implemented for this field")

    def need_rd_protect(self, key_purpose: str) -> bool:
        raise NotImplementedError("need_rd_protect is not implemented for this field")


class EfuseWaferBase(EfuseFieldBase):
    @abstractmethod
    def get(self, from_read: bool = True) -> int:
        pass

    def save(self, new_value: int | bytes | BitArray) -> None:
        raise esptool.FatalError(f"Burning {self.name} is not supported.")


class EfuseTempSensor(EfuseFieldBase):
    def get(self, from_read: bool = True) -> float:
        value = self.get_bitstring(from_read)
        sig = -1 if value[0] else 1
        return sig * int(value[1:].uint) * 0.1


class EfuseAdcPointCalibration(EfuseFieldBase):
    STEP_SIZE: int = 4

    def get(self, from_read: bool = True) -> int:
        value = self.get_bitstring(from_read)
        sig = -1 if value[0] else 1
        return sig * int(value[1:].uint) * self.STEP_SIZE


class EfuseMacFieldBase(EfuseFieldBase):
    def check_format(self, new_value_str: str | None) -> bytes:
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
        hexad = new_value_str.replace(":", "")
        hexad = hexad.split(" ", 1)[0]  # remove " (OK)" when combining fields
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

    def check(self) -> str:
        errs, fail = self.parent.get_block_errors(self.block)
        if errs != 0 or fail:
            output = f"Block{self.block} has ERRORS:{errs} FAIL:{fail}"
        else:
            output = "OK"
        return f"({output})"

    def get(self, from_read: bool = True) -> str:
        if self.name == "CUSTOM_MAC":
            mac = self.get_raw(from_read)[::-1]  # type: ignore
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

    def save(self, new_value: int | bytes | BitArray) -> None:
        def print_field(e: EfuseFieldBase, new_value: t.Any) -> None:
            log.print(
                f"    - '{e.name}' ({e.description}) {e.get_bitstring()} -> {new_value}"
            )

        if self.name == "CUSTOM_MAC":
            bitarray_mac = self.convert_to_bitstring(new_value)
            print_field(self, bitarray_mac)
            super().save(new_value)
        else:
            raise esptool.FatalError(f"Burning {self.name} is not supported.")


class EfuseKeyPurposeFieldBase(EfuseFieldBase):
    # KeyPurposeType: Name, ID, Digest, Reverse, RD Protect
    KeyPurposeType = tuple[str, int, str | None, str | None, str]

    # Set in subclass
    key_purpose_len: int = 0  # Number of bits for custom key purposes
    KEY_PURPOSES: list[KeyPurposeType]

    # Automatically set based on KEY_PURPOSES
    KEY_PURPOSES_NAME: list[str]
    DIGEST_KEY_PURPOSES: list[str]
    CUSTOM_KEY_PURPOSES: list[KeyPurposeType]

    # This method ensures that all class variables are initialized based
    # on the subclass's KEY_PURPOSES only once per inheritance instead of per instance
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # We need to initialize the CUSTOM_KEY_PURPOSES; so each chip has fresh list
        cls.CUSTOM_KEY_PURPOSES = []
        # Add custom key purposes if key_purpose_len is set
        if cls.key_purpose_len > 0:
            for id in range(0, 1 << cls.key_purpose_len):
                if id not in [p[1] for p in cls.KEY_PURPOSES]:
                    cls.CUSTOM_KEY_PURPOSES.append(
                        (f"CUSTOM_{id}", id, None, None, "no_need_rd_protect")
                    )
                    cls.CUSTOM_KEY_PURPOSES.append(
                        (
                            f"CUSTOM_DIGEST_{id}",
                            id,
                            "DIGEST",
                            None,
                            "no_need_rd_protect",
                        )
                    )
            cls.CUSTOM_KEY_PURPOSES.append(
                (
                    "CUSTOM_MAX",
                    (1 << cls.key_purpose_len) - 1,
                    None,
                    None,
                    "no_need_rd_protect",
                )
            )
            cls.CUSTOM_KEY_PURPOSES.append(
                (
                    "CUSTOM_DIGEST_MAX",
                    (1 << cls.key_purpose_len) - 1,
                    "DIGEST",
                    None,
                    "no_need_rd_protect",
                )
            )
            cls.KEY_PURPOSES += cls.CUSTOM_KEY_PURPOSES

        cls.KEY_PURPOSES_NAME = [name[0] for name in cls.KEY_PURPOSES]
        cls.DIGEST_KEY_PURPOSES = [
            name[0] for name in cls.KEY_PURPOSES if name[2] == "DIGEST"
        ]

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
                raise esptool.FatalError(
                    f"'{raw_val}' can not be set (value out of range)"
                )
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
        return super().save(raw_val)
