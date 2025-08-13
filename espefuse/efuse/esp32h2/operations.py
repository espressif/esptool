# This file includes the operations with eFuses for ESP32-H2 chip
#
# SPDX-FileCopyrightText: 2022-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from io import IOBase
from typing import BinaryIO
from esptool.logger import log
import rich_click as click

import espsecure
import esptool

from . import fields
from .mem_definition import EfuseDefineBlocks
from .. import util
from ..base_operations import (
    BaseCommands,
    NonCompositeTuple,
    TupleParameter,
    add_force_write_always,
    add_show_sensitive_info_option,
    protect_options,
)


class ESP32H2Commands(BaseCommands):
    CHIP_NAME = "ESP32-H2"
    efuse_lib = fields.EspEfuses

    ################################### CLI definitions ###################################

    def add_cli_commands(self, cli: click.Group):
        super().add_cli_commands(cli)
        blocks_for_keys = EfuseDefineBlocks().get_blocks_for_keys()

        @cli.command(
            "burn-key",
            help="Burn the key block with the specified name. Arguments are groups of block name, "
            "key file (containing 256 bits of binary key data) and key purpose.\n\n"
            f"Block is one of: [{', '.join(blocks_for_keys)}]\n\n"
            f"Key purpose is one of: [{', '.join(fields.EfuseKeyPurposeField.KEY_PURPOSES_NAME)}]",
        )
        @click.argument(
            "block_keyfile_keypurpose",
            metavar="<BLOCK> <KEYFILE> <KEYPURPOSE>",
            cls=TupleParameter,
            required=True,
            nargs=-1,
            max_arity=len(blocks_for_keys),
            type=NonCompositeTuple(
                [
                    click.Choice(blocks_for_keys),
                    click.File("rb"),
                    click.Choice(fields.EfuseKeyPurposeField.KEY_PURPOSES_NAME),
                ]
            ),
        )
        @protect_options
        @add_force_write_always
        @add_show_sensitive_info_option
        @click.pass_context
        def burn_key_cli(ctx, **kwargs):
            kwargs.pop("force_write_always")
            block, keyfile, keypurpose = zip(*kwargs.pop("block_keyfile_keypurpose"))
            kwargs["show_sensitive_info"] = ctx.show_sensitive_info
            self.burn_key(block, keyfile, keypurpose, **kwargs)

        @cli.command(
            "burn-key-digest",
            short_help="Parse a RSA public key and burn the digest.",
            help="Parse a RSA public key and burn the digest to key eFuse block.\n\n"
            f"Block is one of: [{', '.join(blocks_for_keys)}]\n\n"
            f"Key purpose is one of: [{', '.join(fields.EfuseKeyPurposeField.DIGEST_KEY_PURPOSES)}]",
        )
        @click.argument(
            "block_keyfile_keypurpose",
            metavar="<BLOCK> <KEYFILE> <KEYPURPOSE>",
            cls=TupleParameter,
            required=True,
            nargs=-1,
            max_arity=len(blocks_for_keys),
            type=NonCompositeTuple(
                [
                    click.Choice(blocks_for_keys),
                    click.File("rb"),
                    click.Choice(fields.EfuseKeyPurposeField.DIGEST_KEY_PURPOSES),
                ]
            ),
        )
        @protect_options
        @add_force_write_always
        @add_show_sensitive_info_option
        @click.pass_context
        def burn_key_digest_cli(ctx, **kwargs):
            kwargs.pop("force_write_always")
            block, keyfile, keypurpose = zip(*kwargs.pop("block_keyfile_keypurpose"))
            kwargs["show_sensitive_info"] = ctx.show_sensitive_info
            self.burn_key_digest(block, keyfile, keypurpose, **kwargs)

    ###################################### Commands ######################################

    def adc_info(self):
        log.print("Block version:", self.efuses.get_block_version())
        if self.efuses.get_block_version() >= 2:
            # fmt: off
            log.print(f"Temperature Sensor Calibration = {self.efuses['TEMP_CALIB'].get()}C")
            log.print("")
            log.print("ADC1:")
            log.print("AVE_INITCODE_ATTEN0      = ", self.efuses["ADC1_AVE_INITCODE_ATTEN0"].get())
            log.print("AVE_INITCODE_ATTEN1      = ", self.efuses["ADC1_AVE_INITCODE_ATTEN1"].get())
            log.print("AVE_INITCODE_ATTEN2      = ", self.efuses["ADC1_AVE_INITCODE_ATTEN2"].get())
            log.print("AVE_INITCODE_ATTEN3      = ", self.efuses["ADC1_AVE_INITCODE_ATTEN3"].get())
            log.print("HI_DOUT_ATTEN0           = ", self.efuses["ADC1_HI_DOUT_ATTEN0"].get())
            log.print("HI_DOUT_ATTEN1           = ", self.efuses["ADC1_HI_DOUT_ATTEN1"].get())
            log.print("HI_DOUT_ATTEN2           = ", self.efuses["ADC1_HI_DOUT_ATTEN2"].get())
            log.print("HI_DOUT_ATTEN3           = ", self.efuses["ADC1_HI_DOUT_ATTEN3"].get())
            log.print("CH0_ATTEN0_INITCODE_DIFF = ", self.efuses["ADC1_CH0_ATTEN0_INITCODE_DIFF"].get())
            log.print("CH1_ATTEN0_INITCODE_DIFF = ", self.efuses["ADC1_CH1_ATTEN0_INITCODE_DIFF"].get())
            log.print("CH2_ATTEN0_INITCODE_DIFF = ", self.efuses["ADC1_CH2_ATTEN0_INITCODE_DIFF"].get())
            log.print("CH3_ATTEN0_INITCODE_DIFF = ", self.efuses["ADC1_CH3_ATTEN0_INITCODE_DIFF"].get())
            log.print("CH4_ATTEN0_INITCODE_DIFF = ", self.efuses["ADC1_CH4_ATTEN0_INITCODE_DIFF"].get())
            # fmt: on

    def burn_key(
        self,
        blocks: list[str],
        keyfiles: list[BinaryIO],
        keypurposes: list[str],
        no_write_protect: bool = False,
        no_read_protect: bool = False,
        show_sensitive_info: bool = False,
        digest: list[bytes] | None = None,
    ):
        """Burn the key block with the specified name. Arguments are groups of block name,
        key file (containing 256 bits of binary key data) and key purpose.

        Args:
            blocks: List of eFuse block names to burn keys to.
            keyfiles: List of open files to read key data from.
            keypurposes: List of key purposes to burn.
            no_write_protect: If True, the write protection will NOT be enabled.
            no_read_protect: If True, the read protection will NOT be enabled.
            show_sensitive_info: If True, the sensitive information will be shown.
            digest: List of digests to burn.
        """
        datafile_list: list[BinaryIO] | list[bytes]
        if digest is None:
            datafile_list = keyfiles[
                0 : len([name for name in keyfiles if name is not None]) :
            ]
        else:
            datafile_list = digest[
                0 : len([name for name in digest if name is not None]) :
            ]
        block_name_list = blocks[
            0 : len([name for name in blocks if name is not None]) :
        ]
        keypurpose_list = keypurposes[
            0 : len([name for name in keypurposes if name is not None]) :
        ]

        block_name_list, datafile_list, keypurpose_list = (
            self._adjust_key_data_for_blocks(
                block_name_list,
                datafile_list,  # type: ignore
                keypurpose_list,
            )
        )

        log.print("Burn keys to blocks:")
        for block_name, datafile, keypurpose in zip(
            block_name_list, datafile_list, keypurpose_list
        ):
            efuse = None
            for block in self.efuses.blocks:
                if block_name == block.name or block_name in block.alias:
                    efuse = self.efuses[block.name]
            if efuse is None:
                raise esptool.FatalError(f"Unknown block name - {block_name}.")
            num_bytes = efuse.bit_len // 8

            block_num = self.efuses.get_index_block_by_name(block_name)
            block = self.efuses.blocks[block_num]

            if isinstance(datafile, IOBase):
                data = datafile.read()
                datafile.close()
            else:
                data = datafile

            log.print(f" - {efuse.name}", end=" ")
            revers_msg = None
            if self.efuses[block.key_purpose_name].need_reverse(keypurpose):
                revers_msg = (
                    f"\tReversing byte order for {keypurpose} hardware peripheral..."
                )
                data = data[::-1]
            log.print(
                "-> [{}]".format(
                    util.hexify(data, " ")
                    if show_sensitive_info
                    else " ".join(["??"] * len(data))
                )
            )
            if revers_msg:
                log.print(revers_msg)
            if len(data) != num_bytes:
                raise esptool.FatalError(
                    "Incorrect key file size {}. Key file must be {} bytes ({} bits) "
                    "of raw binary key data.".format(
                        len(data), num_bytes, num_bytes * 8
                    )
                )

            if self.efuses[block.key_purpose_name].need_rd_protect(keypurpose):
                read_protect = False if no_read_protect else True
            else:
                read_protect = False
            write_protect = not no_write_protect

            # using eFuse instead of a block gives the advantage of checking it as the whole field.
            efuse.save(data)

            disable_wr_protect_key_purpose = False
            if self.efuses[block.key_purpose_name].get() != keypurpose:
                if self.efuses[block.key_purpose_name].is_writeable():
                    log.print(
                        f"\t'{block.key_purpose_name}': "
                        f"'{self.efuses[block.key_purpose_name].get()}' -> '{keypurpose}'."
                    )
                    self.efuses[block.key_purpose_name].save(keypurpose)
                    disable_wr_protect_key_purpose = True
                else:
                    raise esptool.FatalError(
                        f"It is not possible to change '{block.key_purpose_name}' "
                        f"to '{keypurpose}' because write protection bit is set."
                    )
            else:
                log.print(f"\t'{block.key_purpose_name}' is already '{keypurpose}'.")
                if self.efuses[block.key_purpose_name].is_writeable():
                    disable_wr_protect_key_purpose = True

            # >= ESP32-H2 ECO5 revision (v1.2) does not have ECDSA_FORCE_USE_HARDWARE_K
            if self.efuses.get_chip_version() <= 101:
                if keypurpose == "ECDSA_KEY":
                    if self.efuses["ECDSA_FORCE_USE_HARDWARE_K"].get() == 0:
                        # For ECDSA key purpose block permanently enable
                        # the hardware TRNG supplied k mode (most secure mode)
                        log.print("\tECDSA_FORCE_USE_HARDWARE_K: 0 -> 1")
                        self.efuses["ECDSA_FORCE_USE_HARDWARE_K"].save(1)
                    else:
                        log.print("\tECDSA_FORCE_USE_HARDWARE_K is already '1'")

            if disable_wr_protect_key_purpose:
                log.print(f"\tDisabling write to '{block.key_purpose_name}'...")
                self.efuses[block.key_purpose_name].disable_write()

            if read_protect:
                log.print("\tDisabling read to key block...")
                efuse.disable_read()

            if write_protect:
                log.print("\tDisabling write to key block...")
                efuse.disable_write()
            log.print("")

        if not write_protect:
            log.print("Keys will remain writeable (due to --no-write-protect).")
        if no_read_protect:
            log.print("Keys will remain readable (due to --no-read-protect).")

        if not self.efuses.burn_all(check_batch_mode=True):
            return
        log.print("Successful.")

    def burn_key_digest(
        self,
        blocks: list[str],
        keyfiles: list[BinaryIO],
        keypurposes: list[str],
        no_write_protect: bool = False,
        no_read_protect: bool = False,
        show_sensitive_info: bool = False,
    ):
        """Parse a RSA public key and burn the digest to key eFuse block.

        Args:
            blocks: List of eFuse block names to burn keys to.
            keyfiles: List of open files to read key data from.
            keypurposes: List of key purposes to burn.
            no_write_protect: If True, the write protection will NOT be enabled.
            no_read_protect: If True, the read protection will NOT be enabled.
            show_sensitive_info: If True, the sensitive information will be shown.
        """
        digest_list = []
        datafile_list = keyfiles[
            0 : len([name for name in keyfiles if name is not None]) :
        ]
        block_list = blocks[0 : len([block for block in blocks if block is not None]) :]

        for block_name, datafile in zip(block_list, datafile_list):
            efuse = None
            for block in self.efuses.blocks:
                if block_name == block.name or block_name in block.alias:
                    efuse = self.efuses[block.name]
            if efuse is None:
                raise esptool.FatalError(f"Unknown block name - {block_name}.")
            num_bytes = efuse.bit_len // 8
            digest = espsecure._digest_sbv2_public_key(datafile)
            if len(digest) != num_bytes:
                raise esptool.FatalError(
                    f"Incorrect digest size {len(digest)}. Digest must be {num_bytes} "
                    f"bytes ({num_bytes * 8} bits) of raw binary key data."
                )
            digest_list.append(digest)

        self.burn_key(
            block_list,
            datafile_list,
            keypurposes,
            no_write_protect,
            no_read_protect,
            show_sensitive_info,
            digest=digest_list,
        )
