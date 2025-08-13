# This file includes the operations with eFuses for ESP32-S3 chip
#
# SPDX-FileCopyrightText: 2020-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import io
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
    TupleParameter,
    NonCompositeTuple,
    add_force_write_always,
    add_show_sensitive_info_option,
    protect_options,
)


class ESP32S3Commands(BaseCommands):
    CHIP_NAME = "ESP32-S3"
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
            """Burn the key block with the specified name"""
            kwargs.pop("force_write_always")
            block, keyfile, keypurpose = zip(*kwargs.pop("block_keyfile_keypurpose"))
            kwargs["show_sensitive_info"] = ctx.show_sensitive_info
            self.burn_key(block, keyfile, keypurpose, **kwargs)

        @cli.command(
            "burn-key-digest",
            help="Burn the key block with the specified name. Arguments are groups of block name, "
            "key file (containing 256 bits of binary key data) and key purpose.\n\n"
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
            """Parse a RSA public key and burn the digest to key eFuse block"""
            kwargs.pop("force_write_always")
            block, keyfile, keypurpose = zip(*kwargs.pop("block_keyfile_keypurpose"))
            kwargs["show_sensitive_info"] = ctx.show_sensitive_info
            self.burn_key_digest(block, keyfile, keypurpose, **kwargs)

        @cli.command(
            "set-flash-voltage",
            short_help="Permanently set the internal flash voltage regulator.",
        )
        @click.argument("voltage", type=click.Choice(["1.8V", "3.3V", "OFF"]))
        def set_flash_voltage_cli(voltage):
            """Permanently set the internal flash voltage regulator to either 1.8V, 3.3V or OFF.
            This means GPIO45 can be high or low at reset without changing the flash voltage."""
            self.set_flash_voltage(voltage)

    ###################################### Commands ######################################

    def set_flash_voltage(self, voltage: str):
        sdio_force = self.efuses["VDD_SPI_FORCE"]
        sdio_tieh = self.efuses["VDD_SPI_TIEH"]
        sdio_reg = self.efuses["VDD_SPI_XPD"]

        # check efuses aren't burned in a way which makes this impossible
        if voltage == "OFF" and sdio_reg.get() != 0:
            raise esptool.FatalError(
                "Can't set flash regulator to OFF as VDD_SPI_XPD eFuse is already burned"
            )

        if voltage == "1.8V" and sdio_tieh.get() != 0:
            raise esptool.FatalError(
                "Can't set regulator to 1.8V is VDD_SPI_TIEH eFuse is already burned"
            )

        if voltage == "OFF":
            log.print(
                "Disable internal flash voltage regulator (VDD_SPI). "
                "SPI flash will need to be powered from an external source.\n"
                "The following eFuse is burned: VDD_SPI_FORCE.\n"
                "It is possible to later re-enable the internal regulator"
                f"{'to 3.3V' if sdio_tieh.get() != 0 else 'to 1.8V or 3.3V'}"
                "by burning an additional eFuse"
            )
        elif voltage == "1.8V":
            log.print(
                "Set internal flash voltage regulator (VDD_SPI) to 1.8V.\n"
                "The following eFuses are burned: VDD_SPI_FORCE, VDD_SPI_XPD.\n"
                "It is possible to later increase the voltage to 3.3V (permanently) "
                "by burning additional eFuse VDD_SPI_TIEH"
            )
        elif voltage == "3.3V":
            log.print(
                "Enable internal flash voltage regulator (VDD_SPI) to 3.3V.\n"
                "The following eFuses are burned: VDD_SPI_FORCE, VDD_SPI_XPD, VDD_SPI_TIEH."
            )

        sdio_force.save(1)  # Disable GPIO45
        if voltage != "OFF":
            sdio_reg.save(1)  # Enable internal regulator
        if voltage == "3.3V":
            sdio_tieh.save(1)
        log.print("VDD_SPI setting complete.")

        if not self.efuses.burn_all(check_batch_mode=True):
            return
        log.print("Successful.")

    def adc_info(self):
        log.print("")
        log.print("Block version:", self.efuses.get_block_version())
        if self.efuses.get_block_version() >= 100:
            # fmt: off
            log.print(f"Temperature Sensor Calibration = {self.efuses['TEMP_CALIB'].get()}C")
            log.print("ADC OCode        = ", self.efuses["OCODE"].get())
            log.print("ADC1:")
            log.print("INIT_CODE_ATTEN0 = ", self.efuses["ADC1_INIT_CODE_ATTEN0"].get())
            log.print("INIT_CODE_ATTEN1 = ", self.efuses["ADC1_INIT_CODE_ATTEN1"].get())
            log.print("INIT_CODE_ATTEN2 = ", self.efuses["ADC1_INIT_CODE_ATTEN2"].get())
            log.print("INIT_CODE_ATTEN3 = ", self.efuses["ADC1_INIT_CODE_ATTEN3"].get())
            log.print("CAL_VOL_ATTEN0   = ", self.efuses["ADC1_CAL_VOL_ATTEN0"].get())
            log.print("CAL_VOL_ATTEN1   = ", self.efuses["ADC1_CAL_VOL_ATTEN1"].get())
            log.print("CAL_VOL_ATTEN2   = ", self.efuses["ADC1_CAL_VOL_ATTEN2"].get())
            log.print("CAL_VOL_ATTEN3   = ", self.efuses["ADC1_CAL_VOL_ATTEN3"].get())
            log.print("ADC2:")
            log.print("INIT_CODE_ATTEN0 = ", self.efuses["ADC2_INIT_CODE_ATTEN0"].get())
            log.print("INIT_CODE_ATTEN1 = ", self.efuses["ADC2_INIT_CODE_ATTEN1"].get())
            log.print("INIT_CODE_ATTEN2 = ", self.efuses["ADC2_INIT_CODE_ATTEN2"].get())
            log.print("INIT_CODE_ATTEN3 = ", self.efuses["ADC2_INIT_CODE_ATTEN3"].get())
            log.print("CAL_VOL_ATTEN0   = ", self.efuses["ADC2_CAL_VOL_ATTEN0"].get())
            log.print("CAL_VOL_ATTEN1   = ", self.efuses["ADC2_CAL_VOL_ATTEN1"].get())
            log.print("CAL_VOL_ATTEN2   = ", self.efuses["ADC2_CAL_VOL_ATTEN2"].get())
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
            for blk in self.efuses.blocks:
                if block_name == blk.name or block_name in blk.alias:
                    efuse = self.efuses[blk.name]
            if efuse is None:
                raise esptool.FatalError(f"Unknown block name - {block_name}.")
            num_bytes = efuse.bit_len // 8

            block_num = self.efuses.get_index_block_by_name(block_name)
            block = self.efuses.blocks[block_num]

            if isinstance(datafile, io.IOBase):
                data = datafile.read()
                datafile.close()
            else:
                data = datafile  # type: ignore  # this is safe but mypy still complains

            log.print(f" - {efuse.name}", end=" ")
            revers_msg = None
            if self.efuses[block.key_purpose_name].need_reverse(keypurpose):
                revers_msg = "\tReversing byte order for AES-XTS hardware peripheral..."
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
                    f"Incorrect key file size {len(data)}. Key file must be {num_bytes} "
                    f"bytes ({num_bytes * 8} bits) of raw binary key data."
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
            for blk in self.efuses.blocks:
                if block_name == blk.name or block_name in blk.alias:
                    efuse = self.efuses[blk.name]
            if efuse is None:
                raise esptool.FatalError(f"Unknown block name - {block_name}.")
            num_bytes = efuse.bit_len // 8
            digest = espsecure._digest_sbv2_public_key(datafile)
            if len(digest) != num_bytes:
                raise esptool.FatalError(
                    "Incorrect digest size {}. Digest must be {} bytes ({} bits) "
                    "of raw binary key data.".format(
                        len(digest), num_bytes, num_bytes * 8
                    )
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
