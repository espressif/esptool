# This file includes the operations with eFuses for ESP32S2 chip
#
# SPDX-FileCopyrightText: 2020-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import io

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


class ESP32S2Commands(BaseCommands):
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

    def set_flash_voltage(self, voltage):
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
            print(
                "Disable internal flash voltage regulator (VDD_SPI). "
                "SPI flash will need to be powered from an external source.\n"
                "The following eFuse is burned: VDD_SPI_FORCE.\n"
                "It is possible to later re-enable the internal regulator"
                f"{'to 3.3V' if sdio_tieh.get() != 0 else 'to 1.8V or 3.3V'}"
                "by burning an additional eFuse"
            )
        elif voltage == "1.8V":
            print(
                "Set internal flash voltage regulator (VDD_SPI) to 1.8V.\n"
                "The following eFuses are burned: VDD_SPI_FORCE, VDD_SPI_XPD.\n"
                "It is possible to later increase the voltage to 3.3V (permanently) "
                "by burning additional eFuse VDD_SPI_TIEH"
            )
        elif voltage == "3.3V":
            print(
                "Enable internal flash voltage regulator (VDD_SPI) to 3.3V.\n"
                "The following eFuses are burned: VDD_SPI_FORCE, VDD_SPI_XPD, VDD_SPI_TIEH."
            )

        sdio_force.save(1)  # Disable GPIO45
        if voltage != "OFF":
            sdio_reg.save(1)  # Enable internal regulator
        if voltage == "3.3V":
            sdio_tieh.save(1)
        print("VDD_SPI setting complete.")

        if not self.efuses.burn_all(check_batch_mode=True):
            return
        print("Successful")

    def adc_info(self):
        # fmt: off
        print("Block version:", self.efuses.get_block_version())
        if self.efuses.get_block_version() >= 1:
            print("Temperature Sensor Calibration = {}C".format(self.efuses["TEMP_CALIB"].get()))
            print("TADC_CALIB          = {}C".format(self.efuses["ADC_CALIB"].get()))
            print("RTCCALIB_V1IDX_A10H = ", self.efuses["RTCCALIB_V1IDX_A10H"].get())
            print("RTCCALIB_V1IDX_A11H = ", self.efuses["RTCCALIB_V1IDX_A11H"].get())
            print("RTCCALIB_V1IDX_A12H = ", self.efuses["RTCCALIB_V1IDX_A12H"].get())
            print("RTCCALIB_V1IDX_A13H = ", self.efuses["RTCCALIB_V1IDX_A13H"].get())
            print("RTCCALIB_V1IDX_A20H = ", self.efuses["RTCCALIB_V1IDX_A20H"].get())
            print("RTCCALIB_V1IDX_A21H = ", self.efuses["RTCCALIB_V1IDX_A21H"].get())
            print("RTCCALIB_V1IDX_A22H = ", self.efuses["RTCCALIB_V1IDX_A22H"].get())
            print("RTCCALIB_V1IDX_A23H = ", self.efuses["RTCCALIB_V1IDX_A23H"].get())
            print("RTCCALIB_V1IDX_A10L = ", self.efuses["RTCCALIB_V1IDX_A10L"].get())
            print("RTCCALIB_V1IDX_A11L = ", self.efuses["RTCCALIB_V1IDX_A11L"].get())
            print("RTCCALIB_V1IDX_A12L = ", self.efuses["RTCCALIB_V1IDX_A12L"].get())
            print("RTCCALIB_V1IDX_A13L = ", self.efuses["RTCCALIB_V1IDX_A13L"].get())
            print("RTCCALIB_V1IDX_A20L = ", self.efuses["RTCCALIB_V1IDX_A20L"].get())
            print("RTCCALIB_V1IDX_A21L = ", self.efuses["RTCCALIB_V1IDX_A21L"].get())
            print("RTCCALIB_V1IDX_A22L = ", self.efuses["RTCCALIB_V1IDX_A22L"].get())
            print("RTCCALIB_V1IDX_A23L = ", self.efuses["RTCCALIB_V1IDX_A23L"].get())
        # fmt: on

    def _key_block_is_unused(self, block, key_purpose_block):
        """Helper method to check if a key block is available for use"""
        if not block.is_readable() or not block.is_writeable():
            return False

        if key_purpose_block.get() != "USER" or not key_purpose_block.is_writeable():
            return False

        if not block.get_bitstring().all(False):
            return False

        return True

    def _get_next_key_block(self, current_key_block, block_name_list):
        """Helper method to get the next available key block"""
        key_blocks = [b for b in self.efuses.blocks if b.key_purpose_name]
        start = key_blocks.index(current_key_block)

        # Sort key blocks so that we pick the next free block (and loop around if necessary)
        key_blocks = key_blocks[start:] + key_blocks[0:start]

        # Exclude any other blocks that will be be burned
        key_blocks = [b for b in key_blocks if b.name not in block_name_list]

        for block in key_blocks:
            key_purpose_block = self.efuses[block.key_purpose_name]
            if self._key_block_is_unused(block, key_purpose_block):
                return block

        return None

    def _split_512_bit_key(self, block_name_list, datafile_list, keypurpose_list):
        """Helper method to split 512-bit key into two 256-bit keys"""
        datafile_list = list(datafile_list)
        block_name_list = list(block_name_list)
        keypurpose_list = list(keypurpose_list)

        i = keypurpose_list.index("XTS_AES_256_KEY")
        block_name = block_name_list[i]

        block_num = self.efuses.get_index_block_by_name(block_name)
        block = self.efuses.blocks[block_num]

        data = datafile_list[i].read()
        if len(data) != 64:
            raise esptool.FatalError(
                "Incorrect key file size %d, XTS_AES_256_KEY should be 64 bytes"
                % len(data)
            )

        key_block_2 = self._get_next_key_block(block, block_name_list)
        if not key_block_2:
            raise esptool.FatalError("XTS_AES_256_KEY requires two free keyblocks")

        keypurpose_list.append("XTS_AES_256_KEY_1")
        datafile_list.append(io.BytesIO(data[:32]))
        block_name_list.append(block_name)

        keypurpose_list.append("XTS_AES_256_KEY_2")
        datafile_list.append(io.BytesIO(data[32:]))
        block_name_list.append(key_block_2.name)

        keypurpose_list.pop(i)
        datafile_list.pop(i)
        block_name_list.pop(i)
        return tuple(block_name_list), tuple(datafile_list), tuple(keypurpose_list)

    def burn_key(
        self,
        block,
        keyfile,
        keypurpose,
        no_write_protect,
        no_read_protect,
        show_sensitive_info,
        digest=None,
    ):
        if digest is None:
            datafile_list = keyfile[
                0 : len([name for name in keyfile if name is not None]) :
            ]
        else:
            datafile_list = digest[
                0 : len([name for name in digest if name is not None]) :
            ]
        block_name_list = block[0 : len([name for name in block if name is not None]) :]
        keypurpose_list = keypurpose[
            0 : len([name for name in keypurpose if name is not None]) :
        ]

        if "XTS_AES_256_KEY" in keypurpose_list:
            # XTS_AES_256_KEY is not an actual HW key purpose, needs to be split into
            # XTS_AES_256_KEY_1 and XTS_AES_256_KEY_2
            block_name_list, datafile_list, keypurpose_list = self._split_512_bit_key(
                block_name_list, datafile_list, keypurpose_list
            )

        util.check_duplicate_name_in_list(block_name_list)
        if len(block_name_list) != len(datafile_list) or len(block_name_list) != len(
            keypurpose_list
        ):
            raise esptool.FatalError(
                "The number of blocks (%d), datafile (%d) and keypurpose (%d) should be the same."
                % (len(block_name_list), len(datafile_list), len(keypurpose_list))
            )

        print("Burn keys to blocks:")
        for block_name, datafile, keypurpose in zip(
            block_name_list, datafile_list, keypurpose_list
        ):
            efuse = None
            for block in self.efuses.blocks:
                if block_name == block.name or block_name in block.alias:
                    efuse = self.efuses[block.name]
            if efuse is None:
                raise esptool.FatalError("Unknown block name - %s" % (block_name))
            num_bytes = efuse.bit_len // 8

            block_num = self.efuses.get_index_block_by_name(block_name)
            block = self.efuses.blocks[block_num]

            if digest is None:
                data = datafile.read()
                datafile.close()
            else:
                data = datafile

            print(" - %s" % (efuse.name), end=" ")
            revers_msg = None
            if self.efuses[block.key_purpose_name].need_reverse(keypurpose):
                revers_msg = "\tReversing byte order for AES-XTS hardware peripheral"
                data = data[::-1]
            print(
                "-> [{}]".format(
                    util.hexify(data, " ")
                    if show_sensitive_info
                    else " ".join(["??"] * len(data))
                )
            )
            if revers_msg:
                print(revers_msg)
            if len(data) != num_bytes:
                raise esptool.FatalError(
                    "Incorrect key file size %d. Key file must be %d bytes (%d bits) "
                    "of raw binary key data." % (len(data), num_bytes, num_bytes * 8)
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
                    print(
                        "\t'%s': '%s' -> '%s'."
                        % (
                            block.key_purpose_name,
                            self.efuses[block.key_purpose_name].get(),
                            keypurpose,
                        )
                    )
                    self.efuses[block.key_purpose_name].save(keypurpose)
                    disable_wr_protect_key_purpose = True
                else:
                    raise esptool.FatalError(
                        "It is not possible to change '%s' to '%s' "
                        "because write protection bit is set."
                        % (block.key_purpose_name, keypurpose)
                    )
            else:
                print("\t'%s' is already '%s'." % (block.key_purpose_name, keypurpose))
                if self.efuses[block.key_purpose_name].is_writeable():
                    disable_wr_protect_key_purpose = True

            if disable_wr_protect_key_purpose:
                print("\tDisabling write to '%s'." % block.key_purpose_name)
                self.efuses[block.key_purpose_name].disable_write()

            if read_protect:
                print("\tDisabling read to key block")
                efuse.disable_read()

            if write_protect:
                print("\tDisabling write to key block")
                efuse.disable_write()
            print("")

        if not write_protect:
            print("Keys will remain writeable (due to --no-write-protect)")
        if no_read_protect:
            print("Keys will remain readable (due to --no-read-protect)")

        if not self.efuses.burn_all(check_batch_mode=True):
            return
        print("Successful")

    def burn_key_digest(
        self,
        block,
        keyfile,
        keypurpose,
        no_write_protect,
        no_read_protect,
        show_sensitive_info,
    ):
        digest_list = []
        datafile_list = keyfile[
            0 : len([name for name in keyfile if name is not None]) :
        ]
        block_list = block[0 : len([block for block in block if block is not None]) :]

        for block_name, datafile in zip(block_list, datafile_list):
            efuse = None
            for block in self.efuses.blocks:
                if block_name == block.name or block_name in block.alias:
                    efuse = self.efuses[block.name]
            if efuse is None:
                raise esptool.FatalError("Unknown block name - %s" % (block_name))
            num_bytes = efuse.bit_len // 8
            digest = espsecure._digest_sbv2_public_key(datafile)
            if len(digest) != num_bytes:
                raise esptool.FatalError(
                    "Incorrect digest size %d. Digest must be %d bytes (%d bits) "
                    "of raw binary key data." % (len(digest), num_bytes, num_bytes * 8)
                )
            digest_list.append(digest)

        self.burn_key(
            block_list,
            datafile_list,
            keypurpose,
            no_write_protect,
            no_read_protect,
            show_sensitive_info,
            digest=digest_list,
        )
