# This file includes the operations with eFuses for ESP32-C2 chip
#
# SPDX-FileCopyrightText: 2021-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

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


class ESP32C2Commands(BaseCommands):
    ################################### CLI definitions ###################################

    def add_cli_commands(self, cli: click.Group):
        super().add_cli_commands(cli)
        blocks_for_keys = EfuseDefineBlocks().get_blocks_for_keys()

        @cli.command(
            "burn-key",
            help="Burn the key block with the specified name. Arguments are groups of block name, "
            "key file (containing 128/256 bits of binary key data) and key purpose.\n\n"
            f"Block is one of: [{', '.join(blocks_for_keys)}]\n\n"
            f"Key purpose is one of: [{', '.join(fields.EfuseKeyPurposeField.KEY_PURPOSES_NAME)}]",
        )
        @click.argument(
            "block_keyfile_keypurpose",
            metavar="<BLOCK> <KEYFILE> <KEYPURPOSE>",
            cls=TupleParameter,
            nargs=-1,
            # we need to add +1 here as this chip has only one key block. SB and FE
            # keys will share this key block if both of them have to be written.
            max_arity=len(blocks_for_keys) + 1,
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
            block, keyfile, keypurpose = zip(*kwargs.pop("block_keyfile_keypurpose"))
            kwargs.pop("force_write_always")
            kwargs["show_sensitive_info"] = ctx.show_sensitive_info
            self.burn_key(block, keyfile, keypurpose, **kwargs)

        @cli.command(
            "burn-key-digest",
            short_help="Parse an ECDSA public key and burn the digest.",
            help="Parse an ECDSA public key and burn the digest to higher 128-bits of BLOCK_KEY0. "
            "KEYFILE is in PEM format.",
        )
        @click.argument("keyfile", type=click.File("rb"))
        @protect_options
        @add_force_write_always
        @add_show_sensitive_info_option
        @click.pass_context
        def burn_key_digest_cli(ctx, **kwargs):
            kwargs.pop("force_write_always")
            kwargs["show_sensitive_info"] = ctx.show_sensitive_info
            self.burn_key_digest(**kwargs)

    ###################################### Commands ######################################

    def burn_custom_mac(self, mac):
        self.efuses["CUSTOM_MAC"].save(mac)
        self.efuses["CUSTOM_MAC_USED"].save(1)
        if not self.efuses.burn_all(check_batch_mode=True):
            return
        self.get_custom_mac()
        print("Successful")

    def adc_info(self):
        print("Block version:", self.efuses.get_block_version())
        if self.efuses.get_block_version() >= 1:
            print(
                "Temperature Sensor Calibration = {}C".format(
                    self.efuses["TEMP_CALIB"].get()
                )
            )
            print("ADC OCode        = ", self.efuses["OCODE"].get())
            print("ADC1:")
            print("INIT_CODE_ATTEN0 = ", self.efuses["ADC1_INIT_CODE_ATTEN0"].get())
            print("INIT_CODE_ATTEN3 = ", self.efuses["ADC1_INIT_CODE_ATTEN3"].get())
            print("CAL_VOL_ATTEN0   = ", self.efuses["ADC1_CAL_VOL_ATTEN0"].get())
            print("CAL_VOL_ATTEN3   = ", self.efuses["ADC1_CAL_VOL_ATTEN3"].get())

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
                0 : len([keyfile for keyfile in keyfile if keyfile is not None]) :
            ]
        else:
            datafile_list = digest[
                0 : len([name for name in digest if name is not None]) :
            ]
        block_name_list = block[0 : len([name for name in block if name is not None]) :]
        keypurpose_list = keypurpose[
            0 : len([name for name in keypurpose if name is not None]) :
        ]

        util.check_duplicate_name_in_list(keypurpose_list)
        if len(block_name_list) != len(datafile_list) or len(block_name_list) != len(
            keypurpose_list
        ):
            raise esptool.FatalError(
                "The number of blocks (%d), datafile (%d) and "
                "keypurpose (%d) should be the same."
                % (len(block_name_list), len(datafile_list), len(keypurpose_list))
            )

        assert 1 <= len(block_name_list) <= 2, "Unexpected case"

        if len(block_name_list) == 2:
            incompatible = True if "XTS_AES_128_KEY" in keypurpose_list else False
            permitted_purposes = [
                "XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS",
                "SECURE_BOOT_DIGEST",
            ]
            incompatible |= (
                keypurpose_list[0] in permitted_purposes
                and keypurpose_list[1] not in permitted_purposes
            )
            if incompatible:
                raise esptool.FatalError(
                    f"These keypurposes are incompatible {list(keypurpose_list)}"
                )

        print("Burn keys to blocks:")
        for datafile, keypurpose in zip(datafile_list, keypurpose_list):
            if isinstance(datafile, bytes):
                data = datafile
            else:
                data = datafile.read()
                datafile.close()

            if keypurpose == "XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS":
                efuse = self.efuses["BLOCK_KEY0_LOW_128"]
            elif keypurpose == "SECURE_BOOT_DIGEST":
                efuse = self.efuses["BLOCK_KEY0_HI_128"]
                if len(data) == 32:
                    print(
                        "\tProgramming only left-most 128-bits from SHA256 hash of "
                        "public key to highest 128-bits of BLOCK KEY0"
                    )
                    data = data[:16]
                elif len(data) != efuse.bit_len // 8:
                    raise esptool.FatalError(
                        "Wrong length of this file for SECURE_BOOT_DIGEST. "
                        "Got %d (expected %d or %d)"
                        % (len(data), 32, efuse.bit_len // 8)
                    )
                assert len(data) == 16, "Only 16 bytes expected"
            else:
                efuse = self.efuses["BLOCK_KEY0"]

            num_bytes = efuse.bit_len // 8

            print(" - %s" % (efuse.name), end=" ")
            revers_msg = None
            if keypurpose.startswith("XTS_AES_"):
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
                    "Incorrect key file size %d. "
                    "Key file must be %d bytes (%d bits) of raw binary key data."
                    % (len(data), num_bytes, num_bytes * 8)
                )

            if keypurpose.startswith("XTS_AES_"):
                read_protect = not no_read_protect
            else:
                read_protect = False
            write_protect = not no_write_protect

            # using eFuse instead of a block gives the advantage
            # of checking it as the whole field.
            efuse.save(data)

            if keypurpose == "XTS_AES_128_KEY":
                if self.efuses["XTS_KEY_LENGTH_256"].get():
                    print("\t'XTS_KEY_LENGTH_256' is already '1'")
                else:
                    print("\tXTS_KEY_LENGTH_256 -> 1")
                    self.efuses["XTS_KEY_LENGTH_256"].save(1)

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
        self, keyfile, no_write_protect, no_read_protect, show_sensitive_info
    ):
        digest = espsecure._digest_sbv2_public_key(keyfile)
        digest = digest[:16]
        num_bytes = self.efuses["BLOCK_KEY0_HI_128"].bit_len // 8
        if len(digest) != num_bytes:
            raise esptool.FatalError(
                "Incorrect digest size %d. "
                "Digest must be %d bytes (%d bits) of raw binary key data."
                % (len(digest), num_bytes, num_bytes * 8)
            )
        self.burn_key(
            ["BLOCK_KEY0"],
            keyfile,
            ["SECURE_BOOT_DIGEST"],
            no_write_protect,
            no_read_protect,
            show_sensitive_info,
            digest=[digest],
        )
