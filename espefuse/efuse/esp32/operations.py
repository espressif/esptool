# This file includes the operations with eFuses for ESP32 chip
#
# SPDX-FileCopyrightText: 2020-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import BinaryIO
import rich_click as click

import espsecure

import esptool
from esptool.logger import log

from .mem_definition import EfuseDefineBlocks
from .. import util
from .fields import EspEfuses
from ..base_operations import (
    BaseCommands,
    NonCompositeTuple,
    TupleParameter,
    add_force_write_always,
    add_show_sensitive_info_option,
)


class ESP32Commands(BaseCommands):
    CHIP_NAME = "ESP32"
    efuse_lib = EspEfuses

    ################################### CLI definitions ###################################

    def add_cli_commands(self, cli: click.Group):
        super().add_cli_commands(cli)
        blocks_for_keys = EfuseDefineBlocks().get_blocks_for_keys()

        @cli.command(
            "burn-key",
            help="Burn a 256-bit key to EFUSE. Arguments are pairs of block name and "
            "key file, containing 256 bits of binary key data.\n\n"
            f"Block is one of: [{', '.join(blocks_for_keys)}]",
        )
        @click.argument(
            "block_keyfile",
            metavar="<BLOCK> <KEYFILE>",
            cls=TupleParameter,
            required=True,
            nargs=-1,
            max_arity=len(blocks_for_keys),
            type=NonCompositeTuple([click.Choice(blocks_for_keys), click.File("rb")]),
        )
        @click.option(
            "--no-protect-key",
            is_flag=True,
            help="Disable the default read- and write-protection of the key. "
            "If this option is not set, once the key is flashed "
            "it cannot be read back or changed.",
        )
        @add_force_write_always
        @add_show_sensitive_info_option
        @click.pass_context
        def burn_key_cli(
            ctx, block_keyfile, no_protect_key, show_sensitive_info, **kwargs
        ):
            block, keyfile = zip(*block_keyfile)
            show_sensitive_info = ctx.show_sensitive_info
            self.burn_key(block, keyfile, no_protect_key, show_sensitive_info)

        @cli.command(
            "burn-key-digest",
            short_help="Parse a RSA public key and burn the digest.",
            help="Parse a RSA public key and burn the digest to eFuse for use with Secure Boot V2.",
        )
        @click.argument("keyfile", type=click.File("rb"))
        @click.option(
            "--no-protect-key",
            is_flag=True,
            help="Disable the default write-protection of the key digest. "
            "If this option is not set, once the key is flashed it cannot be changed.",
        )
        @add_force_write_always
        @add_show_sensitive_info_option
        @click.pass_context
        def burn_key_digest_cli(
            ctx, keyfile, no_protect_key, show_sensitive_info, **kwargs
        ):
            kwargs["show_sensitive_info"] = ctx.show_sensitive_info
            self.burn_key_digest(keyfile, no_protect_key, show_sensitive_info)

        @cli.command(
            "set-flash-voltage",
            short_help="Permanently set the internal flash voltage regulator.",
        )
        @click.argument("voltage", type=click.Choice(["1.8V", "3.3V", "OFF"]))
        def set_flash_voltage_cli(voltage):
            """Permanently set the internal flash voltage regulator to either 1.8V, 3.3V or OFF.
            This means GPIO12 can be high or low at reset without changing the flash voltage."""
            self.set_flash_voltage(voltage)

    ###################################### Commands ######################################

    def get_custom_mac(self):
        version = self.efuses["MAC_VERSION"].get()
        if version > 0:
            log.print(
                f"Custom MAC Address version {version}: {self.efuses['CUSTOM_MAC'].get()}"
            )
        else:
            log.print("Custom MAC Address is not set in the device.")

    def set_flash_voltage(self, voltage: str):
        sdio_force = self.efuses["XPD_SDIO_FORCE"]
        sdio_tieh = self.efuses["XPD_SDIO_TIEH"]
        sdio_reg = self.efuses["XPD_SDIO_REG"]

        # check efuses aren't burned in a way which makes this impossible
        if voltage == "OFF" and sdio_reg.get() != 0:
            raise esptool.FatalError(
                "Can't set flash regulator to OFF as XPD_SDIO_REG eFuse is already burned."
            )

        if voltage == "1.8V" and sdio_tieh.get() != 0:
            raise esptool.FatalError(
                "Can't set regulator to 1.8V is XPD_SDIO_TIEH eFuse is already burned."
            )

        if voltage == "OFF":
            log.print(
                "Disable internal flash voltage regulator (VDD_SDIO). "
                "SPI flash will need to be powered from an external source.\n"
                "The following eFuse is burned: XPD_SDIO_FORCE.\n"
                "It is possible to later re-enable the internal regulator"
                f"{'to 3.3V' if sdio_tieh.get() != 0 else 'to 1.8V or 3.3V'}"
                "by burning an additional eFuse."
            )
        elif voltage == "1.8V":
            log.print(
                "Set internal flash voltage regulator (VDD_SDIO) to 1.8V.\n"
                "The following eFuses are burned: XPD_SDIO_FORCE, XPD_SDIO_REG.\n"
                "It is possible to later increase the voltage to 3.3V (permanently) "
                "by burning additional eFuse XPD_SDIO_TIEH."
            )
        elif voltage == "3.3V":
            log.print(
                "Enable internal flash voltage regulator (VDD_SDIO) to 3.3V.\n"
                "The following eFuses are burned: XPD_SDIO_FORCE, XPD_SDIO_REG, XPD_SDIO_TIEH."
            )

        sdio_force.save(1)  # Disable GPIO12
        if voltage != "OFF":
            sdio_reg.save(1)  # Enable internal regulator
        if voltage == "3.3V":
            sdio_tieh.save(1)
        log.print("VDD_SDIO setting complete.")
        if not self.efuses.burn_all(check_batch_mode=True):
            return
        log.print("Successful.")

    def adc_info(self):
        adc_vref = self.efuses["ADC_VREF"]
        blk3_reserve = self.efuses["BLK3_PART_RESERVE"]

        vref_raw = adc_vref.get_raw()
        if vref_raw == 0:
            log.print("ADC VRef calibration: None (1100mV nominal)")
        else:
            log.print(f"ADC VRef calibration: {adc_vref.get()}mV")

        if blk3_reserve.get():
            log.print("ADC readings stored in eFuse BLOCK3:")
            log.print(
                f"    ADC1 Low reading  (150mV): {self.efuses['ADC1_TP_LOW'].get()}"
            )
            log.print(
                f"    ADC1 High reading (850mV): {self.efuses['ADC1_TP_HIGH'].get()}"
            )
            log.print(
                f"    ADC2 Low reading  (150mV): {self.efuses['ADC2_TP_LOW'].get()}"
            )
            log.print(
                f"    ADC2 High reading (850mV): {self.efuses['ADC2_TP_HIGH'].get()}"
            )

    def burn_key(
        self,
        block: list[str],
        keyfile: list[BinaryIO],
        no_protect_key: bool = False,
        show_sensitive_info: bool = False,
    ):
        """Burn a 256-bit key to EFUSE. Arguments are pairs of block name and
        key file, containing 256 bits of binary key data.

        Args:
            block: List of eFuse block names to burn keys to.
            keyfile: List of open files to read key data from.
            no_protect_key: If True, the write protection will NOT be enabled.
            show_sensitive_info: If True, the sensitive information will be shown.
        """
        datafile_list = keyfile[
            0 : len([keyfile for keyfile in keyfile if keyfile is not None]) :
        ]
        block_name_list = block[
            0 : len([block for block in block if block is not None]) :
        ]

        util.check_duplicate_name_in_list(block_name_list)
        if len(block_name_list) != len(datafile_list):
            raise esptool.FatalError(
                f"The number of blocks ({len(block_name_list)}) "
                f"and datafile ({len(datafile_list)}) should be the same."
            )

        log.print("Burn keys to blocks:")
        for block_name, datafile in zip(block_name_list, datafile_list):
            efuse = None
            for blk in self.efuses.blocks:
                if block_name == blk.name or block_name in blk.alias:
                    efuse = self.efuses[blk.name]
            if efuse is None:
                raise esptool.FatalError(f"Unknown block name - {block_name}.")
            num_bytes = efuse.bit_len // 8
            data = datafile.read()
            datafile.close()
            revers_msg = None
            if block_name in ("flash_encryption", "secure_boot_v1"):
                revers_msg = "\tReversing the byte order..."
                data = data[::-1]
            log.print(f" - {efuse.name}", end=" ")
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
                    f"Incorrect key file size {len(data)}. Key file must be {num_bytes}"
                    f" bytes ({num_bytes * 8} bits) of raw binary key data."
                )

            efuse.save(data)

            if block_name in ("flash_encryption", "secure_boot_v1"):
                if not no_protect_key:
                    log.print("\tDisabling read to key block...")
                    efuse.disable_read()

            if not no_protect_key:
                log.print("\tDisabling write to key block...")
                efuse.disable_write()
            log.print("")

        if no_protect_key:
            log.print("Key is left unprotected as per --no-protect-key argument.")

        msg = "Burn keys in eFuse blocks.\n"
        if no_protect_key:
            msg += (
                "The key block will be left readable and writeable "
                "(due to --no-protect-key)."
            )
        else:
            msg += (
                "The key block will be read and write protected "
                "(no further changes or readback)."
            )
        log.print(msg, "\n")
        if not self.efuses.burn_all(check_batch_mode=True):
            return
        log.print("Successful.")

    def burn_key_digest(
        self,
        keyfile: BinaryIO,
        no_protect_key: bool = False,
        show_sensitive_info: bool = False,
    ):
        """Parse a RSA public key and burn the digest to eFuse for use with Secure Boot V2.

        Args:
            keyfile: Open file to read key data from.
            no_protect_key: If True, the write protection will NOT be enabled.
            show_sensitive_info: If True, the sensitive information will be shown.
        """
        if self.efuses.coding_scheme == self.efuses.REGS.CODING_SCHEME_34:
            raise esptool.FatalError(
                "burn-key-digest only works with 'None' coding scheme"
            )

        chip_revision = self.esp.get_chip_revision()
        if chip_revision < 300:
            raise esptool.FatalError(
                "Incorrect chip revision for Secure boot v2. "
                "Detected: v{}.{}. Expected: >= v3.0".format(
                    chip_revision // 100, chip_revision % 100
                )
            )

        digest = espsecure._digest_sbv2_public_key(keyfile)
        efuse = self.efuses["BLOCK2"]
        num_bytes = efuse.bit_len // 8
        if len(digest) != num_bytes:
            raise esptool.FatalError(
                f"Incorrect digest size {len(digest)}. "
                f"Digest must be {num_bytes} bytes "
                f"({num_bytes * 8} bits) of raw binary key data."
            )
        log.print(f" - {efuse.name}", end=" ")
        log.print(
            "-> [{}]".format(
                util.hexify(digest, " ")
                if show_sensitive_info
                else " ".join(["??"] * len(digest))
            )
        )

        efuse.save(digest)
        if not no_protect_key:
            log.print(f"Disabling write to eFuse {efuse.name}...")
            efuse.disable_write()

        if not self.efuses.burn_all(check_batch_mode=True):
            return
        log.print("Successful.")
