# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Derive Sphinx tags and substitutions from esptool ROM loader classes."""

from esptool.loader import ESPLoader

DOC_CAPABILITY_TAGS = (
    "USB_OTG_SUPPORTED",
    "USB_SERIAL_JTAG_SUPPORTED",
    "WATCHDOG_RESET_SUPPORTED",
    "SECURITY_INFO_SUPPORTED",
    "CUSTOM_SPI_FLASH_PINS_SUPPORTED",
    "FLASH_32BIT_ADDR_SUPPORTED",
)


def get_doc_tags(chip_class: type[ESPLoader]) -> list[str]:
    """Return Sphinx tags enabled for the given ROM loader class."""
    return [tag for tag in DOC_CAPABILITY_TAGS if getattr(chip_class, tag, False)]


def get_doc_substitutions(chip_class: type[ESPLoader]) -> dict[str, str]:
    """Return ``{IDF_TARGET_*}`` substitution values derived from a ROM class."""
    subs = {
        "BOOTLOADER_OFFSET": f"0x{chip_class.BOOTLOADER_FLASH_OFFSET:x}",
    }

    flash_frequency = getattr(chip_class, "FLASH_FREQUENCY", None)
    if not flash_frequency:
        return subs

    mhz = {freq: int(freq.rstrip("m")) for freq in flash_frequency}
    subs["FLASH_FREQ"] = ", ".join(f"``{freq}``" for freq in flash_frequency)
    subs["FLASH_FREQ_F"] = str(max(mhz.values()))
    # ESP32-C6 maps both 80m and 40m to encoding 0; the lower one is the default.
    subs["FLASH_FREQ_0"] = str(
        min(mhz[freq] for freq, enc in flash_frequency.items() if enc == 0x0)
    )

    by_enc: dict[int, list[str]] = {}
    for freq, enc in flash_frequency.items():
        by_enc.setdefault(enc, []).append(f"{mhz[freq]}MHz")
    encodings = []
    for enc, values in sorted(by_enc.items()):
        enc_str = str(enc) if enc < 10 else hex(enc)
        encodings.append(f"``{enc_str}`` = {' or '.join(values)}")
    subs["FLASH_FREQ_ENCODING"] = ", ".join(encodings)

    return subs
