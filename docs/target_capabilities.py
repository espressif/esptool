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
)


def get_doc_tags(chip_class: type[ESPLoader]) -> list[str]:
    """Return Sphinx tags enabled for the given ROM loader class."""
    return [tag for tag in DOC_CAPABILITY_TAGS if getattr(chip_class, tag, False)]


def _flash_freq_mhz(freq_key: str) -> str:
    """Strip the trailing `m` from a `FLASH_FREQUENCY` key (e.g. `40m` -> `40`)."""
    return freq_key[:-1] if freq_key.endswith("m") else freq_key


def get_doc_substitutions(chip_class: type[ESPLoader]) -> dict[str, str]:
    """Return ``{IDF_TARGET_*}`` substitution values derived from a ROM class."""
    subs = {
        "BOOTLOADER_OFFSET": f"0x{chip_class.BOOTLOADER_FLASH_OFFSET:x}",
    }

    flash_frequency = getattr(chip_class, "FLASH_FREQUENCY", None)
    if not flash_frequency:
        return subs

    # ESP32-C6 maps both 80 MHz and 40 MHz to encoding 0 as a ROM workaround.
    # Keep the highest frequency in the conventional final (0xF) display position.
    highest_freq = max(flash_frequency, key=lambda f: int(_flash_freq_mhz(f)))
    ordered = sorted(
        flash_frequency,
        key=lambda freq: 0xF if freq == highest_freq else flash_frequency[freq],
    )
    subs["FLASH_FREQ"] = ", ".join(f"``{freq}``" for freq in ordered)

    # Always define 0/1/2/F: Sphinx resolves substitutions even inside excluded
    # ``only::`` blocks (e.g. FLASH_FREQ_1 on chips without encoding 0x1).
    # If multiple frequencies share an encoding, keep the last one.
    by_enc: dict[int, str] = {}
    for freq, enc in flash_frequency.items():
        if enc in (0x0, 0x1, 0x2, 0xF):
            by_enc[enc] = _flash_freq_mhz(freq)

    for enc, name in (
        (0x0, "FLASH_FREQ_0"),
        (0x1, "FLASH_FREQ_1"),
        (0x2, "FLASH_FREQ_2"),
    ):
        subs[name] = by_enc.get(enc, "")

    # Prefer encoding 0xF; otherwise use the highest listed frequency (e.g. ESP32-C6).
    subs["FLASH_FREQ_F"] = by_enc.get(0xF, _flash_freq_mhz(highest_freq))

    return subs
