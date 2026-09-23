#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later
#
r"""Assemble the RAM "hello world" firmware images for the esptool test suite.

test_esptool.py (load-ram, write-flash --encrypt), test_merge_bin.py and
test_image_info.py load these. This script is the only definition of the images;
nothing in the repository compiles them.

Every image holds two segments: a 16-byte .rodata string and a .text stub that
calls the ROM ets_printf in a loop. The stub is the machine code GCC emitted with
-Os for the C function below, plus -mlongcalls -mtext-section-literals on
Xtensa, which put the literal pool in front of the code and call ets_printf
through l32r/callx. ram_main() is the image's entry point. The C function is
quoted only to document what the machine code does:

    void ets_printf(const char *s);  // simplified prototype

    void __attribute__((noreturn)) ram_main()
    {
      while (1) {
        ets_printf("Hello world!\n");
      }
    }

The .text comes from one of three instruction templates, one per distinct
compiler output: the two Xtensa ABIs and RISC-V. CHIPS maps each chip to one of
them and holds the per-chip addresses and image-header chip ID. The container
(header, XOR checksum, appended SHA-256) is written here rather than through
esptool, so the fixtures stay independent of the tool under test.

To add a chip, add a CHIPS entry; images/README.md explains where each value
comes from and how to test the new image.

Called automatically from conftest.py before pytest runs, or manually:

    python test/ram_helloworld_builder.py [--output test/images/ram_helloworld]
"""

import argparse
import hashlib
import struct
from pathlib import Path
from typing import NamedTuple

# .rodata: the string ram_main() passes to ets_printf, NUL-padded to 4 bytes.
HELLO_WORLD = b"Hello world!\n" + b"\x00" * 3

IMAGE_MAGIC = 0xE9
CHECKSUM_INIT = 0xEF
WP_PIN_DISABLED = 0xEE

# .text instruction templates. Xtensa needs no relocation at all: the two
# addresses sit in the literal pool and the l32r offsets are fixed by
# alignment. The RISC-V template places the addresses in the instruction
# stream, so lui/addi and auipc/jalr have to be filled in per chip.
XTENSA_WINDOWED = "xtensa-windowed"  # ESP32, ESP32-S2, ESP32-S3: entry / callx8
XTENSA_LX106 = "xtensa-lx106"  # ESP8266: call0 ABI, no register windows
# One template for every RISC-V chip: it is the code that GCC 15.1 and later
# emit for each of them (checked up to GCC 16.1.0, esp-16.1.0_20260609). GCC 14
# and older kept the string's base address in s0 and emitted 24 bytes of code
# instead of 30. Most of the RISC-V images once committed to the repository came
# from those older versions. The images are no longer committed, so there is no
# fixture left to stay byte-identical to.
RISCV = "riscv"


class ChipParams(NamedTuple):
    """Everything that differs between the per-chip images.

    iram is the load address of .text and dram the load address of the string.
    ets_printf is the ets_printf address from the chip's ROM linker script (the
    ROM jump-table entry on chips that have one). isa selects the .text
    template. chip_id is IMAGE_CHIP_ID from esptool/targets/<chip>.py; ESP8266
    images have no chip ID field.
    """

    iram: int
    dram: int
    ets_printf: int
    isa: str
    chip_id: int


CHIPS = {
    "esp8266": ChipParams(0x40108000, 0x3FFE8000, 0x400024CC, XTENSA_LX106, 0),
    "esp32": ChipParams(0x4008C000, 0x3FFC0000, 0x40007D54, XTENSA_WINDOWED, 0x00),
    "esp32c2": ChipParams(0x403A0000, 0x3FCC0100, 0x40000034, RISCV, 0x0C),
    "esp32c3": ChipParams(0x403B0000, 0x3FCB0100, 0x40000040, RISCV, 0x05),
    "esp32c5": ChipParams(0x40810F5C, 0x4081105C, 0x40000024, RISCV, 0x17),
    "esp32c6": ChipParams(0x40860000, 0x40870000, 0x40000028, RISCV, 0x0D),
    "esp32c61": ChipParams(0x40830000, 0x40830100, 0x40000024, RISCV, 0x14),
    "esp32h2": ChipParams(0x40804000, 0x40848000, 0x40000028, RISCV, 0x10),
    "esp32h4": ChipParams(0x40848000, 0x40849000, 0x40000024, RISCV, 0x1C),
    "esp32p4": ChipParams(0x4FF60000, 0x4FF70000, 0x4FC00024, RISCV, 0x12),
    "esp32s3": ChipParams(0x40380000, 0x3FC90100, 0x400005D0, XTENSA_WINDOWED, 0x09),
    "esp32s31": ChipParams(0x2F020000, 0x2F021000, 0x2F800024, RISCV, 0x20),
}


def _word(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _hi_lo(value: int) -> tuple[int, int]:
    """Split value the way the RISC-V %hi/%lo relocation pair does.

    %lo is a sign-extended 12-bit add, so %hi rounds to the nearest multiple of
    4096 rather than truncating.
    """
    hi = (value + 0x800) >> 12
    return hi & 0xFFFFF, (value - (hi << 12)) & 0xFFF


def _riscv_text(chip: ChipParams) -> bytes:
    """Build the RISC-V .text stub for one chip."""
    str_hi, str_lo = _hi_lo(chip.dram)
    # auipc sits 12 bytes into .text; its offset is pc-relative
    call_hi, call_lo = _hi_lo(chip.ets_printf - (chip.iram + 12))
    return (
        b"\x41\x11"  # addi  sp,sp,-16
        + _word(str_hi << 12 | 10 << 7 | 0x37)  # lui   a0,%hi(str)
        + b"\x06\xc6"  # sw    ra,12(sp)
        + _word(str_lo << 20 | 10 << 15 | 10 << 7 | 0x13)  # addi  a0,a0,%lo(str)
        + _word(call_hi << 12 | 1 << 7 | 0x17)  # auipc ra,%pcrel_hi(printf)
        + _word(call_lo << 20 | 1 << 15 | 1 << 7 | 0x67)  # jalr  ra,%pcrel_lo(ra)
        + _word(str_hi << 12 | 15 << 7 | 0x37)  # lui   a5,%hi(str)
        + _word(str_lo << 20 | 15 << 15 | 10 << 7 | 0x13)  # addi  a0,a5,%lo(str)
        + b"\xc5\xbf"  # j     back to the auipc
        + b"\x00\x00"  # pad to 4 bytes
    )


def _xtensa_text(chip: ChipParams) -> bytes:
    """Build the Xtensa .text stub, literal pool first."""
    literals = struct.pack("<II", chip.dram, chip.ets_printf)
    if chip.isa == XTENSA_LX106:
        body = (
            "12c1f0"  # addi   a1,a1,-16
            "0931"  # s32i.n a0,a1,12
            "21fcff"  # l32r   a2,str
            "01fdff"  # l32r   a0,printf
            "c00000"  # callx0 a0
            "c6fcff"  # j      back to the l32r
            "000000"  # pad to 4 bytes
        )
    elif chip.isa == XTENSA_WINDOWED:
        body = (
            "364100"  # entry  a1,32
            "a1fdff"  # l32r   a10,str
            "81fdff"  # l32r   a8,printf
            "e00800"  # callx8 a8
            "c6fcff"  # j      back to the l32r
            "00"  # pad to 4 bytes
        )
    else:
        raise ValueError(f"Unknown ISA {chip.isa!r}")
    return literals + bytes.fromhex(body)


def build_image(name: str) -> bytes:
    """Assemble one helloworld-<chip>.bin."""
    chip = CHIPS[name]
    xtensa = chip.isa in (XTENSA_WINDOWED, XTENSA_LX106)
    text = _xtensa_text(chip) if xtensa else _riscv_text(chip)
    # On Xtensa the literal pool comes first, so ram_main() starts 8 bytes in.
    entry_point = chip.iram + 8 if xtensa else chip.iram
    segments = [(chip.iram, text), (chip.dram, HELLO_WORLD)]

    if chip.isa == XTENSA_LX106:
        # ESP8266 v1 header: no extended header and no appended hash. The
        # segments stay in .text, string order, as elf2image wrote the original
        # fixture; the other chips sort them by address.
        # 0x20 is the flash size / frequency nibble pair.
        image = struct.pack("<BBBBI", IMAGE_MAGIC, len(segments), 0, 0x20, entry_point)
    else:
        segments.sort(key=lambda segment: segment[0])
        image = struct.pack("<BBBBI", IMAGE_MAGIC, len(segments), 0, 0, entry_point)
        image += struct.pack(
            "<BBBBHBHHIB",
            WP_PIN_DISABLED,
            0,  # spi_pin_drv (3 bytes)
            0,
            0,
            chip.chip_id,
            0,  # min_chip_rev, superseded by min_chip_rev_full
            0,  # min_chip_rev_full
            0xFFFF,  # max_chip_rev_full: no maximum revision
            0,  # reserved
            1,  # hash_appended
        )

    checksum = CHECKSUM_INIT
    for address, data in segments:
        image += struct.pack("<II", address, len(data)) + data
        for byte in data:
            checksum ^= byte

    # The checksum byte lands in the last position of a 16-byte block.
    image += b"\x00" * (15 - len(image) % 16) + bytes([checksum])
    if chip.isa != XTENSA_LX106:
        image += hashlib.sha256(image).digest()
    return image


def build_ram_helloworld() -> dict[str, bytes]:
    """Return filename -> contents for every RAM hello world image."""
    return {f"helloworld-{name}.bin": build_image(name) for name in CHIPS}


def materialize_ram_helloworld(dest_dir: Path) -> int:
    """Write every RAM hello world image into dest_dir (created if needed).

    Returns the number of files written.
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    images = build_ram_helloworld()
    for name, data in images.items():
        (dest_dir / name).write_bytes(data)
    return len(images)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Assemble the RAM hello world .bin fixtures for esptool tests."
    )
    default_out = Path(__file__).resolve().parent / "images" / "ram_helloworld"
    parser.add_argument(
        "--output",
        type=Path,
        default=default_out,
        help=f"Destination directory (default: {default_out})",
    )
    args = parser.parse_args(argv)
    count = materialize_ram_helloworld(args.output)
    print(f"Wrote {count} RAM hello world images to {args.output}")


if __name__ == "__main__":
    main()
