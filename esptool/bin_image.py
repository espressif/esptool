# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import binascii
import copy
import hashlib
import io
import os
import re
import struct
import tempfile
from typing import IO

from intelhex import HexRecordError, IntelHex

from .loader import ESPLoader
from .logger import log
from .targets import (
    ESP32C2ROM,
    ESP32C3ROM,
    ESP32C5ROM,
    ESP32C6ROM,
    ESP32C61ROM,
    ESP32H2ROM,
    ESP32H21ROM,
    ESP32H4ROM,
    ESP32P4ROM,
    ESP32ROM,
    ESP32S2ROM,
    ESP32S3ROM,
    ESP8266ROM,
)
from .util import FatalError, byte, ImageSource, get_bytes, pad_to


def align_file_position(f, size):
    """Align the position in the file to the next block of specified size"""
    align = (size - 1) - (f.tell() % size)
    f.seek(align, 1)


def _find_subsequences(addresses: list[int]) -> list[tuple[int, int]]:
    """Find continuous subsequences in a list of addresses"""
    if not addresses:
        return []

    sorted_seq = sorted(addresses)

    subsequences = []
    start = sorted_seq[0]

    for prev, num in zip(sorted_seq, sorted_seq[1:]):
        if num != prev + 1:
            # Found a gap, save the current subsequence
            subsequences.append((start, prev))
            start = num

    # Add the last subsequence
    subsequences.append((start, sorted_seq[-1]))

    return subsequences


def _split_intel_hex_file(ih: IntelHex) -> list[tuple[int, IO[bytes]]]:
    """Split an IntelHex file into multiple temporary binary files based on the gaps
    in the addresses"""
    subsequences = _find_subsequences(ih.addresses())
    bins: list[tuple[int, IO[bytes]]] = []
    for start, end in subsequences:
        bin = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        ih.tobinfile(bin, start=start, end=end)
        bin.seek(0)  # make sure the file is at the beginning
        bins.append((start, bin))
    return bins


def intel_hex_to_bin(
    file: IO[bytes], start_addr: int | None = None
) -> list[tuple[int | None, IO[bytes]]]:
    """Convert IntelHex file to list of temp binary files
    If not hex file return input file otherwise"""
    INTEL_HEX_MAGIC = b":"
    magic = file.read(1)
    file.seek(0)
    try:
        if magic == INTEL_HEX_MAGIC:
            ih = IntelHex()
            ih.loadhex(file.name)
            file.close()
            return _split_intel_hex_file(ih)  # type: ignore
        else:
            return [(start_addr, file)]
    except (HexRecordError, UnicodeDecodeError):
        # file started with HEX magic but the rest was not according to the standard
        return [(start_addr, file)]


def LoadFirmwareImage(chip: str, image_data: ImageSource):
    """
    Load a firmware image. Can be for any supported SoC.

    ESP8266 images will be examined to determine if they are original ROM firmware
    images (ESP8266ROMFirmwareImage) or "v2" OTA bootloader images.

    Returns a BaseFirmwareImage subclass.
    """
    data, _ = get_bytes(image_data)
    f = io.BytesIO(data)
    chip = re.sub(r"[-()]", "", chip.lower())
    if chip == "esp8266":
        # Look at the magic number to determine the ESP8266 image type
        magic = ord(f.read(1))
        f.seek(0)
        if magic == ESPLoader.ESP_IMAGE_MAGIC:
            return ESP8266ROMFirmwareImage(f)
        elif magic == ESP8266V2FirmwareImage.IMAGE_V2_MAGIC:
            return ESP8266V2FirmwareImage(f)
        else:
            raise FatalError(f"Invalid image magic number: {magic}")
    else:
        return {
            "esp32": ESP32FirmwareImage,
            "esp32s2": ESP32S2FirmwareImage,
            "esp32s3": ESP32S3FirmwareImage,
            "esp32c3": ESP32C3FirmwareImage,
            "esp32c2": ESP32C2FirmwareImage,
            "esp32c6": ESP32C6FirmwareImage,
            "esp32c61": ESP32C61FirmwareImage,
            "esp32c5": ESP32C5FirmwareImage,
            "esp32h2": ESP32H2FirmwareImage,
            "esp32h21": ESP32H21FirmwareImage,
            "esp32p4": ESP32P4FirmwareImage,
            "esp32h4": ESP32H4FirmwareImage,
        }[chip](f)


class ImageSegment(object):
    """Wrapper class for a segment in an ESP image
    (very similar to a section in an ELFImage also)"""

    def __init__(self, addr, data, file_offs=None, flags=0, align=4):
        self.addr = addr
        self.data = data
        self.file_offs = file_offs
        self.flags = flags
        self.align = align
        self.include_in_checksum = True
        if self.addr != 0:
            self.pad_to_alignment(
                4
            )  # pad all "real" ImageSegments 4 byte aligned length

    def copy_with_new_addr(self, new_addr):
        """Return a new ImageSegment with same data, but mapped at
        a new address."""
        return ImageSegment(new_addr, self.data, 0)

    def split_image(self, split_len):
        """Return a new ImageSegment which splits "split_len" bytes
        from the beginning of the data. Remaining bytes are kept in
        this segment object (and the start address is adjusted to match.)"""
        result = copy.copy(self)
        result.data = self.data[:split_len]
        self.data = self.data[split_len:]
        self.addr += split_len
        self.file_offs = None
        result.file_offs = None
        return result

    def __repr__(self):
        r = "len 0x%05x load 0x%08x" % (len(self.data), self.addr)
        if self.file_offs is not None:
            r += " file_offs 0x%08x" % (self.file_offs)
        return r

    def get_memory_type(self, image):
        """
        Return a list describing the memory type(s) that is covered by this
        segment's start address.
        """
        return [
            map_range[2]
            for map_range in image.ROM_LOADER.MEMORY_MAP
            if map_range[0] <= self.addr < map_range[1]
        ]

    def pad_to_alignment(self, alignment):
        self.data = pad_to(self.data, alignment, b"\x00")

    def end_addr_if_aligned(self, alignment):
        """
        Return the segment end address as it would be if
        aligned as requested by the argument.
        """
        end_addr = self.addr + len(self.data)
        addr_mod = end_addr % alignment
        if addr_mod != 0:
            end_addr += alignment - addr_mod
        return end_addr

    def pad_until_addr(self, addr):
        """
        Pad the segment with `0x00` starting with segment address
        until the address given by the argument.
        """
        pad = addr - (self.addr + len(self.data))
        if pad > 0:
            self.data += b"\x00" * pad


class ELFSection(ImageSegment):
    """Wrapper class for a section in an ELF image, has a section
    name as well as the common properties of an ImageSegment."""

    def __init__(self, name, addr, data, flags, align=4):
        super(ELFSection, self).__init__(addr, data, flags=flags, align=align)
        self.name = name.decode("utf-8")

    def __repr__(self):
        return "%s %s" % (self.name, super(ELFSection, self).__repr__())


class BaseFirmwareImage(object):
    SEG_HEADER_LEN = 8
    SHA256_DIGEST_LEN = 32
    IROM_ALIGN = 0
    MMU_PAGE_SIZE_CONF: tuple[int, ...] = ()

    """ Base class with common firmware image functions """

    def __init__(self):
        self.segments = []
        self.entrypoint = 0
        self.elf_sha256 = None
        self.elf_sha256_offset = 0
        self.pad_to_size = 0

    def load_common_header(self, load_file, expected_magic):
        (
            magic,
            segments,
            self.flash_mode,
            self.flash_size_freq,
            self.entrypoint,
        ) = struct.unpack("<BBBBI", load_file.read(8))

        if magic != expected_magic:
            raise FatalError("Invalid firmware image magic=0x%x" % (magic))
        return segments

    def verify(self):
        if len(self.segments) > 16:
            raise FatalError(
                "Invalid segment count %d (max 16). "
                "Usually this indicates a linker script problem." % len(self.segments)
            )

    def load_segment(self, f, is_irom_segment=False):
        """Load the next segment from the image file"""
        file_offs = f.tell()
        (offset, size) = struct.unpack("<II", f.read(8))
        self.warn_if_unusual_segment(offset, size, is_irom_segment)
        segment_data = f.read(size)
        if len(segment_data) < size:
            raise FatalError(
                "End of file reading segment 0x%x, length %d (actual length %d)"
                % (offset, size, len(segment_data))
            )
        segment = ImageSegment(offset, segment_data, file_offs)
        self.segments.append(segment)
        return segment

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        if not is_irom_segment:
            if offset > 0x40200000 or offset < 0x3FFE0000 or size > 65536:
                log.warning(f"Suspicious segment {offset:#x}, length {size}")

    def maybe_patch_segment_data(self, f, segment_data):
        """
        If SHA256 digest of the ELF file needs to be inserted into this segment, do so.
        Returns segment data.
        """
        segment_len = len(segment_data)
        file_pos = f.tell()  # file_pos is position in the .bin file
        if (
            self.elf_sha256_offset >= file_pos
            and self.elf_sha256_offset < file_pos + segment_len
        ):
            # SHA256 digest needs to be patched into this binary segment,
            # calculate offset of the digest inside the binary segment.
            patch_offset = self.elf_sha256_offset - file_pos
            # Sanity checks
            if (
                patch_offset < self.SEG_HEADER_LEN
                or patch_offset + self.SHA256_DIGEST_LEN > segment_len
            ):
                raise FatalError(
                    "Cannot place SHA256 digest on segment boundary"
                    "(elf_sha256_offset=%d, file_pos=%d, segment_size=%d)"
                    % (self.elf_sha256_offset, file_pos, segment_len)
                )
            # offset relative to the data part
            patch_offset -= self.SEG_HEADER_LEN
            if (
                segment_data[patch_offset : patch_offset + self.SHA256_DIGEST_LEN]
                != b"\x00" * self.SHA256_DIGEST_LEN
            ):
                raise FatalError(
                    "Contents of segment at SHA256 digest offset 0x%x are not all zero."
                    " Refusing to overwrite." % self.elf_sha256_offset
                )
            assert len(self.elf_sha256) == self.SHA256_DIGEST_LEN
            segment_data = (
                segment_data[0:patch_offset]
                + self.elf_sha256
                + segment_data[patch_offset + self.SHA256_DIGEST_LEN :]
            )
        return segment_data

    def save_segment(self, f, segment, checksum=None, segment_name=None):
        """
        Save the next segment to the image file,
        return next checksum value if provided
        """
        segment_data = self.maybe_patch_segment_data(f, segment.data)
        segment_len = len(segment_data)
        segment_name = segment_name if segment_name is not None else ""
        if segment_len & 3:
            raise FatalError(
                f"Invalid {segment_name} segment length {segment_len:#x}. "
                "It has to be multiple of 4."
            )
        SIXTEEN_MB = 0x1000000
        if segment_len >= SIXTEEN_MB:
            raise FatalError(
                f"Invalid {segment_name} segment length {segment_len:#x}. "
                "The 16 MB limit has been exceeded."
            )
        f.write(struct.pack("<II", segment.addr, segment_len))
        f.write(segment_data)
        if checksum is not None:
            return ESPLoader.checksum(segment_data, checksum)

    def save_flash_segment(self, f, segment, checksum=None):
        """
        Save the next segment to the image file, return next checksum value if provided
        """
        if self.ROM_LOADER.CHIP_NAME == "ESP32":
            # Work around a bug in ESP-IDF 2nd stage bootloader, that it didn't map the
            # last MMU page, if an IROM/DROM segment was < 0x24 bytes
            # over the page boundary.
            segment_end_pos = f.tell() + len(segment.data) + self.SEG_HEADER_LEN
            segment_len_remainder = segment_end_pos % self.IROM_ALIGN
            if segment_len_remainder < 0x24:
                segment.data += b"\x00" * (0x24 - segment_len_remainder)
        segment_name = getattr(segment, "name", None)
        return self.save_segment(f, segment, checksum, segment_name)

    def read_checksum(self, f):
        """Return ESPLoader checksum from end of just-read image"""
        # Skip the padding. The checksum is stored in the last byte so that the
        # file is a multiple of 16 bytes.
        align_file_position(f, 16)
        return ord(f.read(1))

    def calculate_checksum(self):
        """
        Calculate checksum of loaded image, based on segments in
        segment array.
        """
        checksum = ESPLoader.ESP_CHECKSUM_MAGIC
        for seg in self.segments:
            if seg.include_in_checksum:
                checksum = ESPLoader.checksum(seg.data, checksum)
        return checksum

    def append_checksum(self, f, checksum):
        """Append ESPLoader checksum to the just-written image"""
        align_file_position(f, 16)
        f.write(struct.pack(b"B", checksum))

    def write_common_header(self, f, segments):
        f.write(
            struct.pack(
                "<BBBBI",
                ESPLoader.ESP_IMAGE_MAGIC,
                len(segments),
                self.flash_mode,
                self.flash_size_freq,
                self.entrypoint,
            )
        )

    def is_irom_addr(self, addr):
        """
        Returns True if an address starts in the irom region.
        Valid for ESP8266 only.
        """
        return ESP8266ROM.IROM_MAP_START <= addr < ESP8266ROM.IROM_MAP_END

    def get_irom_segment(self):
        irom_segments = [s for s in self.segments if self.is_irom_addr(s.addr)]
        if len(irom_segments) > 0:
            if len(irom_segments) != 1:
                raise FatalError(
                    "Found %d segments that could be irom0. Bad ELF file?"
                    % len(irom_segments)
                )
            return irom_segments[0]
        return None

    def get_non_irom_segments(self):
        irom_segment = self.get_irom_segment()
        return [s for s in self.segments if s != irom_segment]

    def sort_segments(self):
        if not self.segments:
            return  # nothing to sort
        self.segments = sorted(self.segments, key=lambda s: s.addr)

    def merge_adjacent_segments(self):
        if not self.segments:
            return  # nothing to merge

        segments = []
        # The easiest way to merge the sections is the browse them backward.
        for i in range(len(self.segments) - 1, 0, -1):
            # elem is the previous section, the one `next_elem` may need to be
            # merged in
            elem = self.segments[i - 1]
            next_elem = self.segments[i]

            # When creating the images from 3rd-party frameworks ELFs, the merging
            # could bring together segments with incompatible alignment requirements.
            # At this point, we add padding so the resulting placement respects the
            # original alignment requirements of those segments.
            if self.ROM_LOADER != ESP8266ROM and self.ram_only_header:
                elem_pad_addr = elem.end_addr_if_aligned(next_elem.align)

                if (
                    elem_pad_addr != elem.addr + len(elem.data)
                    and elem_pad_addr == next_elem.addr
                ):
                    log.info(
                        "Inserting {} bytes padding between {} and {}".format(
                            next_elem.addr - (elem.addr + len(elem.data)),
                            elem.name,
                            next_elem.name,
                        )
                    )
                    elem.pad_until_addr(elem_pad_addr)
            if all(
                (
                    elem.get_memory_type(self) == next_elem.get_memory_type(self),
                    elem.include_in_checksum == next_elem.include_in_checksum,
                    next_elem.addr == elem.addr + len(elem.data),
                )
            ):
                # Merge any segment that ends where the next one starts,
                # without spanning memory types
                #
                # (don't 'pad' any gaps here as they may be excluded from the image
                # due to 'noinit' or other reasons.)
                elem.data += next_elem.data
            else:
                # The section next_elem cannot be merged into the previous one,
                # which means it needs to be part of the final segments.
                # As we are browsing the list backward, the elements need to be
                # inserted at the beginning of the final list.
                segments.insert(0, next_elem)

        # The first segment will always be here as it cannot be merged into any
        # "previous" section.
        segments.insert(0, self.segments[0])

        # note: we could sort segments here as well, but the ordering of segments is
        # sometimes important for other reasons (like embedded ELF SHA-256),
        # so we assume that the linker script will have produced any adjacent sections
        # in linear order in the ELF, anyhow.
        self.segments = segments

    def set_mmu_page_size(self, size):
        """Set the MMU page size for the image if supported by the chip."""
        if not self.MMU_PAGE_SIZE_CONF and size != self.IROM_ALIGN:
            # For chips where MMU page size cannot be set or is fixed, just log a
            # warning and use default if there is one.
            log.warning(
                "Changing MMU page size is not supported on "
                f"{self.ROM_LOADER.CHIP_NAME}! Defaulting to "
                f"{self.IROM_ALIGN // 1024}KB."
                if self.IROM_ALIGN != 0
                else ""
            )
        elif self.MMU_PAGE_SIZE_CONF and size not in self.MMU_PAGE_SIZE_CONF:
            # For chips with configurable MMU page sizes, error is raised when the
            # size is not valid.
            valid_sizes = ", ".join(f"{x // 1024}KB" for x in self.MMU_PAGE_SIZE_CONF)
            raise FatalError(
                f"{size} bytes is not a valid {self.ROM_LOADER.CHIP_NAME} page size, "
                f"select from {valid_sizes}."
            )
        else:
            self.IROM_ALIGN = size


class ESP8266ROMFirmwareImage(BaseFirmwareImage):
    """'Version 1' firmware image, segments loaded directly by the ROM bootloader."""

    ROM_LOADER = ESP8266ROM

    def __init__(self, load_file=None):
        super(ESP8266ROMFirmwareImage, self).__init__()
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1

        if load_file is not None:
            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            self.verify()

    def default_output_name(self, input_file):
        """Derive a default output name from the ELF name."""
        return input_file + "-"

    def save(self, filename: str | None) -> tuple[bytes | None, bytes] | None:
        irom_data: bytes | None = None
        other_data: bytes | None = None

        # Handle IROM data
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            irom_data = irom_segment.data

        # Handle other segments (everything but IROM)
        with io.BytesIO() as f:  # Use BytesIO to write to memory
            normal_segments = self.get_non_irom_segments()
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)

            other_data = f.getvalue()  # Get the bytes from BytesIO

        if filename is not None:
            # Write IROM data to a file
            if irom_data is not None:
                offset = irom_segment.addr - ESP8266ROM.IROM_MAP_START
                with open(f"{filename}{offset:#07x}.bin", "wb") as f:
                    f.write(irom_data)
            # Write other data to a file
            if other_data is not None:
                with open(f"{filename}{0:#07x}.bin", "wb") as f:
                    f.write(other_data)
            return None
        else:
            return (irom_data, other_data)


ESP8266ROM.BOOTLOADER_IMAGE = ESP8266ROMFirmwareImage


class ESP8266V2FirmwareImage(BaseFirmwareImage):
    """'Version 2' firmware image, segments loaded by software bootloader stub
    (ie Espressif bootloader or rboot)
    """

    ROM_LOADER = ESP8266ROM
    # First byte of the "v2" application image
    IMAGE_V2_MAGIC = 0xEA

    # First 'segment' value in a "v2" application image,
    # appears to be a constant version value?
    IMAGE_V2_SEGMENT = 4

    def __init__(self, load_file=None):
        super(ESP8266V2FirmwareImage, self).__init__()
        self.version = 2
        if load_file is not None:
            segments = self.load_common_header(load_file, self.IMAGE_V2_MAGIC)
            if segments != self.IMAGE_V2_SEGMENT:
                # segment count is not really segment count here,
                # but we expect to see '4'
                log.warning(
                    f'V2 header has unexpected "segment" count {segments} (usually 4)'
                )

            # irom segment comes before the second header
            #
            # the file is saved in the image with a zero load address
            # in the header, so we need to calculate a load address
            irom_segment = self.load_segment(load_file, True)
            # for actual mapped addr, add ESP8266ROM.IROM_MAP_START + flashing_addr + 8
            irom_segment.addr = 0
            irom_segment.include_in_checksum = False

            first_flash_mode = self.flash_mode
            first_flash_size_freq = self.flash_size_freq
            first_entrypoint = self.entrypoint
            # load the second header

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

            if first_flash_mode != self.flash_mode:
                log.warning(
                    f"Flash mode value in first header ({first_flash_mode:#04x}) "
                    f"disagrees with second ({self.flash_mode:#04x}). "
                    "Using second value."
                )
            if first_flash_size_freq != self.flash_size_freq:
                log.warning(
                    "Flash size/freq value in first header "
                    f"({first_flash_size_freq:#04x}) disagrees with second "
                    f"({self.flash_size_freq:#04x}). Using second value."
                )
            if first_entrypoint != self.entrypoint:
                log.warning(
                    f"Entrypoint address in first header ({first_entrypoint:#010x}) "
                    f"disagrees with second header ({self.entrypoint:#010x}). "
                    "Using second value."
                )

            # load all the usual segments
            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            self.verify()

    def default_output_name(self, input_file):
        """Derive a default output name from the ELF name."""
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            irom_offs = irom_segment.addr - ESP8266ROM.IROM_MAP_START
        else:
            irom_offs = 0
        return "%s-0x%05x.bin" % (
            os.path.splitext(input_file)[0],
            irom_offs & ~(ESPLoader.FLASH_SECTOR_SIZE - 1),
        )

    def save(self, filename: str | None) -> bytes | None:
        with io.BytesIO() as f:  # Write to memory first
            # Save first header for irom0 segment
            f.write(
                struct.pack(
                    b"<BBBBI",
                    self.IMAGE_V2_MAGIC,
                    self.IMAGE_V2_SEGMENT,
                    self.flash_mode,
                    self.flash_size_freq,
                    self.entrypoint,
                )
            )

            irom_segment = self.get_irom_segment()
            if irom_segment is not None:
                # save irom0 segment, make sure it has load addr 0 in the file
                irom_segment = irom_segment.copy_with_new_addr(0)
                irom_segment.pad_to_alignment(
                    16
                )  # irom_segment must end on a 16 byte boundary
                self.save_segment(f, irom_segment)

            # second header, matches V1 header and contains loadable segments
            normal_segments = self.get_non_irom_segments()
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)

            # Calculate CRC32 of the entire file and append
            f.seek(0)  # Move to the start of the BytesIO buffer
            crc = esp8266_crc32(f.read())
            f.write(struct.pack(b"<I", crc))

            if filename is not None:
                # Write the content to a real file
                with open(filename, "wb") as real_file:
                    real_file.write(f.getvalue())
                return None
            else:
                # Return the bytes if no filename is provided
                return f.getvalue()


def esp8266_crc32(data):
    """
    CRC32 algorithm used by 8266 SDK bootloader (and gen_appbin.py).
    """
    crc = binascii.crc32(data, 0) & 0xFFFFFFFF
    if crc & 0x80000000:
        return crc ^ 0xFFFFFFFF
    else:
        return crc + 1


class ESP32FirmwareImage(BaseFirmwareImage):
    """ESP32 firmware image is very similar to V1 ESP8266 image,
    except with an additional 16 byte reserved header at top of image,
    and because of new flash mapping capabilities the flash-mapped regions
    can be placed in the normal image (just @ MMU page size padded offsets).
    """

    ROM_LOADER = ESP32ROM

    # ROM bootloader will read the wp_pin field if SPI flash
    # pins are remapped via flash. IDF actually enables QIO only
    # from software bootloader, so this can be ignored. But needs
    # to be set to this value so ROM bootloader will skip it.
    WP_PIN_DISABLED = 0xEE

    EXTENDED_HEADER_STRUCT_FMT = "<BBBBHBHH" + ("B" * 4) + "B"

    IROM_ALIGN = 65536

    def __init__(self, load_file=None, append_digest=True, ram_only_header=False):
        super(ESP32FirmwareImage, self).__init__()
        self.secure_pad = None
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1
        self.wp_pin = self.WP_PIN_DISABLED
        # SPI pin drive levels
        self.clk_drv = 0
        self.q_drv = 0
        self.d_drv = 0
        self.cs_drv = 0
        self.hd_drv = 0
        self.wp_drv = 0
        self.chip_id = 0
        self.min_rev = 0
        self.min_rev_full = 0
        self.max_rev_full = 0
        self.ram_only_header = ram_only_header

        self.append_digest = append_digest
        self.data_length = None

        if load_file is not None:
            start = load_file.tell()

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)
            self.load_extended_header(load_file)

            for _ in range(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

            if self.append_digest:
                end = load_file.tell()
                self.stored_digest = load_file.read(32)
                load_file.seek(start)
                calc_digest = hashlib.sha256()
                calc_digest.update(load_file.read(end - start))
                self.calc_digest = calc_digest.digest()  # TODO: decide what to do here?
                self.data_length = end - start

            self.verify()

    def is_flash_addr(self, addr):
        return (
            self.ROM_LOADER.IROM_MAP_START <= addr < self.ROM_LOADER.IROM_MAP_END
        ) or (self.ROM_LOADER.DROM_MAP_START <= addr < self.ROM_LOADER.DROM_MAP_END)

    def default_output_name(self, input_file):
        """Derive a default output name from the ELF name."""
        return "%s.bin" % (os.path.splitext(input_file)[0])

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        pass  # TODO: add warnings for wrong ESP32 segment offset/size combinations

    def save(self, filename: str | None) -> bytes | None:
        total_segments = 0
        with io.BytesIO() as f:  # write file to memory first
            self.write_common_header(f, self.segments)

            # first 4 bytes of header are read by ROM bootloader for SPI
            # config, but currently unused
            self.save_extended_header(f)

            checksum = ESPLoader.ESP_CHECKSUM_MAGIC

            # split segments into flash-mapped vs ram-loaded,
            # and take copies so we can mutate them
            flash_segments = [
                copy.deepcopy(s)
                for s in sorted(self.segments, key=lambda s: s.addr)
                if self.is_flash_addr(s.addr)
            ]
            ram_segments = [
                copy.deepcopy(s)
                for s in sorted(self.segments, key=lambda s: s.addr)
                if not self.is_flash_addr(s.addr)
            ]

            # Patch to support ESP32-C6 union bus memmap
            # move ".flash.appdesc" segment to the top of the flash segment
            for segment in flash_segments:
                if isinstance(segment, ELFSection) and segment.name == ".flash.appdesc":
                    flash_segments.remove(segment)
                    flash_segments.insert(0, segment)
                    break

            # For the bootloader image
            # move ".dram0.bootdesc" segment to the top of the ram segment
            # So bootdesc will be at the very top of the binary at 0x20 offset
            # (in the first segment).
            for segment in ram_segments:
                if (
                    isinstance(segment, ELFSection)
                    and segment.name == ".dram0.bootdesc"
                ):
                    ram_segments.remove(segment)
                    ram_segments.insert(0, segment)
                    break

            # check for multiple ELF sections that are mapped in the same
            # flash mapping region. This is usually a sign of a broken linker script,
            # but if you have a legitimate use case then let us know
            if len(flash_segments) > 0:
                last_addr = flash_segments[0].addr
                for segment in flash_segments[1:]:
                    if segment.addr // self.IROM_ALIGN == last_addr // self.IROM_ALIGN:
                        raise FatalError(
                            f"Segment loaded at {segment.addr:#010x} lands in same "
                            f"{self.IROM_ALIGN // 1024} KB flash mapping as segment "
                            f"loaded at {last_addr:#010x}. Can't generate binary. "
                            "Suggest changing linker script or ELF to merge sections."
                        )
                    last_addr = segment.addr

            def get_alignment_data_needed(segment):
                # Actual alignment (in data bytes) required for a segment header:
                # positioned so that after we write the next 8 byte header,
                # file_offs % IROM_ALIGN == segment.addr % IROM_ALIGN
                #
                # (this is because the segment's vaddr may not be IROM_ALIGNed,
                # more likely is aligned IROM_ALIGN+0x18
                # to account for the binary file header
                align_past = (segment.addr % self.IROM_ALIGN) - self.SEG_HEADER_LEN
                pad_len = (self.IROM_ALIGN - (f.tell() % self.IROM_ALIGN)) + align_past
                if pad_len == 0 or pad_len == self.IROM_ALIGN:
                    return 0  # already aligned

                # subtract SEG_HEADER_LEN a second time,
                # as the padding block has a header as well
                pad_len -= self.SEG_HEADER_LEN
                if pad_len < 0:
                    pad_len += self.IROM_ALIGN
                return pad_len

            if self.ram_only_header:
                # write RAM segments first in order to get only RAM segments quantity
                # and checksum (ROM bootloader will only care for RAM segments and its
                # correct checksums)
                for segment in ram_segments:
                    checksum = self.save_segment(f, segment, checksum, segment.name)
                    total_segments += 1
                self.append_checksum(f, checksum)

                # reversing to match the same section order from linker script
                flash_segments.reverse()
                for segment in flash_segments:
                    pad_len = get_alignment_data_needed(segment)
                    # Some chips have a non-zero load offset (eg. 0x1000)
                    # therefore we shift the ROM segments "-load_offset"
                    # so it will be aligned properly after it is flashed
                    if pad_len < self.ROM_LOADER.BOOTLOADER_FLASH_OFFSET:
                        # in case pad_len does not fit minimum alignment,
                        # pad it to next aligned boundary
                        pad_len += self.IROM_ALIGN

                    pad_len -= self.ROM_LOADER.BOOTLOADER_FLASH_OFFSET
                    pad_segment = ImageSegment(0, b"\x00" * pad_len, f.tell())
                    self.save_segment(f, pad_segment, None, segment.name)
                    total_segments += 1
                    # check the alignment
                    assert (f.tell() + 8 + self.ROM_LOADER.BOOTLOADER_FLASH_OFFSET) % (
                        self.IROM_ALIGN
                    ) == segment.addr % self.IROM_ALIGN
                    # save the flash segment but not saving its checksum neither
                    # saving the number of flash segments, since ROM bootloader
                    # should "not see" them
                    self.save_flash_segment(f, segment)
                    total_segments += 1
            else:  # not self.ram_only_header
                # try to fit each flash segment on a MMU page size aligned boundary
                # by padding with parts of the non-flash segments...
                while len(flash_segments) > 0:
                    segment = flash_segments[0]
                    pad_len = get_alignment_data_needed(segment)
                    if pad_len > 0:  # need to pad
                        if len(ram_segments) > 0 and pad_len > self.SEG_HEADER_LEN:
                            pad_segment = ram_segments[0].split_image(pad_len)
                            if len(ram_segments[0].data) == 0:
                                ram_segments.pop(0)
                        else:
                            pad_segment = ImageSegment(0, b"\x00" * pad_len, f.tell())
                        checksum = self.save_segment(
                            f, pad_segment, checksum, segment.name
                        )
                        total_segments += 1
                    else:
                        # write the flash segment
                        assert (
                            f.tell() + 8
                        ) % self.IROM_ALIGN == segment.addr % self.IROM_ALIGN
                        checksum = self.save_flash_segment(f, segment, checksum)
                        flash_segments.pop(0)
                        total_segments += 1

                # flash segments all written, so write any remaining RAM segments
                for segment in ram_segments:
                    checksum = self.save_segment(f, segment, checksum, segment.name)
                    total_segments += 1

            if self.secure_pad:
                # pad the image so that after signing it will end on a a MMU page size
                # boundary. This ensures all mapped flash content will be verified.
                if not self.append_digest:
                    raise FatalError(
                        "secure_pad only applies if a SHA-256 digest "
                        "is also appended to the image"
                    )
                align_past = (f.tell() + self.SEG_HEADER_LEN) % self.IROM_ALIGN
                # 16 byte aligned checksum
                # (force the alignment to simplify calculations)
                checksum_space = 16
                if self.secure_pad == "1":
                    # after checksum: SHA-256 digest +
                    # (to be added by signing process) version,
                    # signature + 12 trailing bytes due to alignment
                    space_after_checksum = 32 + 4 + 64 + 12
                elif self.secure_pad == "2":  # Secure Boot V2
                    # after checksum: SHA-256 digest +
                    # signature sector,
                    # but we place signature sector after the MMU page size boundary
                    space_after_checksum = 32
                pad_len = (
                    self.IROM_ALIGN - align_past - checksum_space - space_after_checksum
                ) % self.IROM_ALIGN
                pad_segment = ImageSegment(0, b"\x00" * pad_len, f.tell())

                checksum = self.save_segment(f, pad_segment, checksum)
                total_segments += 1

            if not self.ram_only_header:
                # done writing segments
                self.append_checksum(f, checksum)
            image_length = f.tell()

            if self.secure_pad:
                assert ((image_length + space_after_checksum) % self.IROM_ALIGN) == 0

            # kinda hacky: go back to the initial header and write the new segment count
            # that includes padding segments. This header is not checksummed
            f.seek(1)
            if self.ram_only_header:
                # Update the header with the RAM segments quantity as it should be
                # visible by the ROM bootloader
                f.write(bytes([len(ram_segments)]))
            else:
                f.write(bytes([total_segments]))

            if self.append_digest:
                # calculate the SHA256 of the whole file and append it
                f.seek(0)
                digest = hashlib.sha256()
                digest.update(f.read(image_length))
                f.write(digest.digest())

            if self.pad_to_size:
                image_length = f.tell()
                if image_length % self.pad_to_size != 0:
                    pad_by = self.pad_to_size - (image_length % self.pad_to_size)
                    f.write(b"\xff" * pad_by)

            if filename is not None:
                # Write the content to a real file
                with open(filename, "wb") as real_file:
                    real_file.write(f.getvalue())
                return None
            else:
                # Return the bytes if no filename is provided
                return f.getvalue()

    def load_extended_header(self, load_file):
        def split_byte(n):
            return (n & 0x0F, (n >> 4) & 0x0F)

        fields = list(
            struct.unpack(self.EXTENDED_HEADER_STRUCT_FMT, load_file.read(16))
        )

        self.wp_pin = fields[0]

        # SPI pin drive stengths are two per byte
        self.clk_drv, self.q_drv = split_byte(fields[1])
        self.d_drv, self.cs_drv = split_byte(fields[2])
        self.hd_drv, self.wp_drv = split_byte(fields[3])

        self.chip_id = fields[4]
        if self.chip_id != self.ROM_LOADER.IMAGE_CHIP_ID:
            log.warning(
                f"Unexpected chip ID in image. Expected {self.ROM_LOADER.IMAGE_CHIP_ID}"
                f" but value was {self.chip_id}. Is this image for a different "
                "chip model?"
            )

        self.min_rev = fields[5]
        self.min_rev_full = fields[6]
        self.max_rev_full = fields[7]

        append_digest = fields[-1]  # last byte is append_digest
        if append_digest in [0, 1]:
            self.append_digest = append_digest == 1
        else:
            raise RuntimeError(
                "Invalid value for append_digest field (0x%02x). Should be 0 or 1.",
                append_digest,
            )

    def save_extended_header(self, save_file):
        def join_byte(ln, hn):
            return (ln & 0x0F) + ((hn & 0x0F) << 4)

        append_digest = 1 if self.append_digest else 0

        fields = [
            self.wp_pin,
            join_byte(self.clk_drv, self.q_drv),
            join_byte(self.d_drv, self.cs_drv),
            join_byte(self.hd_drv, self.wp_drv),
            self.ROM_LOADER.IMAGE_CHIP_ID,
            self.min_rev,
            self.min_rev_full,
            self.max_rev_full,
        ]
        fields += [0] * 4  # padding
        fields += [append_digest]

        packed = struct.pack(self.EXTENDED_HEADER_STRUCT_FMT, *fields)
        save_file.write(packed)


class ESP8266V3FirmwareImage(ESP32FirmwareImage):
    """ESP8266 V3 firmware image is very similar to ESP32 image"""

    EXTENDED_HEADER_STRUCT_FMT = "B" * 16

    def is_flash_addr(self, addr):
        return addr > ESP8266ROM.IROM_MAP_START

    def save(self, filename: str | None) -> bytes | None:
        total_segments = 0
        with io.BytesIO() as f:  # write file to memory first
            self.write_common_header(f, self.segments)

            checksum = ESPLoader.ESP_CHECKSUM_MAGIC

            # split segments into flash-mapped vs ram-loaded,
            # and take copies so we can mutate them
            flash_segments = [
                copy.deepcopy(s)
                for s in sorted(self.segments, key=lambda s: s.addr)
                if self.is_flash_addr(s.addr) and len(s.data)
            ]
            ram_segments = [
                copy.deepcopy(s)
                for s in sorted(self.segments, key=lambda s: s.addr)
                if not self.is_flash_addr(s.addr) and len(s.data)
            ]

            # check for multiple ELF sections that are mapped in the same
            # flash mapping region. This is usually a sign of a broken linker script,
            # but if you have a legitimate use case then let us know
            if len(flash_segments) > 0:
                last_addr = flash_segments[0].addr
                for segment in flash_segments[1:]:
                    if segment.addr // self.IROM_ALIGN == last_addr // self.IROM_ALIGN:
                        raise FatalError(
                            f"Segment loaded at {segment.addr:#010x} lands in same "
                            f"{self.IROM_ALIGN // 1024} KB flash mapping as segment "
                            f"loaded at {last_addr:#010x}. Can't generate binary. "
                            "Suggest changing linker script or ELF to merge sections."
                        )
                    last_addr = segment.addr

            # try to fit each flash segment on a MMU page size aligned boundary
            # by padding with parts of the non-flash segments...
            while len(flash_segments) > 0:
                segment = flash_segments[0]
                # remove 8 bytes empty data for insert segment header
                if isinstance(segment, ELFSection) and segment.name == ".flash.rodata":
                    segment.data = segment.data[8:]
                # write the flash segment
                checksum = self.save_segment(f, segment, checksum)
                flash_segments.pop(0)
                total_segments += 1

            # flash segments all written, so write any remaining RAM segments
            for segment in ram_segments:
                checksum = self.save_segment(f, segment, checksum)
                total_segments += 1

            # done writing segments
            self.append_checksum(f, checksum)
            image_length = f.tell()

            # kinda hacky: go back to the initial header and write the new segment count
            # that includes padding segments. This header is not checksummed
            f.seek(1)
            f.write(bytes([total_segments]))

            if self.append_digest:
                # calculate the SHA256 of the whole file and append it
                f.seek(0)
                digest = hashlib.sha256()
                digest.update(f.read(image_length))
                f.write(digest.digest())

            if filename is not None:
                # Write the content to a real file
                with open(filename, "wb") as real_file:
                    real_file.write(f.getvalue())
                return None
            else:
                # Return the bytes if no filename is provided
                return f.getvalue()

    def load_extended_header(self, load_file):
        def split_byte(n):
            return (n & 0x0F, (n >> 4) & 0x0F)

        fields = list(
            struct.unpack(self.EXTENDED_HEADER_STRUCT_FMT, load_file.read(16))
        )

        self.wp_pin = fields[0]

        # SPI pin drive stengths are two per byte
        self.clk_drv, self.q_drv = split_byte(fields[1])
        self.d_drv, self.cs_drv = split_byte(fields[2])
        self.hd_drv, self.wp_drv = split_byte(fields[3])

        if fields[15] in [0, 1]:
            self.append_digest = fields[15] == 1
        else:
            raise RuntimeError(
                "Invalid value for append_digest field (0x%02x). Should be 0 or 1.",
                fields[15],
            )

        # remaining fields in the middle should all be zero
        if any(f for f in fields[4:15] if f != 0):
            log.warning(
                "Some reserved header fields have non-zero values. "
                "This image may be from a newer esptool?"
            )


ESP32ROM.BOOTLOADER_IMAGE = ESP32FirmwareImage


class ESP32S2FirmwareImage(ESP32FirmwareImage):
    """ESP32S2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32S2ROM


ESP32S2ROM.BOOTLOADER_IMAGE = ESP32S2FirmwareImage


class ESP32S3FirmwareImage(ESP32FirmwareImage):
    """ESP32S3 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32S3ROM


ESP32S3ROM.BOOTLOADER_IMAGE = ESP32S3FirmwareImage


class ESP32C3FirmwareImage(ESP32FirmwareImage):
    """ESP32C3 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C3ROM


ESP32C3ROM.BOOTLOADER_IMAGE = ESP32C3FirmwareImage


class ESP32C2FirmwareImage(ESP32FirmwareImage):
    """ESP32C2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C2ROM
    MMU_PAGE_SIZE_CONF = (16384, 32768, 65536)


ESP32C2ROM.BOOTLOADER_IMAGE = ESP32C2FirmwareImage


class ESP32C6FirmwareImage(ESP32FirmwareImage):
    """ESP32C6 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C6ROM
    MMU_PAGE_SIZE_CONF = (8192, 16384, 32768, 65536)


ESP32C6ROM.BOOTLOADER_IMAGE = ESP32C6FirmwareImage


class ESP32C61FirmwareImage(ESP32C6FirmwareImage):
    """ESP32C61 Firmware Image almost exactly the same as ESP32C6FirmwareImage"""

    ROM_LOADER = ESP32C61ROM


ESP32C61ROM.BOOTLOADER_IMAGE = ESP32C61FirmwareImage


class ESP32C5FirmwareImage(ESP32FirmwareImage):
    """ESP32C5 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C5ROM


ESP32C5ROM.BOOTLOADER_IMAGE = ESP32C5FirmwareImage


class ESP32H4FirmwareImage(ESP32FirmwareImage):
    """ESP32H4 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32H4ROM

    def set_mmu_page_size(self, size):
        if size not in [8192, 16384, 32768, 65536]:
            raise FatalError(
                "{} bytes is not a valid ESP32-H4 page size, "
                "select from 64KB, 32KB, 16KB, 8KB.".format(size)
            )
        self.IROM_ALIGN = size


ESP32H4ROM.BOOTLOADER_IMAGE = ESP32H4FirmwareImage


class ESP32P4FirmwareImage(ESP32FirmwareImage):
    """ESP32P4 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32P4ROM


ESP32P4ROM.BOOTLOADER_IMAGE = ESP32P4FirmwareImage


class ESP32H2FirmwareImage(ESP32C6FirmwareImage):
    """ESP32H2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32H2ROM


ESP32H2ROM.BOOTLOADER_IMAGE = ESP32H2FirmwareImage


class ESP32H21FirmwareImage(ESP32C6FirmwareImage):
    """ESP32H21 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32H21ROM


ESP32H21ROM.BOOTLOADER_IMAGE = ESP32H21FirmwareImage


class ELFFile(object):
    SEC_TYPE_PROGBITS = 0x01
    SEC_TYPE_STRTAB = 0x03
    SEC_TYPE_NOBITS = 0x08  # e.g. .bss section
    SEC_TYPE_INITARRAY = 0x0E
    SEC_TYPE_FINIARRAY = 0x0F

    PROG_SEC_TYPES = (SEC_TYPE_PROGBITS, SEC_TYPE_INITARRAY, SEC_TYPE_FINIARRAY)

    LEN_SEC_HEADER = 0x28

    SEG_TYPE_LOAD = 0x01
    LEN_SEG_HEADER = 0x20

    def __init__(self, data):
        self.data, self.name = get_bytes(data)
        f = io.BytesIO(self.data)
        self._read_elf_file(f)

    def get_section(self, section_name):
        for s in self.sections:
            if s.name == section_name:
                return s
        raise ValueError("No section %s in ELF file" % section_name)

    def _read_elf_file(self, f):
        # read the ELF file header
        LEN_FILE_HEADER = 0x34
        source = "Image" if self.name is None else f"'{self.name}'"
        try:
            (
                ident,
                _type,
                machine,
                _version,
                self.entrypoint,
                _phoff,
                shoff,
                _flags,
                _ehsize,
                _phentsize,
                _phnum,
                shentsize,
                shnum,
                shstrndx,
            ) = struct.unpack("<16sHHLLLLLHHHHHH", f.read(LEN_FILE_HEADER))

        except struct.error as e:
            raise FatalError(f"{source} does not have a valid ELF header: {e}")
        if byte(ident, 0) != 0x7F or ident[1:4] != b"ELF":
            raise FatalError(f"{source} has invalid ELF magic header")
        if machine not in [0x5E, 0xF3]:
            raise FatalError(
                f"{source} does not appear to be an Xtensa or an RISCV ELF image. "
                f"(e_machine = {machine:#06x})"
            )
        if shentsize != self.LEN_SEC_HEADER:
            raise FatalError(
                f"{source} has unexpected section header entry size {shentsize:#x} "
                f"(not {self.LEN_SEC_HEADER:#x})"
            )
        if shnum == 0:
            raise FatalError(f"{source} has 0 section headers")
        self._read_sections(f, shoff, shnum, shstrndx)
        self._read_segments(f, _phoff, _phnum, shstrndx)

    def _read_sections(self, f, section_header_offs, section_header_count, shstrndx):
        f.seek(section_header_offs)
        len_bytes = section_header_count * self.LEN_SEC_HEADER
        section_header = f.read(len_bytes)
        if len(section_header) == 0:
            raise FatalError(
                f"No section header found at offset {section_header_offs:#06x} "
                "in ELF image."
            )
        if len(section_header) != (len_bytes):
            raise FatalError(
                f"Only read {len(section_header):#x} bytes from section header "
                f"(expected {len_bytes:#x}). Truncated ELF image?"
            )

        # walk through the section header and extract all sections
        section_header_offsets = range(0, len(section_header), self.LEN_SEC_HEADER)

        def read_section_header(offs):
            (
                name_offs,
                sec_type,
                _flags,
                lma,
                sec_offs,
                size,
                _,
                _,
                align,
            ) = struct.unpack_from("<LLLLLLLLL", section_header[offs:])
            return (name_offs, sec_type, lma, size, sec_offs, _flags, align)

        all_sections = [read_section_header(offs) for offs in section_header_offsets]
        prog_sections = [s for s in all_sections if s[1] in ELFFile.PROG_SEC_TYPES]
        nobits_secitons = [s for s in all_sections if s[1] == ELFFile.SEC_TYPE_NOBITS]

        # search for the string table section
        if (shstrndx * self.LEN_SEC_HEADER) not in section_header_offsets:
            raise FatalError(f"ELF file has no STRTAB section at shstrndx {shstrndx}")
        _, sec_type, _, sec_size, sec_offs, _flags, align = read_section_header(
            shstrndx * self.LEN_SEC_HEADER
        )
        if sec_type != ELFFile.SEC_TYPE_STRTAB:
            log.warning(f"ELF file has incorrect STRTAB section type {sec_type:#04x}")
        f.seek(sec_offs)
        string_table = f.read(sec_size)

        # build the real list of ELFSections by reading the actual section names from
        # the string table section, and actual data for each section
        # from the ELF file itself
        def lookup_string(offs):
            raw = string_table[offs:]
            return raw[: raw.index(b"\x00")]

        def read_data(offs, size):
            f.seek(offs)
            return f.read(size)

        prog_sections = [
            ELFSection(
                lookup_string(n_offs),
                lma,
                read_data(offs, size),
                flags=_flags,
                align=align,
            )
            for (n_offs, _type, lma, size, offs, _flags, align) in prog_sections
            if lma != 0 and size > 0
        ]
        self.sections = prog_sections
        self.nobits_sections = [
            ELFSection(lookup_string(n_offs), lma, b"", flags=_flags, align=align)
            for (n_offs, _type, lma, size, offs, _flags, align) in nobits_secitons
            if lma != 0 and size > 0
        ]

    def _read_segments(self, f, segment_header_offs, segment_header_count, shstrndx):
        f.seek(segment_header_offs)
        len_bytes = segment_header_count * self.LEN_SEG_HEADER
        segment_header = f.read(len_bytes)
        if len(segment_header) == 0:
            raise FatalError(
                f"No segment header found at offset {segment_header_offs:#06x} "
                "in ELF image."
            )
        if len(segment_header) != (len_bytes):
            raise FatalError(
                f"Only read {len(segment_header):#x} bytes from segment header "
                f"(expected {len_bytes:#x}). Truncated ELF image?"
            )

        # walk through the segment header and extract all segments
        segment_header_offsets = range(0, len(segment_header), self.LEN_SEG_HEADER)

        def read_segment_header(offs):
            (
                seg_type,
                seg_offs,
                _vaddr,
                lma,
                size,
                _memsize,
                _flags,
                _align,
            ) = struct.unpack_from("<LLLLLLLL", segment_header[offs:])
            return (seg_type, lma, size, seg_offs, _flags, _align)

        all_segments = [read_segment_header(offs) for offs in segment_header_offsets]
        prog_segments = [s for s in all_segments if s[0] == ELFFile.SEG_TYPE_LOAD]

        def read_data(offs, size):
            f.seek(offs)
            return f.read(size)

        prog_segments = [
            ELFSection(b"PHDR", lma, read_data(offs, size), flags=_flags, align=_align)
            for (_type, lma, size, offs, _flags, _align) in prog_segments
            if lma != 0 and size > 0
        ]
        self.segments = prog_segments

    def sha256(self):
        # return SHA256 hash of the input ELF file
        sha256 = hashlib.sha256()
        f = io.BytesIO(self.data)
        sha256.update(f.read())
        return sha256.digest()
