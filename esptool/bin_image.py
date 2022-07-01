# SPDX-FileCopyrightText: 2014-2022 Fredrik Ahlberg, Angus Gratton,
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

from .loader import ESPLoader
from .targets import (
    ESP32C2ROM,
    ESP32C3ROM,
    ESP32C6BETAROM,
    ESP32C6ROM,
    ESP32H2BETA1ROM,
    ESP32H2BETA2ROM,
    ESP32ROM,
    ESP32S2ROM,
    ESP32S3BETA2ROM,
    ESP32S3ROM,
    ESP8266ROM,
)
from .util import FatalError, byte, pad_to


def align_file_position(f, size):
    """Align the position in the file to the next block of specified size"""
    align = (size - 1) - (f.tell() % size)
    f.seek(align, 1)


def LoadFirmwareImage(chip, image_file):
    """
    Load a firmware image. Can be for any supported SoC.

    ESP8266 images will be examined to determine if they are original ROM firmware
    images (ESP8266ROMFirmwareImage) or "v2" OTA bootloader images.

    Returns a BaseFirmwareImage subclass, either ESP8266ROMFirmwareImage (v1)
    or ESP8266V2FirmwareImage (v2).
    """

    def select_image_class(f, chip):
        chip = re.sub(r"[-()]", "", chip.lower())
        if chip != "esp8266":
            return {
                "esp32": ESP32FirmwareImage,
                "esp32s2": ESP32S2FirmwareImage,
                "esp32s3beta2": ESP32S3BETA2FirmwareImage,
                "esp32s3": ESP32S3FirmwareImage,
                "esp32c3": ESP32C3FirmwareImage,
                "esp32c6beta": ESP32C6BETAFirmwareImage,
                "esp32h2beta1": ESP32H2BETA1FirmwareImage,
                "esp32h2beta2": ESP32H2BETA2FirmwareImage,
                "esp32c2": ESP32C2FirmwareImage,
                "esp32c6": ESP32C6FirmwareImage,
            }[chip](f)
        else:  # Otherwise, ESP8266 so look at magic to determine the image type
            magic = ord(f.read(1))
            f.seek(0)
            if magic == ESPLoader.ESP_IMAGE_MAGIC:
                return ESP8266ROMFirmwareImage(f)
            elif magic == ESP8266V2FirmwareImage.IMAGE_V2_MAGIC:
                return ESP8266V2FirmwareImage(f)
            else:
                raise FatalError("Invalid image magic number: %d" % magic)

    if isinstance(image_file, str):
        with open(image_file, "rb") as f:
            return select_image_class(f, chip)
    return select_image_class(image_file, chip)


class ImageSegment(object):
    """Wrapper class for a segment in an ESP image
    (very similar to a section in an ELFImage also)"""

    def __init__(self, addr, data, file_offs=None):
        self.addr = addr
        self.data = data
        self.file_offs = file_offs
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


class ELFSection(ImageSegment):
    """Wrapper class for a section in an ELF image, has a section
    name as well as the common properties of an ImageSegment."""

    def __init__(self, name, addr, data):
        super(ELFSection, self).__init__(addr, data)
        self.name = name.decode("utf-8")

    def __repr__(self):
        return "%s %s" % (self.name, super(ELFSection, self).__repr__())


class BaseFirmwareImage(object):
    SEG_HEADER_LEN = 8
    SHA256_DIGEST_LEN = 32

    """ Base class with common firmware image functions """

    def __init__(self):
        self.segments = []
        self.entrypoint = 0
        self.elf_sha256 = None
        self.elf_sha256_offset = 0

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
                print("WARNING: Suspicious segment 0x%x, length %d" % (offset, size))

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

    def save_segment(self, f, segment, checksum=None):
        """
        Save the next segment to the image file,
        return next checksum value if provided
        """
        segment_data = self.maybe_patch_segment_data(f, segment.data)
        f.write(struct.pack("<II", segment.addr, len(segment_data)))
        f.write(segment_data)
        if checksum is not None:
            return ESPLoader.checksum(segment_data, checksum)

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
        """
        If supported, this should be overridden by the chip-specific class.
        Gets called in elf2image.
        """
        print(
            "WARNING: Changing MMU page size is not supported on {}! "
            "Defaulting to 64KB.".format(self.ROM_LOADER.CHIP_NAME)
        )


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

    def save(self, basename):
        """Save a set of V1 images for flashing. Parameter is a base filename."""
        # IROM data goes in its own plain binary file
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            with open(
                "%s0x%05x.bin"
                % (basename, irom_segment.addr - ESP8266ROM.IROM_MAP_START),
                "wb",
            ) as f:
                f.write(irom_segment.data)

        # everything but IROM goes at 0x00000 in an image file
        normal_segments = self.get_non_irom_segments()
        with open("%s0x00000.bin" % basename, "wb") as f:
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


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
                print(
                    'Warning: V2 header has unexpected "segment" count %d (usually 4)'
                    % segments
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
                print(
                    "WARNING: Flash mode value in first header (0x%02x) disagrees "
                    "with second (0x%02x). Using second value."
                    % (first_flash_mode, self.flash_mode)
                )
            if first_flash_size_freq != self.flash_size_freq:
                print(
                    "WARNING: Flash size/freq value in first header (0x%02x) disagrees "
                    "with second (0x%02x). Using second value."
                    % (first_flash_size_freq, self.flash_size_freq)
                )
            if first_entrypoint != self.entrypoint:
                print(
                    "WARNING: Entrypoint address in first header (0x%08x) disagrees "
                    "with second header (0x%08x). Using second value."
                    % (first_entrypoint, self.entrypoint)
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

    def save(self, filename):
        with open(filename, "wb") as f:
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

        # calculate a crc32 of entire file and append
        # (algorithm used by recent 8266 SDK bootloaders)
        with open(filename, "rb") as f:
            crc = esp8266_crc32(f.read())
        with open(filename, "ab") as f:
            f.write(struct.pack(b"<I", crc))


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
    can be placed in the normal image (just @ 64kB padded offsets).
    """

    ROM_LOADER = ESP32ROM

    # ROM bootloader will read the wp_pin field if SPI flash
    # pins are remapped via flash. IDF actually enables QIO only
    # from software bootloader, so this can be ignored. But needs
    # to be set to this value so ROM bootloader will skip it.
    WP_PIN_DISABLED = 0xEE

    EXTENDED_HEADER_STRUCT_FMT = "<BBBBHBHH" + ("B" * 4) + "B"

    IROM_ALIGN = 65536

    def __init__(self, load_file=None, append_digest=True):
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

        self.append_digest = append_digest

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

    def save(self, filename):
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

            # Patch to support 761 union bus memmap     // TODO: ESPTOOL-512
            # move ".flash.appdesc" segment to the top of the flash segment
            for segment in flash_segments:
                if segment.name == ".flash.appdesc":
                    flash_segments.remove(segment)
                    flash_segments.insert(0, segment)
                    break

            # check for multiple ELF sections that are mapped in the same
            # flash mapping region. This is usually a sign of a broken linker script,
            # but if you have a legitimate use case then let us know
            if len(flash_segments) > 0:
                last_addr = flash_segments[0].addr
                for segment in flash_segments[1:]:
                    if segment.addr // self.IROM_ALIGN == last_addr // self.IROM_ALIGN:
                        raise FatalError(
                            "Segment loaded at 0x%08x lands in same 64KB flash mapping "
                            "as segment loaded at 0x%08x. Can't generate binary. "
                            "Suggest changing linker script or ELF to merge sections."
                            % (segment.addr, last_addr)
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

            # try to fit each flash segment on a 64kB aligned boundary
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
                    checksum = self.save_segment(f, pad_segment, checksum)
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
                checksum = self.save_segment(f, segment, checksum)
                total_segments += 1

            if self.secure_pad:
                # pad the image so that after signing it will end on a a 64KB boundary.
                # This ensures all mapped flash content will be verified.
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
                    # but we place signature sector after the 64KB boundary
                    space_after_checksum = 32
                pad_len = (
                    self.IROM_ALIGN - align_past - checksum_space - space_after_checksum
                ) % self.IROM_ALIGN
                pad_segment = ImageSegment(0, b"\x00" * pad_len, f.tell())

                checksum = self.save_segment(f, pad_segment, checksum)
                total_segments += 1

            # done writing segments
            self.append_checksum(f, checksum)
            image_length = f.tell()

            if self.secure_pad:
                assert ((image_length + space_after_checksum) % self.IROM_ALIGN) == 0

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

            with open(filename, "wb") as real_file:
                real_file.write(f.getvalue())

    def save_flash_segment(self, f, segment, checksum=None):
        """
        Save the next segment to the image file, return next checksum value if provided
        """
        segment_end_pos = f.tell() + len(segment.data) + self.SEG_HEADER_LEN
        segment_len_remainder = segment_end_pos % self.IROM_ALIGN
        if segment_len_remainder < 0x24:
            # Work around a bug in ESP-IDF 2nd stage bootloader, that it didn't map the
            # last MMU page, if an IROM/DROM segment was < 0x24 bytes
            # over the page boundary.
            segment.data += b"\x00" * (0x24 - segment_len_remainder)
        return self.save_segment(f, segment, checksum)

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
            print(
                (
                    "Unexpected chip id in image. Expected %d but value was %d. "
                    "Is this image for a different chip model?"
                )
                % (self.ROM_LOADER.IMAGE_CHIP_ID, self.chip_id)
            )

        self.min_rev = fields[5]
        self.min_rev_full = fields[6]
        self.max_rev_full = fields[7]

        # reserved fields in the middle should all be zero
        if any(f for f in fields[8:-1] if f != 0):
            print(
                "Warning: some reserved header fields have non-zero values. "
                "This image may be from a newer esptool.py?"
            )

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

    def save(self, filename):
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
                            "Segment loaded at 0x%08x lands in same 64KB flash mapping "
                            "as segment loaded at 0x%08x. Can't generate binary. "
                            "Suggest changing linker script or ELF to merge sections."
                            % (segment.addr, last_addr)
                        )
                    last_addr = segment.addr

            # try to fit each flash segment on a 64kB aligned boundary
            # by padding with parts of the non-flash segments...
            while len(flash_segments) > 0:
                segment = flash_segments[0]
                # remove 8 bytes empty data for insert segment header
                if segment.name == ".flash.rodata":
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

            with open(filename, "wb") as real_file:
                real_file.write(f.getvalue())

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
            print(
                "Warning: some reserved header fields have non-zero values. "
                "This image may be from a newer esptool.py?"
            )


ESP32ROM.BOOTLOADER_IMAGE = ESP32FirmwareImage


class ESP32S2FirmwareImage(ESP32FirmwareImage):
    """ESP32S2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32S2ROM


ESP32S2ROM.BOOTLOADER_IMAGE = ESP32S2FirmwareImage


class ESP32S3BETA2FirmwareImage(ESP32FirmwareImage):
    """ESP32S3 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32S3BETA2ROM


ESP32S3BETA2ROM.BOOTLOADER_IMAGE = ESP32S3BETA2FirmwareImage


class ESP32S3FirmwareImage(ESP32FirmwareImage):
    """ESP32S3 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32S3ROM


ESP32S3ROM.BOOTLOADER_IMAGE = ESP32S3FirmwareImage


class ESP32C3FirmwareImage(ESP32FirmwareImage):
    """ESP32C3 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C3ROM


ESP32C3ROM.BOOTLOADER_IMAGE = ESP32C3FirmwareImage


class ESP32C6BETAFirmwareImage(ESP32FirmwareImage):
    """ESP32C6 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C6BETAROM


ESP32C6BETAROM.BOOTLOADER_IMAGE = ESP32C6BETAFirmwareImage


class ESP32H2BETA1FirmwareImage(ESP32FirmwareImage):
    """ESP32H2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32H2BETA1ROM


ESP32H2BETA1ROM.BOOTLOADER_IMAGE = ESP32H2BETA1FirmwareImage


class ESP32H2BETA2FirmwareImage(ESP32FirmwareImage):
    """ESP32H2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32H2BETA2ROM


ESP32H2BETA2ROM.BOOTLOADER_IMAGE = ESP32H2BETA2FirmwareImage


class ESP32C2FirmwareImage(ESP32FirmwareImage):
    """ESP32C2 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C2ROM

    def set_mmu_page_size(self, size):
        if size not in [16384, 32768, 65536]:
            raise FatalError(
                "{} bytes is not a valid ESP32-C2 page size, "
                "select from 64KB, 32KB, 16KB.".format(size)
            )
        self.IROM_ALIGN = size


ESP32C2ROM.BOOTLOADER_IMAGE = ESP32C2FirmwareImage


class ESP32C6FirmwareImage(ESP32FirmwareImage):
    """ESP32C6 Firmware Image almost exactly the same as ESP32FirmwareImage"""

    ROM_LOADER = ESP32C6ROM

    def set_mmu_page_size(self, size):
        if size not in [8192, 16384, 32768, 65536]:
            raise FatalError(
                "{} bytes is not a valid ESP32-C6 page size, "
                "select from 64KB, 32KB, 16KB, 8KB.".format(size)
            )
        self.IROM_ALIGN = size


ESP32C6ROM.BOOTLOADER_IMAGE = ESP32C6FirmwareImage


class ELFFile(object):
    SEC_TYPE_PROGBITS = 0x01
    SEC_TYPE_STRTAB = 0x03
    SEC_TYPE_INITARRAY = 0x0E
    SEC_TYPE_FINIARRAY = 0x0F

    PROG_SEC_TYPES = (SEC_TYPE_PROGBITS, SEC_TYPE_INITARRAY, SEC_TYPE_FINIARRAY)

    LEN_SEC_HEADER = 0x28

    SEG_TYPE_LOAD = 0x01
    LEN_SEG_HEADER = 0x20

    def __init__(self, name):
        # Load sections from the ELF file
        self.name = name
        with open(self.name, "rb") as f:
            self._read_elf_file(f)

    def get_section(self, section_name):
        for s in self.sections:
            if s.name == section_name:
                return s
        raise ValueError("No section %s in ELF file" % section_name)

    def _read_elf_file(self, f):
        # read the ELF file header
        LEN_FILE_HEADER = 0x34
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
            raise FatalError(
                "Failed to read a valid ELF header from %s: %s" % (self.name, e)
            )

        if byte(ident, 0) != 0x7F or ident[1:4] != b"ELF":
            raise FatalError("%s has invalid ELF magic header" % self.name)
        if machine not in [0x5E, 0xF3]:
            raise FatalError(
                "%s does not appear to be an Xtensa or an RISCV ELF file. "
                "e_machine=%04x" % (self.name, machine)
            )
        if shentsize != self.LEN_SEC_HEADER:
            raise FatalError(
                "%s has unexpected section header entry size 0x%x (not 0x%x)"
                % (self.name, shentsize, self.LEN_SEC_HEADER)
            )
        if shnum == 0:
            raise FatalError("%s has 0 section headers" % (self.name))
        self._read_sections(f, shoff, shnum, shstrndx)
        self._read_segments(f, _phoff, _phnum, shstrndx)

    def _read_sections(self, f, section_header_offs, section_header_count, shstrndx):
        f.seek(section_header_offs)
        len_bytes = section_header_count * self.LEN_SEC_HEADER
        section_header = f.read(len_bytes)
        if len(section_header) == 0:
            raise FatalError(
                "No section header found at offset %04x in ELF file."
                % section_header_offs
            )
        if len(section_header) != (len_bytes):
            raise FatalError(
                "Only read 0x%x bytes from section header (expected 0x%x.) "
                "Truncated ELF file?" % (len(section_header), len_bytes)
            )

        # walk through the section header and extract all sections
        section_header_offsets = range(0, len(section_header), self.LEN_SEC_HEADER)

        def read_section_header(offs):
            name_offs, sec_type, _flags, lma, sec_offs, size = struct.unpack_from(
                "<LLLLLL", section_header[offs:]
            )
            return (name_offs, sec_type, lma, size, sec_offs)

        all_sections = [read_section_header(offs) for offs in section_header_offsets]
        prog_sections = [s for s in all_sections if s[1] in ELFFile.PROG_SEC_TYPES]

        # search for the string table section
        if not (shstrndx * self.LEN_SEC_HEADER) in section_header_offsets:
            raise FatalError("ELF file has no STRTAB section at shstrndx %d" % shstrndx)
        _, sec_type, _, sec_size, sec_offs = read_section_header(
            shstrndx * self.LEN_SEC_HEADER
        )
        if sec_type != ELFFile.SEC_TYPE_STRTAB:
            print(
                "WARNING: ELF file has incorrect STRTAB section type 0x%02x" % sec_type
            )
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
            ELFSection(lookup_string(n_offs), lma, read_data(offs, size))
            for (n_offs, _type, lma, size, offs) in prog_sections
            if lma != 0 and size > 0
        ]
        self.sections = prog_sections

    def _read_segments(self, f, segment_header_offs, segment_header_count, shstrndx):
        f.seek(segment_header_offs)
        len_bytes = segment_header_count * self.LEN_SEG_HEADER
        segment_header = f.read(len_bytes)
        if len(segment_header) == 0:
            raise FatalError(
                "No segment header found at offset %04x in ELF file."
                % segment_header_offs
            )
        if len(segment_header) != (len_bytes):
            raise FatalError(
                "Only read 0x%x bytes from segment header (expected 0x%x.) "
                "Truncated ELF file?" % (len(segment_header), len_bytes)
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
            return (seg_type, lma, size, seg_offs)

        all_segments = [read_segment_header(offs) for offs in segment_header_offsets]
        prog_segments = [s for s in all_segments if s[0] == ELFFile.SEG_TYPE_LOAD]

        def read_data(offs, size):
            f.seek(offs)
            return f.read(size)

        prog_segments = [
            ELFSection(b"PHDR", lma, read_data(offs, size))
            for (_type, lma, size, offs) in prog_segments
            if lma != 0 and size > 0
        ]
        self.segments = prog_segments

    def sha256(self):
        # return SHA256 hash of the input ELF file
        sha256 = hashlib.sha256()
        with open(self.name, "rb") as f:
            sha256.update(f.read())
        return sha256.digest()
