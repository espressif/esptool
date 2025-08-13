import hashlib
import os
import os.path
import re
import struct
import subprocess
import sys
import math

from conftest import need_to_install_package_err

from elftools.elf.elffile import ELFFile

import pytest

TEST_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "elf2image")

try:
    import esptool
except ImportError:
    need_to_install_package_err()


def try_delete(path):
    try:
        os.remove(path)
    except OSError:
        pass


def segment_matches_section(segment, section):
    """segment is an ImageSegment from an esptool binary.
    section is an elftools ELF section

    Returns True if they match
    """
    sh_size = (section.header.sh_size + 0x3) & ~3  # pad length of ELF sections
    return section.header.sh_addr == segment.addr and sh_size == len(segment.data)


@pytest.mark.host_test
class BaseTestCase:
    @classmethod
    def setup_class(self):
        # Save the current working directory to be restored later
        self.stored_dir = os.getcwd()
        os.chdir(TEST_DIR)

    @classmethod
    def teardown_class(self):
        # Restore the stored working directory
        os.chdir(self.stored_dir)

    def assertEqualHex(self, expected, actual, message=None):
        try:
            expected = hex(expected)
        except TypeError:  # if expected is character
            expected = hex(ord(expected))
        try:
            actual = hex(actual)
        except TypeError:  # if actual is character
            actual = hex(ord(actual))
        assert expected == actual, message

    def assertImageDoesNotContainSection(self, image, elf, section_name):
        """
        Assert an esptool binary image object does not
        contain the data for a particular ELF section.
        """
        with open(elf, "rb") as f:
            e = ELFFile(f)
            section = e.get_section_by_name(section_name)
            assert section, f"{section_name} should be in the ELF"
            sh_addr = section.header.sh_addr
            data = section.data()
            # no section should start at the same address as the ELF section.
            for seg in sorted(image.segments, key=lambda s: s.addr):
                print(
                    f"comparing seg {seg.addr:#x} sec {sh_addr:#x} len {len(data):#x}"
                )
                assert seg.addr != sh_addr, (
                    f"{section_name} should not be in the binary image"
                )

    def assertImageContainsSection(self, image, elf, section_name):
        """
        Assert an esptool binary image object contains
        the data for a particular ELF section.
        """
        with open(elf, "rb") as f:
            e = ELFFile(f)
            section = e.get_section_by_name(section_name)
            assert section, f"{section_name} should be in the ELF"
            sh_addr = section.header.sh_addr
            data = section.data()
            # section contents may be smeared across multiple image segments,
            # so look through each segment and remove it from ELF section 'data'
            # as we find it in the image segments. When we're done 'data' should
            # all be accounted for
            for seg in sorted(image.segments, key=lambda s: s.addr):
                print(
                    f"comparing seg {seg.addr:#x} sec {sh_addr:#x} len {len(data):#x}"
                )
                if seg.addr == sh_addr:
                    overlap_len = min(len(seg.data), len(data))
                    assert data[:overlap_len] == seg.data[:overlap_len], (
                        f"ELF '{section_name}' section has mis-matching bin image data"
                    )
                    sh_addr += overlap_len
                    data = data[overlap_len:]

            # no bytes in 'data' should be left unmatched
            assert len(data) == 0, (
                f"ELF {elf} section '{section_name}' has no encompassing"
                f" segment(s) in bin image (image segments: {image.segments})"
            )

    def assertImageInfo(self, binpath, chip="esp8266", assert_sha=False):
        """
        Run esptool image-info on a binary file,
        assert no red flags about contents.
        """
        cmd = [sys.executable, "-m", "esptool", "--chip", chip, "image-info", binpath]
        try:
            output = subprocess.check_output(cmd)
            output = output.decode("utf-8")
            print(output)
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise
        assert re.search(r"Checksum: 0x[a-fA-F0-9]{2} \(valid\)", output), (
            "Checksum calculation should be valid"
        )
        if assert_sha:
            assert re.search(r"Validation hash: [a-fA-F0-9]{64} \(valid\)", output), (
                "SHA256 should be valid"
            )
        assert "warning" not in output.lower(), (
            "Should be no warnings in image-info output"
        )

    def run_elf2image(
        self, chip, elf_path, version=None, extra_args=[], allow_warnings=False
    ):
        """Run elf2image on elf_path"""
        cmd = [sys.executable, "-m", "esptool", "--chip", chip, "elf2image"]
        if version is not None:
            cmd += ["--version", str(version)]
        cmd += [elf_path] + extra_args
        print("\nExecuting {}".format(" ".join(cmd)))
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            output = output.decode("utf-8")
            print(output)
            if not allow_warnings:
                assert "warning" not in output.lower(), (
                    "elf2image should not output warnings"
                )
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

    @staticmethod
    def assertAllFF(some_bytes):
        """Assert that the given bytes are all 0xFF (erased flash state)"""
        assert b"\xff" * len(some_bytes) == some_bytes, (
            "Expected all 0xFF bytes, but found different values"
        )


class TestESP8266V1Image(BaseTestCase):
    ELF = "esp8266-nonosssdk20-iotdemo.elf"
    BIN_LOAD = "esp8266-nonosssdk20-iotdemo.elf-0x00000.bin"
    BIN_IROM = "esp8266-nonosssdk20-iotdemo.elf-0x10000.bin"

    @classmethod
    def setup_class(self):
        super().setup_class()
        self.run_elf2image(self, "esp8266", self.ELF, 1)

    @classmethod
    def teardown_class(self):
        try_delete(self.BIN_LOAD)
        try_delete(self.BIN_IROM)
        super().teardown_class()

    def test_irom_bin(self):
        with open(self.ELF, "rb") as f:
            e = ELFFile(f)
            irom_section = e.get_section_by_name(".irom0.text")
            assert irom_section.header.sh_size == os.stat(self.BIN_IROM).st_size, (
                "IROM raw binary file should be same length as .irom0.text section"
            )

    def test_loaded_sections(self):
        image = esptool.bin_image.LoadFirmwareImage("esp8266", self.BIN_LOAD)
        # Adjacent sections are now merged, len(image.segments) should
        # equal 2 (instead of 3).
        assert len(image.segments) == 2
        self.assertImageContainsSection(image, self.ELF, ".data")
        self.assertImageContainsSection(image, self.ELF, ".text")
        # Section .rodata is merged in the binary with the previous one,
        # so it won't be found in the binary image.
        self.assertImageDoesNotContainSection(image, self.ELF, ".rodata")


class TestESP8266V12SectionHeaderNotAtEnd(BaseTestCase):
    """Ref https://github.com/espressif/esptool/issues/197 -
    this ELF image has the section header not at the end of the file"""

    ELF = "esp8266-nonossdkv12-example.elf"
    BIN_LOAD = ELF + "-0x00000.bin"
    BIN_IROM = ELF + "-0x40000.bin"

    @classmethod
    def teardown_class(self):
        try_delete(self.BIN_LOAD)
        try_delete(self.BIN_IROM)

    def test_elf_section_header_not_at_end(self):
        self.run_elf2image("esp8266", self.ELF)
        image = esptool.bin_image.LoadFirmwareImage("esp8266", self.BIN_LOAD)
        assert len(image.segments) == 3
        self.assertImageContainsSection(image, self.ELF, ".data")
        self.assertImageContainsSection(image, self.ELF, ".text")
        self.assertImageContainsSection(image, self.ELF, ".rodata")


class TestESP8266V2Image(BaseTestCase):
    def _test_elf2image(self, elfpath, binpath, mergedsections=[]):
        try:
            self.run_elf2image("esp8266", elfpath, 2)
            image = esptool.bin_image.LoadFirmwareImage("esp8266", binpath)
            print("In test_elf2image", len(image.segments))
            assert 4 - len(mergedsections) == len(image.segments)
            sections = [".data", ".text", ".rodata"]
            # Remove the merged sections from the `sections` list
            sections = [sec for sec in sections if sec not in mergedsections]
            for sec in sections:
                self.assertImageContainsSection(image, elfpath, sec)
            for sec in mergedsections:
                self.assertImageDoesNotContainSection(image, elfpath, sec)

            irom_segment = image.segments[0]
            assert irom_segment.addr == 0, "IROM segment 'load address' should be zero"
            with open(elfpath, "rb") as f:
                e = ELFFile(f)
                sh_size = (
                    e.get_section_by_name(".irom0.text").header.sh_size + 15
                ) & ~15
                assert len(irom_segment.data) == sh_size, (
                    f"irom segment ({len(irom_segment.data):#x}) should be same size "
                    f"(16 padded) as .irom0.text section ({sh_size:#x})"
                )

            # check V2 CRC (for ESP8266 SDK bootloader)
            with open(binpath, "rb") as f:
                f.seek(-4, os.SEEK_END)
                image_len = f.tell()
                crc_stored = struct.unpack("<I", f.read(4))[0]
                f.seek(0)
                crc_calc = esptool.bin_image.esp8266_crc32(f.read(image_len))
                assert crc_stored == crc_calc

            # test imageinfo doesn't fail
            self.assertImageInfo(binpath)

        finally:
            try_delete(binpath)

    def test_nonossdkimage(self):
        ELF = "esp8266-nonossdkv20-at-v2.elf"
        BIN = "esp8266-nonossdkv20-at-v2-0x01000.bin"
        self._test_elf2image(ELF, BIN)

    def test_espopenrtosimage(self):
        ELF = "esp8266-openrtos-blink-v2.elf"
        BIN = "esp8266-openrtos-blink-v2-0x02000.bin"
        # .rodata section is merged with the previous one: .data
        self._test_elf2image(ELF, BIN, [".rodata"])


class TestESP32Image(BaseTestCase):
    def _test_elf2image(self, elfpath, binpath, extra_args=[]):
        try:
            self.run_elf2image("esp32", elfpath, extra_args=extra_args)
            image = esptool.bin_image.LoadFirmwareImage("esp32", binpath)
            self.assertImageInfo(
                binpath,
                "esp32",
                True if "--ram-only-header" not in extra_args else False,
            )
            return image
        finally:
            try_delete(binpath)

    def test_bootloader(self):
        ELF = "esp32-bootloader.elf"
        BIN = "esp32-bootloader.bin"
        image = self._test_elf2image(ELF, BIN)
        assert len(image.segments) == 3
        for section in [".iram1.text", ".iram_pool_1.text", ".dram0.rodata"]:
            self.assertImageContainsSection(image, ELF, section)

    def test_app_template(self):
        ELF = "esp32-app-template.elf"
        BIN = "esp32-app-template.bin"
        image = self._test_elf2image(ELF, BIN)
        # Adjacent sections are now merged, len(image.segments) should
        # equal 5 (instead of 6).
        assert len(image.segments) == 5
        # the other segment is a padding or merged segment
        for section in [
            ".iram0.vectors",
            ".dram0.data",
            ".flash.rodata",
            ".flash.text",
        ]:
            self.assertImageContainsSection(image, ELF, section)
        # check that merged sections are not in the binary image
        for mergedsection in [".iram0.text"]:
            self.assertImageDoesNotContainSection(image, ELF, mergedsection)

    def test_too_many_sections(self, capsys):
        ELF = "esp32-too-many-sections.elf"
        BIN = "esp32-too-many-sections.bin"
        with pytest.raises(subprocess.CalledProcessError):
            self._test_elf2image(ELF, BIN)
        output = capsys.readouterr().out
        assert "max 16" in output
        assert "linker script" in output

    def test_use_segments(self):
        ELF = "esp32-zephyr.elf"
        BIN = "esp32-zephyr.bin"
        # default behaviour uses ELF sections,
        # this ELF will produce 8 segments in the bin
        image = self._test_elf2image(ELF, BIN)
        # Adjacent sections are now merged, len(image.segments) should
        # equal 4 (instead of 8).
        assert len(image.segments) == 4

        # --use-segments uses ELF segments(phdrs), produces just 2 segments in the bin
        image = self._test_elf2image(ELF, BIN, ["--use-segments"])
        assert len(image.segments) == 2

    def test_ram_only_header(self):
        ELF = "esp32-app-template.elf"
        BIN = "esp32-app-template.bin"
        # --ram-only-header produces just 2 visible segments in the bin
        image = self._test_elf2image(ELF, BIN, ["--ram-only-header"])
        assert len(image.segments) == 2

    @pytest.fixture(scope="class")
    def reference_bin(self):
        BASE_NAME = "esp32-bootloader"
        BIN = f"{BASE_NAME}-reference.bin"
        self.run_elf2image("esp32", f"{BASE_NAME}.elf")
        os.rename(f"{BASE_NAME}.bin", BIN)
        yield BIN
        # Cleanup the reference binary after the test
        try_delete(BIN)

    def test_pad_to_size(self, reference_bin: str):
        """Test that --pad-to-size correctly pads output binary to specified size"""
        ELF = "esp32-bootloader.elf"
        BIN = "esp32-bootloader.bin"

        try:
            # Generate the padded binary with 1MB size
            self.run_elf2image("esp32", ELF, extra_args=["--pad-to-size", "1MB"])

            # Get the size of the reference binary
            normal_size = os.path.getsize(reference_bin)

            # Check that the padded binary is exactly 1MB
            padded_size = os.path.getsize(BIN)
            expected_size = 0x100000  # 1MB in bytes
            assert padded_size == expected_size, (
                f"Expected {expected_size} bytes (1MB), got {padded_size} bytes"
            )

            # Check that the original content is preserved at the beginning
            with open(reference_bin, "rb") as f:
                original_content = f.read()
            with open(BIN, "rb") as f:
                padded_content = f.read()

            assert padded_content[:normal_size] == original_content, (
                "Original content should be preserved at the beginning of padded file"
            )

            # Check that the padding is filled with 0xFF bytes (erased flash state)
            padding = padded_content[normal_size:]
            expected_padding_size = expected_size - normal_size
            assert len(padding) == expected_padding_size, (
                f"Padding should be {expected_padding_size} bytes, got {len(padding)}"
            )
            self.assertAllFF(padding)

        finally:
            try_delete(BIN)

    @pytest.mark.parametrize("size", ["512KB", "2MB", "4MB"])
    def test_pad_to_size_different_sizes(self, size: str, reference_bin: str):
        """Test --pad-to-size with different size values"""
        ELF = "esp32-bootloader.elf"
        BIN = "esp32-bootloader.bin"

        expected_bytes = esptool.util.flash_size_bytes(size)
        try:
            # Generate the padded binary
            self.run_elf2image("esp32", ELF, extra_args=["--pad-to-size", size])

            # Check the file size
            padded_size = os.path.getsize(BIN)
            assert padded_size == expected_bytes, (
                f"Expected {expected_bytes} bytes for {size}, got {padded_size}"
            )

            # Check that padding is 0xFF
            with open(BIN, "rb") as f:
                padded_content = f.read()

            # Get original size from the normal binary and check that padding
            normal_size = os.path.getsize(reference_bin)
            self.assertAllFF(padded_content[normal_size:])

        finally:
            try_delete(BIN)


class TestESP8266FlashHeader(BaseTestCase):
    def test_2mb(self):
        ELF = "esp8266-nonossdkv20-at-v2.elf"
        BIN = "esp8266-nonossdkv20-at-v2-0x01000.bin"
        try:
            self.run_elf2image(
                "esp8266",
                ELF,
                version=2,
                extra_args=["--flash-size", "2MB", "--flash-mode", "dio"],
            )
            with open(BIN, "rb") as f:
                header = f.read(4)
                print(f"header {header}")
                self.assertEqualHex(0xEA, header[0])
                self.assertEqualHex(0x02, header[2])
                self.assertEqualHex(0x30, header[3])
        finally:
            try_delete(BIN)


class TestESP32FlashHeader(BaseTestCase):
    def test_16mb(self):
        ELF = "esp32-app-template.elf"
        BIN = "esp32-app-template.bin"
        try:
            self.run_elf2image(
                "esp32",
                ELF,
                extra_args=[
                    "--flash-size",
                    "16MB",
                    "--flash-mode",
                    "dio",
                    "--min-rev",
                    "1",
                ],
            )
            with open(BIN, "rb") as f:
                header = f.read(24)
                self.assertEqualHex(0xE9, header[0])
                self.assertEqualHex(0x02, header[2])
                self.assertEqualHex(0x40, header[3])
                self.assertEqualHex(0x01, header[14])  # chip revision
        finally:
            try_delete(BIN)


class TestELFSHA256(BaseTestCase):
    ELF = "esp32c6-appdesc.elf"
    SHA_OFFS = 0xB0  # absolute offset of the SHA in the .bin file
    BIN = "esp32c6-appdesc.bin"

    """
    esp32c6-appdesc.elf was built with the following application version info:

    __attribute__((section(".flash.appdesc")))
    esp_app_desc_t my_app_desc = {
        .magic_word = 0xABCD5432,
        .secure_version = 0xffffffff,
        .reserv1 = {0xffffffff, 0xffffffff},
        .version = "_______________________________",
        .project_name = "-------------------------------",
        .time = "xxxxxxxxxxxxxxx",
        .date = "yyyyyyyyyyyyyyy",
        .idf_ver = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        .app_elf_sha256 = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        },
        .min_efuse_blk_rev_full = 0xffff,
        .max_efuse_blk_rev_full = 0xffff,
        .mmu_page_size = 0,
        .reserv3 = {0xff, 0xff, 0xff},
        .reserv2 = {
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff
        },
    };

    This leaves zeroes only for the fields of SHA-256 and the test will fail
    if the placement of zeroes are tested at the wrong place.

    00000000: e901 0000 2000 0042 ee00 0000 0d00 0000  .... ..B........
    00000010: 00ff ff00 0000 0001 2000 0042 0001 0000  ........ ..B....
    00000020: 3254 cdab ffff ffff ffff ffff ffff ffff  2T..............
    00000030: 5f5f 5f5f 5f5f 5f5f 5f5f 5f5f 5f5f 5f5f  ________________
    00000040: 5f5f 5f5f 5f5f 5f5f 5f5f 5f5f 5f5f 5f00  _______________.
    00000050: 2d2d 2d2d 2d2d 2d2d 2d2d 2d2d 2d2d 2d2d  ----------------
    00000060: 2d2d 2d2d 2d2d 2d2d 2d2d 2d2d 2d2d 2d00  ---------------.
    00000070: 7878 7878 7878 7878 7878 7878 7878 7800  xxxxxxxxxxxxxxx.
    00000080: 7979 7979 7979 7979 7979 7979 7979 7900  yyyyyyyyyyyyyyy.
    00000090: 7a7a 7a7a 7a7a 7a7a 7a7a 7a7a 7a7a 7a7a  zzzzzzzzzzzzzzzz
    000000a0: 7a7a 7a7a 7a7a 7a7a 7a7a 7a7a 7a7a 7a00  zzzzzzzzzzzzzzz.
    000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................    SHA-256 here
    000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    000000d0: ffff ffff 00ff ffff ffff ffff ffff ffff  ................
    000000e0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    000000f0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    00000100: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    00000110: ffff ffff ffff ffff ffff ffff ffff ffff  ................

    """

    def verify_sha256(self, elf_path, bin_path):
        image = esptool.bin_image.LoadFirmwareImage("esp32c6", bin_path)
        rodata_segment = image.segments[0]
        bin_sha256 = rodata_segment.data[
            self.SHA_OFFS - 0x20 : self.SHA_OFFS - 0x20 + 32
        ]  # subtract 0x20 byte header here

        with open(elf_path, "rb") as f:
            elf_computed_sha256 = hashlib.sha256(f.read()).digest()

        with open(bin_path, "rb") as f:
            f.seek(self.SHA_OFFS)
            bin_sha256_raw = f.read(len(elf_computed_sha256))

        assert elf_computed_sha256 == bin_sha256
        assert elf_computed_sha256 == bin_sha256_raw

    def test_binary_patched_parameter(self):
        try:
            self.run_elf2image(
                "esp32c6",
                self.ELF,
                extra_args=["--elf-sha256-offset", f"{self.SHA_OFFS:#x}"],
            )
            self.verify_sha256(self.ELF, self.BIN)
        finally:
            try_delete(self.BIN)

    def test_binary_patched(self):
        try:
            self.run_elf2image("esp32c6", self.ELF)
            self.verify_sha256(self.ELF, self.BIN)
        finally:
            try_delete(self.BIN)

    def test_no_overwrite_data(self, capsys):
        with pytest.raises(subprocess.CalledProcessError):
            self.run_elf2image(
                "esp32",
                "esp32-bootloader.elf",
                extra_args=["--elf-sha256-offset", "0xb0"],
            )
        output = capsys.readouterr().out
        assert "SHA256" in output
        assert "zero" in output


class TestHashAppend(BaseTestCase):
    ELF = "esp32-bootloader.elf"
    BIN = "esp32-bootloader.bin"

    # 15th byte of the extended header after the 8-byte image header
    HASH_APPEND_OFFSET = 15 + 8

    @classmethod
    def teardown_class(self):
        try_delete(self.BIN)

    def test_hash_append(self):
        self.run_elf2image(
            "esp32",
            self.ELF,
            extra_args=["-o", self.BIN],
        )
        with open(self.BIN, "rb") as f:
            bin_with_hash = f.read()

        assert bin_with_hash[self.HASH_APPEND_OFFSET] == 1

        # drop the last 32 bytes (SHA256 digest)
        expected_bin_without_hash = bytearray(bin_with_hash[:-32])
        # disable the hash append byte in the file header
        expected_bin_without_hash[self.HASH_APPEND_OFFSET] = 0

        try_delete(self.BIN)
        self.run_elf2image(
            "esp32",
            self.ELF,
            extra_args=["--dont-append-digest", "-o", self.BIN],
        )

        with open(self.BIN, "rb") as f:
            bin_without_hash = f.read()

        assert bin_without_hash[self.HASH_APPEND_OFFSET] == 0
        assert bytes(expected_bin_without_hash) == bin_without_hash


class TestELFSectionHandling(BaseTestCase):
    """Test ELF section type handling and related functionality."""

    @staticmethod
    def _modify_section_type(elf_path, section_name, new_type):
        """
        Modify the type of a specific section in the ELF file.
        """
        with open(elf_path, "rb+") as f:
            elf = ELFFile(f)
            section = elf.get_section_by_name(section_name)

            index = elf.get_section_index(section_name)
            # Calculate the section header's position in the file (using section index,
            # the section header table's offset and section header entry size)
            sh_entry_offset = elf.header["e_shoff"] + index * elf.header["e_shentsize"]

            # Modify the section type in the header
            section.header.sh_type = new_type

            f.seek(sh_entry_offset)
            f.write(elf.structs.Elf_Shdr.build(section.header))

    @staticmethod
    def _get_section_type(elf_path, section_name):
        """
        Get the current type of a specific section in the ELF file.
        """
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            section = elf.get_section_by_name(section_name)
            return section.header.sh_type

    def test_unknown_section_type_warning(self, capsys):
        """Test that unknown section types generate the expected warning message."""
        ELF = "esp32c6-appdesc.elf"
        BIN = "esp32c6-appdesc.bin"
        SECTION_NAME = ".flash.appdesc"
        UNKNOWN_TYPE = 0x99

        original_sec_type = self._get_section_type(ELF, SECTION_NAME)

        # Modify the section to have an unknown type
        self._modify_section_type(ELF, SECTION_NAME, UNKNOWN_TYPE)

        # Verify the section was actually modified
        modified_type = self._get_section_type(ELF, SECTION_NAME)
        assert modified_type == UNKNOWN_TYPE

        try:
            self.run_elf2image("esp32c6", ELF, allow_warnings=True)
            output = capsys.readouterr().out
            print(output)

            expected_warning = f"Unknown section type {UNKNOWN_TYPE:#04x} in ELF file"
            assert expected_warning in output

        finally:
            self._modify_section_type(ELF, SECTION_NAME, original_sec_type)
            try_delete(BIN)


class TestMMUPageSize(BaseTestCase):
    def test_appdesc_aligned(self, capsys):
        ELF = "esp32c6-appdesc.elf"
        BIN = "esp32c6-appdesc.bin"
        try:
            self.run_elf2image("esp32c6", ELF)
            output = capsys.readouterr().out
            print(output)
            assert "MMU page size not specified, set to 64 KB" in output
        finally:
            try_delete(BIN)

    @staticmethod
    def _modify_section_address(elf_path, section_name, address_offset):
        with open(elf_path, "rb+") as f:
            elf = ELFFile(f)
            section = elf.get_section_by_name(section_name)

            if not section:
                raise ValueError(f"Section {section_name} not found")

            # This finds the index of the specified section in the ELF file,
            # compute the section header’s position in the file (using section index,
            # the section header table’s offset and section header entry size) and then
            # modify the section’s address in memory by the specified offset.
            index = elf.get_section_index(section_name)
            sh_entry_offset = elf.header["e_shoff"] + index * elf.header["e_shentsize"]
            section.header.sh_addr += address_offset

            # Write modified header to file
            f.seek(sh_entry_offset)
            f.write(elf.structs.Elf_Shdr.build(section.header))

    def test_appdesc_not_aligned(self, capsys):
        ELF = "esp32c6-appdesc.elf"
        BIN = "esp32c6-appdesc.bin"
        ADDRESS_OFFSET = 4  # 4 bytes is minimum allowed

        self._modify_section_address(ELF, ".flash.appdesc", ADDRESS_OFFSET)
        try:
            self.run_elf2image("esp32c6", ELF, allow_warnings=True)
            output = capsys.readouterr().out
            print(output)
            assert (
                "App description segment is not aligned to MMU page size, probably "
                "linker script issue or wrong MMU page size. "
                "Try to set MMU page size parameter manually." in output
            )
        finally:
            # Restore original address to be able to run other tests
            self._modify_section_address(ELF, ".flash.appdesc", -ADDRESS_OFFSET)
            try_delete(BIN)

    @staticmethod
    def _change_appdesc_mmu_page_size(elf_path, mmu_page_size):
        """
        Change the MMU page size in the appdesc section of the ELF file.
        The following values can be chosen: 0 (empty), 8192, 16384, 32768, 65536.
        The numbers are not valid for all chips, so refer to the documentation
        of the chip being used.
        """
        with open(elf_path, "rb+") as f:
            elf = ELFFile(f)
            section = elf.get_section_by_name(".flash.appdesc")

            if not section:
                raise ValueError("Section .flash.appdesc not found")

            # The mmu_page_size is a power of 2, so we convert it to the corresponding
            # value for the appdesc section. It can also be empty (0).
            if mmu_page_size == 0:
                mmu_page_size_appdesc = 0
            else:
                mmu_page_size_appdesc = int(math.log2(mmu_page_size))

            # Go to the mmu_page_size field in the appdesc section (at offset 0xB4) and
            # modify it
            f.seek(section.header.sh_offset + 0xB4)
            f.write(mmu_page_size_appdesc.to_bytes(4, byteorder="little"))

    def test_appdesc_data(self, capsys):
        ELF = "esp32c6-appdesc.elf"
        BIN = "esp32c6-appdesc.bin"
        MMU_PAGE_SIZE = 65536

        self._change_appdesc_mmu_page_size(ELF, MMU_PAGE_SIZE)
        try:
            self.run_elf2image("esp32c6", ELF)
            output = capsys.readouterr().out
            assert "MMU page size" not in output
            print(output)
        finally:
            self._change_appdesc_mmu_page_size(ELF, 0)
            try_delete(BIN)
