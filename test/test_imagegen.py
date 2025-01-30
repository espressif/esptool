import hashlib
import os
import os.path
import re
import struct
import subprocess
import sys

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
                assert (
                    seg.addr != sh_addr
                ), f"{section_name} should not be in the binary image"

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
                    assert (
                        data[:overlap_len] == seg.data[:overlap_len]
                    ), f"ELF '{section_name}' section has mis-matching bin image data"
                    sh_addr += overlap_len
                    data = data[overlap_len:]

            # no bytes in 'data' should be left unmatched
            assert len(data) == 0, (
                f"ELF {elf} section '{section_name}' has no encompassing"
                f" segment(s) in bin image (image segments: {image.segments})"
            )

    def assertImageInfo(self, binpath, chip="esp8266", assert_sha=False):
        """
        Run esptool.py image_info on a binary file,
        assert no red flags about contents.
        """
        cmd = [sys.executable, "-m", "esptool", "--chip", chip, "image_info", binpath]
        try:
            output = subprocess.check_output(cmd)
            output = output.decode("utf-8")
            print(output)
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise
        assert re.search(
            r"Checksum: 0x[a-fA-F0-9]{2} \(valid\)", output
        ), "Checksum calculation should be valid"
        if assert_sha:
            assert re.search(
                r"Validation hash: [a-fA-F0-9]{64} \(valid\)", output
            ), "SHA256 should be valid"
        assert (
            "warning" not in output.lower()
        ), "Should be no warnings in image_info output"

    def run_elf2image(self, chip, elf_path, version=None, extra_args=[]):
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
            assert (
                "warning" not in output.lower()
            ), "elf2image should not output warnings"
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise


class TestESP8266V1Image(BaseTestCase):
    ELF = "esp8266-nonosssdk20-iotdemo.elf"
    BIN_LOAD = "esp8266-nonosssdk20-iotdemo.elf-0x00000.bin"
    BIN_IROM = "esp8266-nonosssdk20-iotdemo.elf-0x10000.bin"

    @classmethod
    def setup_class(self):
        super(TestESP8266V1Image, self).setup_class()
        self.run_elf2image(self, "esp8266", self.ELF, 1)

    @classmethod
    def teardown_class(self):
        super(TestESP8266V1Image, self).teardown_class()
        try_delete(self.BIN_LOAD)
        try_delete(self.BIN_IROM)

    def test_irom_bin(self):
        with open(self.ELF, "rb") as f:
            e = ELFFile(f)
            irom_section = e.get_section_by_name(".irom0.text")
            assert (
                irom_section.header.sh_size == os.stat(self.BIN_IROM).st_size
            ), "IROM raw binary file should be same length as .irom0.text section"

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

        # --use_segments uses ELF segments(phdrs), produces just 2 segments in the bin
        image = self._test_elf2image(ELF, BIN, ["--use_segments"])
        assert len(image.segments) == 2

    def test_ram_only_header(self):
        ELF = "esp32-app-template.elf"
        BIN = "esp32-app-template.bin"
        # --ram-only-header produces just 2 visible segments in the bin
        image = self._test_elf2image(ELF, BIN, ["--ram-only-header"])
        assert len(image.segments) == 2


class TestESP8266FlashHeader(BaseTestCase):
    def test_2mb(self):
        ELF = "esp8266-nonossdkv20-at-v2.elf"
        BIN = "esp8266-nonossdkv20-at-v2-0x01000.bin"
        try:
            self.run_elf2image(
                "esp8266",
                ELF,
                version=2,
                extra_args=["--flash_size", "2MB", "--flash_mode", "dio"],
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
                    "--flash_size",
                    "16MB",
                    "--flash_mode",
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
    ELF = "esp32-app-cust-ver-info.elf"
    SHA_OFFS = 0xB0  # absolute offset of the SHA in the .bin file
    BIN = "esp32-app-cust-ver-info.bin"

    """
    esp32-app-cust-ver-info.elf was built with the following application version info:

    const __attribute__((section(".rodata_desc"))) esp_app_desc_t esp_app_desc = {
        .magic_word = 0xffffffff,
        .secure_version = 0xffffffff,
        .reserv1 = {0xffffffff, 0xffffffff},
        .version = "_______________________________",
        .project_name = "-------------------------------",
        .time = "xxxxxxxxxxxxxxx",
        .date = "yyyyyyyyyyyyyyy",
        .idf_ver = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        .app_elf_sha256 =
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        .reserv2 = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
    };

    This leaves zeroes only for the fields of SHA-256 and the test will fail
    if the placement of zeroes are tested at the wrong place.

    00000000: e907 0020 780f 0840 ee00 0000 0000 0000  ... x..@........
    00000010: 0000 0000 0000 0001 2000 403f 605a 0000  ........ .@?`Z..
    00000020: ffff ffff ffff ffff ffff ffff ffff ffff  ................
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
    000000d0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    000000e0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    000000f0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    00000100: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    00000110: ffff ffff ffff ffff ffff ffff ffff ffff  ................
    00000120: 6370 755f 7374 6172 7400 0000 1b5b 303b  cpu_start....[0;

    """

    def test_binary_patched(self):
        try:
            self.run_elf2image(
                "esp32",
                self.ELF,
                extra_args=["--elf-sha256-offset", f"{self.SHA_OFFS:#x}"],
            )
            image = esptool.bin_image.LoadFirmwareImage("esp32", self.BIN)
            rodata_segment = image.segments[0]
            bin_sha256 = rodata_segment.data[
                self.SHA_OFFS - 0x20 : self.SHA_OFFS - 0x20 + 32
            ]  # subtract 0x20 byte header here

            with open(self.ELF, "rb") as f:
                elf_computed_sha256 = hashlib.sha256(f.read()).digest()

            with open(self.BIN, "rb") as f:
                f.seek(self.SHA_OFFS)
                bin_sha256_raw = f.read(len(elf_computed_sha256))

            assert elf_computed_sha256 == bin_sha256
            assert elf_computed_sha256 == bin_sha256_raw
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
