#!/usr/bin/env python
from __future__ import division, print_function

import hashlib
import os
import os.path
import struct
import subprocess
import sys
import unittest

from elftools.elf.elffile import ELFFile

TEST_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "elf2image")
os.chdir(TEST_DIR)
try:
    ESPTOOL_PY = os.environ["ESPTOOL_PY"]
except KeyError:
    ESPTOOL_PY = os.path.join(TEST_DIR, "../..", "esptool.py")

# import the version of esptool we are testing with
sys.path.append(os.path.dirname(ESPTOOL_PY))
import esptool


def try_delete(path):
    try:
        os.remove(path)
    except OSError:
        pass


def segment_matches_section(segment, section):
    """ segment is an ImageSegment from an esptool binary.
    section is an elftools ELF section

    Returns True if they match
    """
    sh_size = (section.header.sh_size + 0x3) & ~3  # pad length of ELF sections
    return section.header.sh_addr == segment.addr and sh_size == len(segment.data)


class BaseTestCase(unittest.TestCase):

    def assertEqualHex(self, expected, actual, message=None):
        try:
            expected = hex(expected)
        except TypeError:  # if expected is character
            expected = hex(ord(expected))
        try:
            actual = hex(actual)
        except TypeError:  # if actual is character
            actual = hex(ord(actual))
        self.assertEqual(expected, actual, message)

    def assertImageContainsSection(self, image, elf, section_name):
        """
        Assert an esptool binary image object contains
        the data for a particular ELF section.
        """
        with open(elf, "rb") as f:
            e = ELFFile(f)
            section = e.get_section_by_name(section_name)
            self.assertTrue(section, "%s should be in the ELF" % section_name)
            sh_addr = section.header.sh_addr
            data = section.data()
            # section contents may be smeared across multiple image segments,
            # so look through each segment and remove it from ELF section 'data'
            # as we find it in the image segments. When we're done 'data' should
            # all be accounted for
            for seg in sorted(image.segments, key=lambda s: s.addr):
                print("comparing seg 0x%x sec 0x%x len 0x%x" % (seg.addr, sh_addr, len(data)))
                if seg.addr == sh_addr:
                    overlap_len = min(len(seg.data), len(data))
                    self.assertEqual(data[:overlap_len], seg.data[:overlap_len],
                                     "ELF '%s' section has mis-matching binary image data" % section_name)
                    sh_addr += overlap_len
                    data = data[overlap_len:]

            # no bytes in 'data' should be left unmatched
            self.assertEqual(0, len(data),
                             "ELF %s section '%s' has no encompassing segment(s) in binary image (image segments: %s)"
                             % (elf, section_name, image.segments))

    def assertImageInfo(self, binpath, chip="esp8266"):
        """
        Run esptool.py image_info on a binary file,
        assert no red flags about contents.
        """
        cmd = [sys.executable, ESPTOOL_PY, "--chip", chip, "image_info", binpath]
        try:
            output = subprocess.check_output(cmd).decode("utf-8")
            print(output)
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise
        self.assertFalse("invalid" in output, "Checksum calculation should be valid")
        self.assertFalse("warning" in output.lower(), "Should be no warnings in image_info output")

    def run_elf2image(self, chip, elf_path, version=None, extra_args=[]):
        """ Run elf2image on elf_path """
        cmd = [sys.executable, ESPTOOL_PY, "--chip", chip, "elf2image"]
        if version is not None:
            cmd += ["--version", str(version)]
        cmd += [elf_path] + extra_args
        print("Executing %s" % (" ".join(cmd)))
        try:
            output = str(subprocess.check_output(cmd))
            print(output)
            self.assertFalse("warning" in output.lower(), "elf2image should not output warnings")
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise


class ESP8266V1ImageTests(BaseTestCase):
    ELF = "esp8266-nonosssdk20-iotdemo.elf"
    BIN_LOAD = "esp8266-nonosssdk20-iotdemo.elf-0x00000.bin"
    BIN_IROM = "esp8266-nonosssdk20-iotdemo.elf-0x10000.bin"

    def setUp(self):
        self.run_elf2image("esp8266", self.ELF, 1)

    def tearDown(self):
        try_delete(self.BIN_LOAD)
        try_delete(self.BIN_IROM)

    def test_irom_bin(self):
        with open(self.ELF, "rb") as f:
            e = ELFFile(f)
            irom_section = e.get_section_by_name(".irom0.text")
            self.assertEqual(irom_section.header.sh_size,
                             os.stat(self.BIN_IROM).st_size,
                             "IROM raw binary file should be same length as .irom0.text section")

    def test_loaded_sections(self):
        image = esptool.LoadFirmwareImage("esp8266", self.BIN_LOAD)
        self.assertEqual(3, len(image.segments))
        self.assertImageContainsSection(image, self.ELF, ".data")
        self.assertImageContainsSection(image, self.ELF, ".text")
        self.assertImageContainsSection(image, self.ELF, ".rodata")


class ESP8266V12SectionHeaderNotAtEnd(BaseTestCase):
    """ Ref https://github.com/espressif/esptool/issues/197 -
    this ELF image has the section header not at the end of the file """
    ELF = "esp8266-nonossdkv12-example.elf"
    BIN_LOAD = ELF + "-0x00000.bin"
    BIN_IROM = ELF + "-0x40000.bin"

    def test_elf_section_header_not_at_end(self):
        self.run_elf2image("esp8266", self.ELF)
        image = esptool.LoadFirmwareImage("esp8266", self.BIN_LOAD)
        self.assertEqual(3, len(image.segments))
        self.assertImageContainsSection(image, self.ELF, ".data")
        self.assertImageContainsSection(image, self.ELF, ".text")
        self.assertImageContainsSection(image, self.ELF, ".rodata")

    def tearDown(self):
        try_delete(self.BIN_LOAD)
        try_delete(self.BIN_IROM)


class ESP8266V2ImageTests(BaseTestCase):

    def _test_elf2image(self, elfpath, binpath):
        try:
            self.run_elf2image("esp8266", elfpath, 2)
            image = esptool.LoadFirmwareImage("esp8266", binpath)
            self.assertEqual(4, len(image.segments))
            self.assertImageContainsSection(image, elfpath, ".data")
            self.assertImageContainsSection(image, elfpath, ".text")
            self.assertImageContainsSection(image, elfpath, ".rodata")
            irom_segment = image.segments[0]
            self.assertEqual(0, irom_segment.addr,
                             "IROM segment 'load address' should be zero")
            with open(elfpath, "rb") as f:
                e = ELFFile(f)
                sh_size = (e.get_section_by_name(".irom0.text").header.sh_size + 15) & ~15
                self.assertEqual(len(irom_segment.data), sh_size, "irom segment (0x%x) should be same size (16 padded) as .irom0.text section (0x%x)"
                                 % (len(irom_segment.data), sh_size))

            # check V2 CRC (for ESP8266 SDK bootloader)
            with open(binpath, "rb") as f:
                f.seek(-4, os.SEEK_END)
                image_len = f.tell()
                crc_stored = struct.unpack("<I", f.read(4))[0]
                f.seek(0)
                crc_calc = esptool.esp8266_crc32(f.read(image_len))
                self.assertEqual(crc_stored, crc_calc)

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
        self._test_elf2image(ELF, BIN)


class ESP32ImageTests(BaseTestCase):
    def _test_elf2image(self, elfpath, binpath):
        try:
            self.run_elf2image("esp32", elfpath)
            image = esptool.LoadFirmwareImage("esp32", binpath)
            self.assertImageInfo(binpath, "esp32")
            return image
        finally:
            try_delete(binpath)

    def test_bootloader(self):
        ELF = "esp32-bootloader.elf"
        BIN = "esp32-bootloader.bin"
        image = self._test_elf2image(ELF, BIN)
        self.assertEqual(3, len(image.segments))
        for section in [".iram1.text", ".iram_pool_1.text",
                        ".dram0.rodata"]:
            self.assertImageContainsSection(image, ELF, section)

    def test_app_template(self):
        ELF = "esp32-app-template.elf"
        BIN = "esp32-app-template.bin"
        image = self._test_elf2image(ELF, BIN)
        self.assertEqual(6, len(image.segments))
        # the other segment is a padding segment
        for section in [".iram0.text", ".iram0.vectors",
                        ".dram0.data", ".flash.rodata",
                        ".flash.text"]:
            self.assertImageContainsSection(image, ELF, section)

    def test_too_many_sections(self):
        ELF = "esp32-too-many-sections.elf"
        BIN = "esp32-too-many-sections.bin"
        with self.assertRaises(subprocess.CalledProcessError) as e:
            self._test_elf2image(ELF, BIN)
        output = e.exception.output
        self.assertIn(b"max 16", output)
        self.assertIn(b"linker script", output)


class ESP8266FlashHeaderTests(BaseTestCase):
    def test_2mb(self):
        ELF = "esp8266-nonossdkv20-at-v2.elf"
        BIN = "esp8266-nonossdkv20-at-v2-0x01000.bin"
        try:
            self.run_elf2image("esp8266", ELF, version=2, extra_args=["--flash_size", "2MB", "--flash_mode", "dio"])
            with open(BIN, "rb") as f:
                header = f.read(4)
                print("header %r" % header)
                self.assertEqualHex(0xea, header[0])
                self.assertEqualHex(0x02, header[2])
                self.assertEqualHex(0x30, header[3])
        finally:
            try_delete(BIN)


class ESP32FlashHeaderTests(BaseTestCase):
    def test_16mb(self):
        ELF = "esp32-app-template.elf"
        BIN = "esp32-app-template.bin"
        try:
            self.run_elf2image("esp32", ELF, extra_args=["--flash_size", "16MB", "--flash_mode", "dio", "--min-rev", "1"])
            with open(BIN, "rb") as f:
                header = f.read(24)
                self.assertEqualHex(0xe9, header[0])
                self.assertEqualHex(0x02, header[2])
                self.assertEqualHex(0x40, header[3])
                self.assertEqualHex(0x01, header[14])  # chip revision
        finally:
            try_delete(BIN)


class ELFSHA256Tests(BaseTestCase):
    ELF = "esp32-app-cust-ver-info.elf"
    SHA_OFFS = 0xb0  # absolute offset of the SHA in the .bin file
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
        .app_elf_sha256 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        .reserv2 = {0xffffffff,0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
    };

    This leaves zeroes only for the fiels of SHA-256 and the test will fail if the placement of zeroes are tested at
    the wrong place.

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
    000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................         SHA-256 should go here
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
            self.run_elf2image("esp32", self.ELF, extra_args=["--elf-sha256-offset", "0x%x" % self.SHA_OFFS])
            image = esptool.LoadFirmwareImage("esp32", self.BIN)
            rodata_segment = image.segments[0]
            bin_sha256 = rodata_segment.data[self.SHA_OFFS - 0x20: self.SHA_OFFS - 0x20 + 32]  # subtract 0x20 byte header here

            with open(self.ELF, "rb") as f:
                elf_computed_sha256 = hashlib.sha256(f.read()).digest()

            with open(self.BIN, "rb") as f:
                f.seek(self.SHA_OFFS)
                bin_sha256_raw = f.read(len(elf_computed_sha256))

            self.assertSequenceEqual(elf_computed_sha256, bin_sha256)
            self.assertSequenceEqual(elf_computed_sha256, bin_sha256_raw)
        finally:
            try_delete(self.BIN)

    def test_no_overwrite_data(self):
        with self.assertRaises(subprocess.CalledProcessError) as e:
            self.run_elf2image("esp32", "esp32-bootloader.elf", extra_args=["--elf-sha256-offset", "0xb0"])
        output = e.exception.output
        self.assertIn(b"SHA256", output)
        self.assertIn(b"zero", output)


if __name__ == '__main__':
    print("Running image generation tests...")
    unittest.main(buffer=True)
