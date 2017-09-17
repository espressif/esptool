#!/usr/bin/env python
import os.path
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
    return (section.header.sh_addr == segment.addr
            and sh_size == len(segment.data))


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
            for seg in sorted(image.segments, key=lambda s:s.addr):
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
        cmd = [ sys.executable, ESPTOOL_PY, "--chip", chip, "image_info", binpath ]
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
        cmd = [sys.executable, ESPTOOL_PY, "--chip", chip, "elf2image" ]
        if version is not None:
            cmd += [ "--version", str(version) ]
        cmd += [ elf_path ] + extra_args
        print("Executing %s" % (" ".join(cmd)))
        try:
            output = str(subprocess.check_output(cmd))
            print(output)
            self.assertFalse("warning" in output.lower(), "elf2image should not output warnings")
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

class ESP8266V1ImageTests(BaseTestCase):
    ELF="esp8266-nonosssdk20-iotdemo.elf"
    BIN_LOAD="esp8266-nonosssdk20-iotdemo.elf-0x00000.bin"
    BIN_IROM="esp8266-nonosssdk20-iotdemo.elf-0x10000.bin"

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
    ELF="esp8266-nonossdkv12-example.elf"
    BIN=ELF+"-0x00000.bin"

    def test_elf_section_header_not_at_end(self):
        self.run_elf2image("esp8266", self.ELF)
        image = esptool.LoadFirmwareImage("esp8266", self.BIN)
        self.assertEqual(3, len(image.segments))
        self.assertImageContainsSection(image, self.ELF, ".data")
        self.assertImageContainsSection(image, self.ELF, ".text")
        self.assertImageContainsSection(image, self.ELF, ".rodata")

    def tearDown(self):
        try_delete(self.BIN)

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
                sh_size = (e.get_section_by_name(".irom0.text").header.sh_size + 3) & ~3
                self.assertEqual(len(irom_segment.data), sh_size, "irom segment (0x%x) should be same size as .irom0.text section (0x%x)" % (len(irom_segment.data), sh_size))

            # test imageinfo doesn't fail
            self.assertImageInfo(binpath)
        finally:
            try_delete(binpath)

    def test_nonossdkimage(self):
        ELF="esp8266-nonossdkv20-at-v2.elf"
        BIN="esp8266-nonossdkv20-at-v2-0x01000.bin"
        self._test_elf2image(ELF, BIN)

    def test_espopenrtosimage(self):
        ELF="esp8266-openrtos-blink-v2.elf"
        BIN="esp8266-openrtos-blink-v2-0x02000.bin"
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
        ELF="esp32-bootloader.elf"
        BIN="esp32-bootloader.bin"
        image = self._test_elf2image(ELF, BIN)
        self.assertEqual(4, len(image.segments))
        for section in [ ".iram1.text", ".iram_pool_1.text",
                         ".dram0.data", ".dram0.rodata"]:
            self.assertImageContainsSection(image, ELF, section)

    def test_app_template(self):
        ELF="esp32-app-template.elf"
        BIN="esp32-app-template.bin"
        image = self._test_elf2image(ELF, BIN)
        self.assertEqual(8, len(image.segments))
        # the other two segments are padding segments
        for section in [ ".iram0.text", ".iram0.vectors",
                         ".dram0.data", ".flash.rodata",
                         ".flash.text", ".rtc.text"]:
            self.assertImageContainsSection(image, ELF, section)

class ESP8266FlashHeaderTests(BaseTestCase):
    def test_2mb(self):
        ELF="esp8266-nonossdkv20-at-v2.elf"
        BIN="esp8266-nonossdkv20-at-v2-0x01000.bin"
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
        ELF="esp32-app-template.elf"
        BIN="esp32-app-template.bin"
        try:
            self.run_elf2image("esp32", ELF, extra_args=["--flash_size", "16MB", "--flash_mode", "dio"])
            with open(BIN, "rb") as f:
                header = f.read(4)
                self.assertEqualHex(0xe9, header[0])
                self.assertEqualHex(0x02, header[2])
                self.assertEqualHex(0x40, header[3])
        finally:
            try_delete(BIN)


if __name__ == '__main__':
    print("Running image generation tests...")
    unittest.main(buffer=True)
