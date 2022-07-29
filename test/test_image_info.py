#!/usr/bin/env python

import os
import os.path
import subprocess
import sys
import unittest

IMAGES_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "images")
os.chdir(IMAGES_DIR)
try:
    ESPTOOL_PY = os.environ["ESPTOOL_PY"]
except KeyError:
    ESPTOOL_PY = os.path.join(IMAGES_DIR, "../..", "esptool/__init__.py")

# import the version of esptool we are testing with
sys.path.append(os.path.dirname(ESPTOOL_PY))

NODEMCU_FILE = "nodemcu-master-7-modules-2017-01-19-11-10-03-integer.bin"


def read_image(filename):
    with open(os.path.join(IMAGES_DIR, filename), "rb") as f:
        return f.read()


class ImageInfoTests(unittest.TestCase):
    def run_image_info(self, chip, file, version=None):
        """Runs image_info on a binary file.

        Returns the command output.

        Filenames are relative to the 'test/images' directory.

        """

        cmd = [
            sys.executable,
            ESPTOOL_PY,
            "--chip",
            chip,
            "image_info",
        ]
        if version is not None:
            cmd += ["--version", str(version)]
        cmd += [file]
        print("Executing {}".format(" ".join(cmd)))

        try:
            output = str(subprocess.check_output(cmd))
            print(output)
            self.assertFalse(
                "warning" in output.lower(), "image_info should not output warnings"
            )
            return output
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

    def test_v1_esp32(self):
        out = self.run_image_info("esp32", "bootloader_esp32.bin")
        self.assertTrue("Entry point: 4009816c" in out, "Wrong entry point")
        self.assertTrue("Checksum: 83 (valid)" in out, "Invalid checksum")
        self.assertTrue("4 segments" in out, "Wrong number of segments")
        self.assertTrue(
            "Segment 3: len 0x01068 load 0x40078000 file_offs 0x00000b64 [CACHE_APP]"
            in out,
            "Wrong segment info",
        )

    def test_v1_esp8266(self):
        out = self.run_image_info("esp8266", NODEMCU_FILE)
        self.assertTrue("Image version: 1" in out, "Wrong image version")
        self.assertTrue("Entry point: 40101844" in out, "Wrong entry point")
        self.assertTrue("Checksum: 2f (valid)" in out, "Invalid checksum")
        self.assertTrue("3 segments" in out, "Wrong number of segments")
        self.assertTrue(
            "Segment 2: len 0x00894 load 0x3ffe8000 file_offs 0x00005ee4 [DRAM]" in out,
            "Wrong segment info",
        )

    def test_v2_esp32c3(self):
        out = self.run_image_info("esp32c3", "bootloader_esp32c3.bin", "2")

        # Header
        self.assertTrue("Entry point: 0x403c0000" in out, "Wrong entry point")
        self.assertTrue("Segments: 4" in out, "Wrong num of segments")
        self.assertTrue("Flash size: 2MB" in out, "Wrong flash size")
        self.assertTrue("Flash freq: 40m" in out, "Wrong flash frequency")
        self.assertTrue("Flash mode: DIO" in out, "Wrong flash mode")

        # Extended header
        self.assertTrue("WP pin: 0xee" in out, "Wrong WP pin")
        self.assertTrue("Chip ID: 5" in out, "Wrong chip ID")
        self.assertTrue(
            "clk_drv: 0x0, q_drv: 0x0, d_drv: 0x0, "
            "cs0_drv: 0x0, hd_drv: 0x0, wp_drv: 0x0" in out,
            "Wrong flash pins drive settings",
        )
        self.assertTrue("Minimal chip revision: 0" in out, "Wrong min revision")

        # Segments
        self.assertTrue(
            "2  0x01864  0x3fcd6114  0x00000034  DRAM, BYTE_ACCESSIBLE" in out,
            "Wrong segment info",
        )

        # Footer
        self.assertTrue("Checksum: 0x77 (valid)" in out, "Invalid checksum")
        self.assertTrue("c0a9d6d882b65580da2e5e6347 (valid)" in out, "Invalid hash")

        # Check output against individual bytes in the headers
        hdr = read_image("bootloader_esp32c3.bin")[:8]
        ex_hdr = read_image("bootloader_esp32c3.bin")[8:24]
        self.assertTrue("Segments: {}".format(hdr[1]) in out, "Wrong num of segments")
        self.assertTrue("WP pin: {:#02x}".format(ex_hdr[0]) in out, "Wrong WP pin")
        self.assertTrue("Chip ID: {}".format(ex_hdr[4]) in out, "Wrong chip ID")
        if ex_hdr[15] == 1:  # Hash appended
            self.assertTrue("Validation hash: 4faeab1bd3fd" in out, "Invalid hash")

    def test_v2_esp8266(self):
        out = self.run_image_info("esp8266", NODEMCU_FILE, "2")
        self.assertTrue("Image version: 1" in out, "Wrong image version")
        self.assertTrue("Entry point: 0x40101844" in out, "Wrong entry point")
        self.assertTrue("Flash size: 512KB" in out, "Wrong flash size")
        self.assertTrue("Flash freq: 40m" in out, "Wrong flash frequency")
        self.assertTrue("Flash mode: QIO" in out, "Wrong flash mode")
        self.assertTrue("Checksum: 0x2f (valid)" in out, "Invalid checksum")
        self.assertTrue("Segments: 3" in out, "Wrong number of segments")
        self.assertTrue(
            "2  0x00894  0x3ffe8000  0x00005ee4  DRAM" in out,
            "Wrong segment info",
        )

    def test_image_type_detection(self):
        # ESP8266, version 1 and 2
        out = self.run_image_info("auto", NODEMCU_FILE, "1")
        self.assertTrue("Detected image type: ESP8266" in out)
        self.assertTrue("Segment 1: len 0x05ed4" in out)
        out = self.run_image_info("auto", NODEMCU_FILE, "2")
        self.assertTrue("Detected image type: ESP8266" in out)
        self.assertTrue("Flash freq: 40m" in out)
        out = self.run_image_info("auto", "esp8266_deepsleep.bin", "2")
        self.assertTrue("Detected image type: ESP8266" in out)

        # ESP32, with and without detection
        out = self.run_image_info("auto", "bootloader_esp32.bin", "2")
        self.assertTrue("Detected image type: ESP32" in out)
        out = self.run_image_info(
            "auto", "ram_helloworld/helloworld-esp32_edit.bin", "2"
        )
        self.assertTrue("Detected image type: ESP32" in out)
        out = self.run_image_info("esp32", "bootloader_esp32.bin", "2")
        self.assertFalse("Detected image type: ESP32" in out)

        # ESP32-C3
        out = self.run_image_info("auto", "bootloader_esp32c3.bin", "2")
        self.assertTrue("Detected image type: ESP32-C3" in out)

        # ESP32-S3
        out = self.run_image_info("auto", "bootloader_esp32s3.bin", "2")
        self.assertTrue("Detected image type: ESP32-S3" in out)

    @unittest.expectedFailure
    def test_invalid_image_type_detection(self):
        # Invalid image
        self.run_image_info("auto", "one_kb.bin", "2")


if __name__ == "__main__":
    unittest.main(buffer=True)
