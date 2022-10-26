import os
import os.path
import subprocess
import sys

from conftest import need_to_install_package_err

import pytest

try:
    import esptool  # noqa: F401
except ImportError:
    need_to_install_package_err()

IMAGES_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "images/")

NODEMCU_FILE = "nodemcu-master-7-modules-2017-01-19-11-10-03-integer.bin"


def read_image(filename):
    with open(os.path.join(IMAGES_DIR, filename), "rb") as f:
        return f.read()


class TestImageInfo:
    def run_image_info(self, chip, file, version=None):
        """Runs image_info on a binary file.
        Returns the command output.
        Filenames are relative to the 'test/images' directory.
        """

        cmd = [
            sys.executable,
            "-m",
            "esptool",
            "--chip",
            chip,
            "image_info",
        ]
        if version is not None:
            cmd += ["--version", str(version)]
        cmd += ["".join([IMAGES_DIR, file])]
        print("\nExecuting {}".format(" ".join(cmd)))

        try:
            output = subprocess.check_output(cmd)
            output = output.decode("utf-8")
            print(output)  # for more complete stdout logs on failure
            assert (
                "warning" not in output.lower()
            ), "image_info should not output warnings"
            return output
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

    def test_v1_esp32(self):
        out = self.run_image_info("esp32", "bootloader_esp32.bin")
        assert "Entry point: 4009816c" in out, "Wrong entry point"
        assert "Checksum: 83 (valid)" in out, "Invalid checksum"
        assert "4 segments" in out, "Wrong number of segments"
        assert (
            "Segment 3: len 0x01068 load 0x40078000 file_offs 0x00000b64 [CACHE_APP]"
            in out
        ), "Wrong segment info"

    def test_v1_esp8266(self):
        out = self.run_image_info("esp8266", NODEMCU_FILE)
        assert "Image version: 1" in out, "Wrong image version"
        assert "Entry point: 40101844" in out, "Wrong entry point"
        assert "Checksum: 2f (valid)" in out, "Invalid checksum"
        assert "3 segments" in out, "Wrong number of segments"
        assert (
            "Segment 2: len 0x00894 load 0x3ffe8000 file_offs 0x00005ee4 [DRAM]" in out
        ), "Wrong segment info"

    def test_v2_esp32c3(self):
        out = self.run_image_info("esp32c3", "bootloader_esp32c3.bin", "2")

        # Header
        assert "Entry point: 0x403c0000" in out, "Wrong entry point"
        assert "Segments: 4" in out, "Wrong num of segments"
        assert "Flash size: 2MB" in out, "Wrong flash size"
        assert "Flash freq: 40m" in out, "Wrong flash frequency"
        assert "Flash mode: DIO" in out, "Wrong flash mode"

        # Extended header
        assert "WP pin: 0xee" in out, "Wrong WP pin"
        assert "Chip ID: 5" in out, "Wrong chip ID"
        assert (
            "clk_drv: 0x0, q_drv: 0x0, d_drv: 0x0, "
            "cs0_drv: 0x0, hd_drv: 0x0, wp_drv: 0x0" in out
        ), "Wrong flash pins drive settings"

        assert "Minimal chip revision: v0.0" in out, "Wrong min revision"
        assert "Maximal chip revision: v0.0" in out, "Wrong min revision"

        # Segments
        assert (
            "2  0x01864  0x3fcd6114  0x00000034  DRAM, BYTE_ACCESSIBLE" in out
        ), "Wrong segment info"

        # Footer
        assert "Checksum: 0x77 (valid)" in out, "Invalid checksum"
        assert "c0a9d6d882b65580da2e5e6347 (valid)" in out, "Invalid hash"

        # Check output against individual bytes in the headers
        hdr = read_image("bootloader_esp32c3.bin")[:8]
        ex_hdr = read_image("bootloader_esp32c3.bin")[8:24]
        assert f"Segments: {hdr[1]}" in out, "Wrong num of segments"
        assert f"WP pin: {ex_hdr[0]:#02x}" in out, "Wrong WP pin"
        assert f"Chip ID: {ex_hdr[4]}" in out, "Wrong chip ID"
        if ex_hdr[15] == 1:  # Hash appended
            assert "Validation hash: 4faeab1bd3fd" in out, "Invalid hash"

    def test_v2_esp8266(self):
        out = self.run_image_info("esp8266", NODEMCU_FILE, "2")
        assert "Image version: 1" in out, "Wrong image version"
        assert "Entry point: 0x40101844" in out, "Wrong entry point"
        assert "Flash size: 512KB" in out, "Wrong flash size"
        assert "Flash freq: 40m" in out, "Wrong flash frequency"
        assert "Flash mode: QIO" in out, "Wrong flash mode"
        assert "Checksum: 0x2f (valid)" in out, "Invalid checksum"
        assert "Segments: 3" in out, "Wrong number of segments"
        assert "2  0x00894  0x3ffe8000  0x00005ee4  DRAM" in out, "Wrong segment info"

    def test_image_type_detection(self):
        # ESP8266, version 1 and 2
        out = self.run_image_info("auto", NODEMCU_FILE, "1")
        assert "Detected image type: ESP8266" in out
        assert "Segment 1: len 0x05ed4" in out
        out = self.run_image_info("auto", NODEMCU_FILE, "2")
        assert "Detected image type: ESP8266" in out
        assert "Flash freq: 40m" in out
        out = self.run_image_info("auto", "esp8266_deepsleep.bin", "2")
        assert "Detected image type: ESP8266" in out

        # ESP32, with and without detection
        out = self.run_image_info("auto", "bootloader_esp32.bin", "2")
        assert "Detected image type: ESP32" in out
        out = self.run_image_info(
            "auto", "ram_helloworld/helloworld-esp32_edit.bin", "2"
        )
        assert "Detected image type: ESP32" in out
        out = self.run_image_info("esp32", "bootloader_esp32.bin", "2")
        assert "Detected image type: ESP32" not in out

        # ESP32-C3
        out = self.run_image_info("auto", "bootloader_esp32c3.bin", "2")
        assert "Detected image type: ESP32-C3" in out

        # ESP32-S3
        out = self.run_image_info("auto", "bootloader_esp32s3.bin", "2")
        assert "Detected image type: ESP32-S3" in out

    def test_invalid_image_type_detection(self, capsys):
        with pytest.raises(subprocess.CalledProcessError):
            # Invalid image
            self.run_image_info("auto", "one_kb.bin", "2")
        assert (
            "This is not a valid image (invalid magic number: 0xed)"
            in capsys.readouterr().out
        )

    def test_application_info(self):
        out = self.run_image_info("auto", "esp_idf_blink_esp32s2.bin", "2")
        assert "Application information" in out
        assert "Project name: blink" in out
        assert "App version: qa-test-v5.0-20220830-4-g4532e6" in out
        assert "Secure version: 0" in out
        assert "Compile time: Sep 13 2022" in out
        assert "19:46:07" in out
        assert "3059e6b55a965865febd28fa9f6028ad5" in out
        assert "cd0dab311febb0a3ea79eaa223ac2b0" in out
        assert "ESP-IDF: v5.0-beta1-427-g4532e6e0b2-dirt" in out
        # No application info in image
        out = self.run_image_info("auto", "bootloader_esp32.bin", "2")
        assert "Application information" not in out
        out = self.run_image_info("auto", NODEMCU_FILE, "2")
        assert "Application information" not in out
