# Unit tests (really integration tests) for esptool.py using the pytest framework
# Uses a device connected to the serial port.
#
# RUNNING THIS WILL MESS UP THE DEVICE'S SPI FLASH CONTENTS
#
# How to use:
#
# Run with a physical connection to a chip:
#  - `pytest test_esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 115200`
#
# where  - --port       - a serial port for esptool.py operation
#        - --chip       - ESP chip name
#        - --baud       - baud rate
#        - --with-trace - trace all interactions (True or False)

import os
import os.path
import random
import re
import struct
import subprocess
import sys
import tempfile
import time
from socket import AF_INET, SOCK_STREAM, socket
from time import sleep

# Make command line options --port, --chip, --baud, and --with-trace available
from conftest import arg_baud, arg_chip, arg_port, arg_trace

sys.path.append("..")
import espefuse

import esptool

import pytest

import serial


# point is this file is not 4 byte aligned in length
NODEMCU_FILE = "nodemcu-master-7-modules-2017-01-19-11-10-03-integer.bin"

BL_IMAGES = {
    "esp8266": "images/bootloader_esp8266.bin",
    "esp32": "images/bootloader_esp32.bin",
    "esp32s2": "images/bootloader_esp32s2.bin",
    "esp32s3beta2": "images/bootloader_esp32s3beta2.bin",
    "esp32s3": "images/bootloader_esp32s3.bin",
    "esp32c3": "images/bootloader_esp32c3.bin",
    "esp32c2": "images/bootloader_esp32c2.bin",
}

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
os.chdir(os.path.dirname(__file__))
try:
    ESPTOOL_PY = os.environ["ESPTOOL_PY"]
except KeyError:
    ESPTOOL_PY = os.path.join(TEST_DIR, "..", "esptool/__init__.py")
ESPSECURE_PY = os.path.join(TEST_DIR, "..", "espsecure/__init__.py")
ESPRFC2217SERVER_PY = os.path.join(TEST_DIR, "..", "esp_rfc2217_server.py")

RETURN_CODE_FATAL_ERROR = 2

# esptool.py skips strapping mode check in USB-CDC case if this is set
os.environ["ESPTOOL_TESTING"] = "1"

print("Running esptool.py tests...")


class ESPRFC2217Server(object):
    """Creates a virtual serial port accessible through rfc2217 port."""

    def __init__(self, rfc2217_port=None):
        self.port = rfc2217_port or self.get_free_port()
        self.cmd = [
            sys.executable,
            ESPRFC2217SERVER_PY,
            "-p",
            str(self.port),
            arg_port,
        ]
        self.server_output_file = open(str(arg_chip) + "_server.out", "a")
        self.server_output_file.write("************************************")
        self.p = None
        self.wait_for_server_starts(attempts_count=5)

    @staticmethod
    def get_free_port():
        s = socket(AF_INET, SOCK_STREAM)
        s.bind(("", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def wait_for_server_starts(self, attempts_count):
        for attempt in range(attempts_count):
            try:
                self.p = subprocess.Popen(
                    self.cmd,
                    cwd=TEST_DIR,
                    stdout=self.server_output_file,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                )
                sleep(2)
                s = socket(AF_INET, SOCK_STREAM)
                result = s.connect_ex(("localhost", self.port))
                s.close()
                if result == 0:
                    print("Server started successfully.")
                    return
            except Exception as e:
                print(e)
            print(
                "Server start failed."
                + (" Retrying . . ." if attempt < attempts_count - 1 else "")
            )
            self.p.terminate()
        raise Exception("Server not started successfully!")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.server_output_file.close()
        self.p.terminate()


class EsptoolTestCase:
    def run_espsecure(self, args):

        cmd = [sys.executable, ESPSECURE_PY] + args.split(" ")
        print("\nExecuting {}...".format(" ".join(cmd)))
        try:
            output = subprocess.check_output(
                [str(s) for s in cmd], cwd=TEST_DIR, stderr=subprocess.STDOUT
            )
            output = output.decode("utf-8")
            print(output)  # for more complete stdout logs on failure
            return output
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise e

    def run_esptool(self, args, baud=None, chip_name=None, rfc2217_port=None):
        """
        Run esptool with the specified arguments. --chip, --port and --baud
        are filled in automatically from the command line.
        (can override default baud rate with baud param.)

        Additional args passed in args parameter as a string.

        Returns output from esptool.py as a string if there is any.
        Raises an exception if esptool.py fails.
        """
        trace_args = ["--trace"] if arg_trace else []
        cmd = [sys.executable, ESPTOOL_PY] + trace_args
        if chip_name or arg_chip is not None and chip_name != "auto":
            cmd += ["--chip", chip_name or arg_chip]
        if rfc2217_port or arg_port is not None:
            cmd += ["--port", rfc2217_port or arg_port]
        if baud or arg_baud is not None:
            cmd += ["--baud", str(baud or arg_baud)]
        cmd += args.split(" ")
        print("\nExecuting {}...".format(" ".join(cmd)))
        try:
            output = subprocess.check_output(
                [str(s) for s in cmd], cwd=TEST_DIR, stderr=subprocess.STDOUT
            )
            output = output.decode("utf-8")
            print(output)  # for more complete stdout logs on failure
            return output
        except subprocess.CalledProcessError as e:
            print(e.output.decode("utf-8"))
            raise e

    def run_esptool_error(self, args, baud=None):
        """
        Run esptool.py similar to run_esptool, but expect an error.

        Verifies the error is an expected error not an unhandled exception,
        and returns the output from esptool.py as a string.
        """
        with pytest.raises(subprocess.CalledProcessError) as fail:
            self.run_esptool(args, baud)
        failure = fail.value
        assert RETURN_CODE_FATAL_ERROR == failure.returncode
        return failure.output.decode("utf-8")

    @classmethod
    def setup_class(self):
        print()
        print(50 * "*")

    def readback(self, offset, length):
        """Read contents of flash back, return to caller."""
        with tempfile.NamedTemporaryFile() as tf:  # need a file we can read into
            self.run_esptool(
                f"--before default_reset read_flash {offset} {length} {tf.name}"
            )
            with open(tf.name, "rb") as f:
                rb = f.read()

        assert length == len(
            rb
        ), f"read_flash length {length} offset {offset:#x} yielded {len(rb)} bytes!"
        return rb

    def verify_readback(self, offset, length, compare_to, is_bootloader=False):
        rb = self.readback(offset, length)
        with open(compare_to, "rb") as f:
            ct = f.read()
        if len(rb) != len(ct):
            print(
                f"WARNING: Expected length {len(ct)} doesn't match comparison {len(rb)}"
            )
        print(f"Readback {len(rb)} bytes")
        if is_bootloader:
            # writing a bootloader image to bootloader offset can set flash size/etc,
            # so don't compare the 8 byte header
            assert ct[0] == rb[0], "First bytes should be identical"
            rb = rb[8:]
            ct = ct[8:]
        for rb_b, ct_b, offs in zip(rb, ct, range(len(rb))):
            assert (
                rb_b == ct_b
            ), f"First difference at offset {offs:#x} Expected {ct_b} got {rb_b}"


@pytest.mark.skipif(arg_chip != "esp32", reason="ESP32 only")
class TestFlashEncryption(EsptoolTestCase):
    def valid_key_present(self):
        esp = esptool.ESP32ROM(arg_port)
        esp.connect()
        efuses, _ = espefuse.get_efuses(esp=esp)
        blk1_rd_en = efuses["BLOCK1"].is_readable()
        return not blk1_rd_en

    def test_blank_efuse_encrypt_write_abort(self):
        """
        since flash crypt config is not set correctly, this test should abort write
        """
        if self.valid_key_present() is True:
            pytest.skip("Valid encryption key already programmed, aborting the test")

        self.run_esptool(
            "write_flash 0x1000 images/bootloader_esp32.bin "
            "0x8000 images/partitions_singleapp.bin "
            "0x10000 images/ram_helloworld/helloworld-esp32.bin"
        )
        output = self.run_esptool_error(
            "write_flash --encrypt 0x10000 images/ram_helloworld/helloworld-esp32.bin"
        )
        assert "Flash encryption key is not programmed".lower() in output.lower()

    def test_blank_efuse_encrypt_write_continue1(self):
        """
        since ignore option is specified, write should happen even though flash crypt
        config is 0
        later encrypted flash contents should be read back & compared with
        precomputed ciphertext
        pass test
        """
        if self.valid_key_present() is True:
            pytest.skip("Valid encryption key already programmed, aborting the test")

        self.run_esptool(
            "write_flash --encrypt --ignore-flash-encryption-efuse-setting "
            "0x10000 images/ram_helloworld/helloworld-esp32.bin"
        )
        self.run_esptool("read_flash 0x10000 192 images/read_encrypted_flash.bin")
        self.run_espsecure(
            "encrypt_flash_data --address 0x10000 --keyfile images/aes_key.bin "
            "--flash_crypt_conf 0 --output images/local_enc.bin "
            "images/ram_helloworld/helloworld-esp32.bin"
        )

        try:
            with open("images/read_encrypted_flash.bin", "rb") as file1:
                read_file1 = file1.read()

            with open("images/local_enc.bin", "rb") as file2:
                read_file2 = file2.read()

            for rf1, rf2, i in zip(read_file1, read_file2, range(len(read_file2))):
                assert (
                    rf1 == rf2
                ), f"Encrypted write failed: file mismatch at byte position {i}"

            print("Encrypted write success")
        finally:
            os.remove("images/read_encrypted_flash.bin")
            os.remove("images/local_enc.bin")

    @pytest.mark.xfail
    def test_blank_efuse_encrypt_write_continue2(self):
        """
        since ignore option is specified, write should happen even though flash crypt
        config is 0
        later encrypted flash contents should be read back & compared with
        precomputed ciphertext
        fail test
        """
        if self.valid_key_present() is True:
            pytest.skip("Valid encryption key already programmed, aborting the test")

        self.run_esptool(
            "write_flash --encrypt --ignore-flash-encryption-efuse-setting "
            "0x10000 images/ram_helloworld/helloworld-esp32_edit.bin"
        )
        self.run_esptool("read_flash 0x10000 192 images/read_encrypted_flash.bin")
        self.run_espsecure(
            "encrypt_flash_data --address 0x10000 --keyfile images/aes_key.bin "
            "--flash_crypt_conf 0 --output images/local_enc.bin "
            "images/ram_helloworld/helloworld-esp32.bin"
        )

        try:
            with open("images/read_encrypted_flash.bin", "rb") as file1:
                read_file1 = file1.read()

            with open("images/local_enc.bin", "rb") as file2:
                read_file2 = file2.read()

            for rf1, rf2, i in zip(read_file1, read_file2, range(len(read_file2))):
                assert rf1 == rf2, f"Files mismatch at byte position {i}"

        finally:
            os.remove("images/read_encrypted_flash.bin")
            os.remove("images/local_enc.bin")


class TestFlashing(EsptoolTestCase):
    def test_short_flash(self):
        self.run_esptool("write_flash 0x0 images/one_kb.bin")
        self.verify_readback(0, 1024, "images/one_kb.bin")

    def test_highspeed_flash(self):
        self.run_esptool("write_flash 0x0 images/fifty_kb.bin", baud=921600)
        self.verify_readback(0, 50 * 1024, "images/fifty_kb.bin")

    def test_adjacent_flash(self):
        self.run_esptool("write_flash 0x0 images/sector.bin 0x1000 images/fifty_kb.bin")
        self.verify_readback(0, 4096, "images/sector.bin")
        self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")

    def test_adjacent_independent_flash(self):
        self.run_esptool("write_flash 0x0 images/sector.bin")
        self.verify_readback(0, 4096, "images/sector.bin")
        self.run_esptool("write_flash 0x1000 images/fifty_kb.bin")
        self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")
        # writing flash the second time shouldn't have corrupted the first time
        self.verify_readback(0, 4096, "images/sector.bin")

    def test_correct_offset(self):
        """Verify writing at an offset actually writes to that offset."""
        self.run_esptool("write_flash 0x2000 images/sector.bin")
        time.sleep(0.1)
        three_sectors = self.readback(0, 0x3000)
        last_sector = three_sectors[0x2000:]
        with open("images/sector.bin", "rb") as f:
            ct = f.read()
        assert last_sector == ct

    def test_no_compression_flash(self):
        self.run_esptool(
            "write_flash -u 0x0 images/sector.bin 0x1000 images/fifty_kb.bin"
        )
        self.verify_readback(0, 4096, "images/sector.bin")
        self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")

    @pytest.mark.skipif(arg_chip == "esp8266", reason="Added in ESP32")
    def test_compressed_nostub_flash(self):
        self.run_esptool(
            "--no-stub write_flash -z 0x0 images/sector.bin 0x1000 images/fifty_kb.bin"
        )
        self.verify_readback(0, 4096, "images/sector.bin")
        self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")

    def _test_partition_table_then_bootloader(self, args):
        self.run_esptool(args + " 0x4000 images/partitions_singleapp.bin")
        self.verify_readback(0x4000, 96, "images/partitions_singleapp.bin")
        self.run_esptool(args + " 0x1000 images/bootloader_esp32.bin")
        self.verify_readback(0x1000, 7888, "images/bootloader_esp32.bin", True)
        self.verify_readback(0x4000, 96, "images/partitions_singleapp.bin")

    def test_partition_table_then_bootloader(self):
        self._test_partition_table_then_bootloader("write_flash --force")

    def test_partition_table_then_bootloader_no_compression(self):
        self._test_partition_table_then_bootloader("write_flash --force -u")

    def test_partition_table_then_bootloader_nostub(self):
        self._test_partition_table_then_bootloader("--no-stub write_flash --force")

    # note: there is no "partition table then bootloader" test that
    # uses --no-stub and -z, as the ESP32 ROM over-erases and can't
    # flash this set of files in this order.  we do
    # test_compressed_nostub_flash() instead.

    def test_length_not_aligned_4bytes(self):
        self.run_esptool(f"write_flash 0x0 images/{NODEMCU_FILE}")

    def test_length_not_aligned_4bytes_no_compression(self):
        self.run_esptool(f"write_flash -u 0x0 images/{NODEMCU_FILE}")

    def test_write_overlap(self):
        output = self.run_esptool_error(
            "write_flash 0x0 images/bootloader_esp32.bin 0x1000 images/one_kb.bin"
        )
        assert "Detected overlap at address: 0x1000 " in output

    def test_repeated_address(self):
        output = self.run_esptool_error(
            "write_flash 0x0 images/one_kb.bin 0x0 images/one_kb.bin"
        )
        assert "Detected overlap at address: 0x0 " in output

    def test_write_sector_overlap(self):
        # These two 1KB files don't overlap,
        # but they do both touch sector at 0x1000 so should fail
        output = self.run_esptool_error(
            "write_flash 0xd00 images/one_kb.bin 0x1d00 images/one_kb.bin"
        )
        assert "Detected overlap at address: 0x1d00" in output

    def test_write_no_overlap(self):
        output = self.run_esptool(
            "write_flash 0x0 images/one_kb.bin 0x2000 images/one_kb.bin"
        )
        assert "Detected overlap at address" not in output

    def test_compressible_file(self):
        with tempfile.NamedTemporaryFile() as f:
            file_size = 1024 * 1024
            f.write(b"\x00" * file_size)
            self.run_esptool(f"write_flash 0x10000 {f.name}")

    def test_compressible_non_trivial_file(self):
        with tempfile.NamedTemporaryFile() as f:
            file_size = 1000 * 1000
            same_bytes = 8000
            for _ in range(file_size // same_bytes):
                f.write(struct.pack("B", random.randrange(0, 1 << 8)) * same_bytes)
            self.run_esptool(f"write_flash 0x10000 {f.name}")

    def test_zero_length(self):
        # Zero length files are skipped with a warning
        output = self.run_esptool(
            "write_flash 0x10000 images/one_kb.bin 0x11000 images/zerolength.bin"
        )
        self.verify_readback(0x10000, 1024, "images/one_kb.bin")
        assert "zerolength.bin is empty" in output

    def test_single_byte(self):
        self.run_esptool("write_flash 0x0 images/onebyte.bin")
        self.verify_readback(0x0, 1, "images/onebyte.bin")

    def test_erase_range_messages(self):
        output = self.run_esptool(
            "write_flash 0x1000 images/sector.bin 0x0FC00 images/one_kb.bin"
        )
        assert "Flash will be erased from 0x00001000 to 0x00001fff..." in output
        assert (
            "WARNING: Flash address 0x0000fc00 is not aligned to a 0x1000 "
            "byte flash sector. 0xc00 bytes before this address will be erased."
            in output
        )
        assert "Flash will be erased from 0x0000f000 to 0x0000ffff..." in output

    @pytest.mark.skipif(
        arg_chip == "esp8266", reason="chip_id field exist in ESP32 and later images"
    )
    @pytest.mark.skipif(
        arg_chip == "esp32s3", reason="This is a valid ESP32-S3 image, would pass"
    )
    def test_write_image_for_another_target(self):
        output = self.run_esptool_error(
            "write_flash 0x0 images/esp32s3_header.bin 0x1000 images/one_kb.bin"
        )
        assert "Unexpected chip id in image." in output
        assert "value was 9. Is this image for a different chip model?" in output
        assert "images/esp32s3_header.bin is not an " in output
        assert "image. Use --force to flash anyway." in output

    @pytest.mark.skipif(
        arg_chip == "esp8266", reason="chip_id field exist in ESP32 and later images"
    )
    @pytest.mark.skipif(
        arg_chip != "esp32s3", reason="This check happens only on a valid image"
    )
    def test_write_image_for_another_revision(self):
        output = self.run_esptool_error(
            "write_flash 0x0 images/one_kb.bin 0x1000 images/esp32s3_header.bin"
        )
        assert "images/esp32s3_header.bin requires chip revision 10" in output
        assert "or higher (this chip is revision" in output
        assert "Use --force to flash anyway." in output


class TestFlashSizes(EsptoolTestCase):
    def test_high_offset(self):
        self.run_esptool("write_flash -fs 4MB 0x300000 images/one_kb.bin")
        self.verify_readback(0x300000, 1024, "images/one_kb.bin")

    def test_high_offset_no_compression(self):
        self.run_esptool("write_flash -u -fs 4MB 0x300000 images/one_kb.bin")
        self.verify_readback(0x300000, 1024, "images/one_kb.bin")

    def test_large_image(self):
        self.run_esptool("write_flash -fs 4MB 0x280000 images/one_mb.bin")
        self.verify_readback(0x280000, 0x100000, "images/one_mb.bin")

    def test_large_no_compression(self):
        self.run_esptool("write_flash -u -fs 4MB 0x280000 images/one_mb.bin")
        self.verify_readback(0x280000, 0x100000, "images/one_mb.bin")

    def test_invalid_size_arg(self):
        self.run_esptool_error("write_flash -fs 10MB 0x6000 images/one_kb.bin")

    def test_write_past_end_fails(self):
        output = self.run_esptool_error(
            "write_flash -fs 1MB 0x280000 images/one_kb.bin"
        )
        assert "File images/one_kb.bin" in output
        assert "will not fit" in output

    def test_write_no_compression_past_end_fails(self):
        output = self.run_esptool_error(
            "write_flash -u -fs 1MB 0x280000 images/one_kb.bin"
        )
        assert "File images/one_kb.bin" in output
        assert "will not fit" in output

    def test_flash_size_keep(self):
        assert arg_chip in BL_IMAGES.keys(), f"Unsupported chip for test: {arg_chip}"

        offset = 0x1000 if arg_chip in ["esp32", "esp32s2"] else 0x0

        # this image is configured for 2MB (512KB on ESP8266) flash by default.
        # assume this is not the flash size in use
        image = BL_IMAGES[arg_chip]

        with open(image, "rb") as f:
            f.seek(0, 2)
            image_len = f.tell()
        self.run_esptool(f"write_flash -fs keep {offset} {image}")
        # header should be the same as in the .bin file
        self.verify_readback(offset, image_len, image)


class TestFlashDetection(EsptoolTestCase):
    def test_flash_id(self):
        """Test manufacturer and device response of flash detection."""
        res = self.run_esptool("flash_id")
        assert "Manufacturer:" in res
        assert "Device:" in res


class TestStubReuse(EsptoolTestCase):
    def test_stub_reuse_with_synchronization(self):
        """Keep the flasher stub running and reuse it the next time."""
        res = self.run_esptool(
            "--after no_reset_stub flash_id"
        )  # flasher stub keeps running after this
        assert "Manufacturer:" in res
        res = self.run_esptool(
            "--before no_reset flash_id"
        )  # do sync before (without reset it talks to the flasher stub)
        assert "Manufacturer:" in res

    @pytest.mark.skipif(arg_chip != "esp8266", reason="ESP8266 only")
    def test_stub_reuse_without_synchronization(self):
        """
        Keep the flasher stub running and reuse it the next time
        without synchronization.

        Synchronization is necessary for chips where the ROM bootloader has different
        status length in comparison to the flasher stub.
        Therefore, this is ESP8266 only test.
        """
        res = self.run_esptool("--after no_reset_stub flash_id")
        assert "Manufacturer:" in res
        res = self.run_esptool("--before no_reset_no_sync flash_id")
        assert "Manufacturer:" in res


class TestErase(EsptoolTestCase):
    def test_chip_erase(self):
        self.run_esptool("write_flash 0x10000 images/one_kb.bin")
        self.verify_readback(0x10000, 0x400, "images/one_kb.bin")
        self.run_esptool("erase_flash")
        empty = self.readback(0x10000, 0x400)
        assert empty == b"\xFF" * 0x400

    def test_region_erase(self):
        self.run_esptool("write_flash 0x10000 images/one_kb.bin")
        self.run_esptool("write_flash 0x11000 images/sector.bin")
        self.verify_readback(0x10000, 0x400, "images/one_kb.bin")
        self.verify_readback(0x11000, 0x1000, "images/sector.bin")
        # erase only the flash sector containing one_kb.bin
        self.run_esptool("erase_region 0x10000 0x1000")
        self.verify_readback(0x11000, 0x1000, "images/sector.bin")
        empty = self.readback(0x10000, 0x1000)
        assert empty == b"\xFF" * 0x1000

    def test_large_region_erase(self):
        # verifies that erasing a large region doesn't time out
        self.run_esptool("erase_region 0x0 0x100000")


class TestSectorBoundaries(EsptoolTestCase):
    def test_end_sector(self):
        self.run_esptool("write_flash 0x10000 images/sector.bin")
        self.run_esptool("write_flash 0x0FC00 images/one_kb.bin")
        self.verify_readback(0x0FC00, 0x400, "images/one_kb.bin")
        self.verify_readback(0x10000, 0x1000, "images/sector.bin")

    def test_end_sector_uncompressed(self):
        self.run_esptool("write_flash -u 0x10000 images/sector.bin")
        self.run_esptool("write_flash -u 0x0FC00 images/one_kb.bin")
        self.verify_readback(0x0FC00, 0x400, "images/one_kb.bin")
        self.verify_readback(0x10000, 0x1000, "images/sector.bin")

    def test_overlap(self):
        self.run_esptool("write_flash 0x20800 images/sector.bin")
        self.verify_readback(0x20800, 0x1000, "images/sector.bin")


class TestVerifyCommand(EsptoolTestCase):
    def test_verify_success(self):
        self.run_esptool("write_flash 0x5000 images/one_kb.bin")
        self.run_esptool("verify_flash 0x5000 images/one_kb.bin")

    def test_verify_failure(self):
        self.run_esptool("write_flash 0x6000 images/sector.bin")
        output = self.run_esptool_error(
            "verify_flash --diff=yes 0x6000 images/one_kb.bin"
        )
        assert "verify FAILED" in output
        assert "first @ 0x00006000" in output

    def test_verify_unaligned_length(self):
        self.run_esptool(f"write_flash 0x0 images/{NODEMCU_FILE}")
        self.run_esptool(f"verify_flash 0x0 images/{NODEMCU_FILE}")


class TestReadIdentityValues(EsptoolTestCase):
    def test_read_mac(self):
        output = self.run_esptool("read_mac")
        mac = re.search(r"[0-9a-f:]{17}", output)
        assert mac is not None
        mac = mac.group(0)
        assert mac != "00:00:00:00:00:00"
        assert mac != "ff:ff:ff:ff:ff:ff"

    @pytest.mark.skipif(arg_chip != "esp8266", reason="ESP8266 only")
    def test_read_chip_id(self):
        output = self.run_esptool("chip_id")
        idstr = re.search("Chip ID: 0x([0-9a-f]+)", output)
        assert idstr is not None
        idstr = idstr.group(1)
        assert idstr != "0" * 8
        assert idstr != "f" * 8


class TestMemoryOperations(EsptoolTestCase):
    def test_memory_dump(self):
        output = self.run_esptool("dump_mem 0x50000000 128 memout.bin")
        assert "Read 128 bytes" in output
        os.remove("memout.bin")

    def test_memory_write(self):
        output = self.run_esptool("write_mem 0x400C0000 0xabad1dea 0x0000ffff")
        assert "Wrote abad1dea" in output
        assert "mask 0000ffff" in output
        assert "to 400c0000" in output

    def test_memory_read(self):
        output = self.run_esptool("read_mem 0x400C0000")
        assert "0x400c0000 =" in output


class TestKeepImageSettings(EsptoolTestCase):
    """Tests for the -fm keep, -ff keep options for write_flash"""

    @classmethod
    def setup_class(self):
        super(TestKeepImageSettings, self).setup_class()
        self.BL_IMAGE = BL_IMAGES[arg_chip]
        self.flash_offset = (
            0x1000 if arg_chip in ("esp32", "esp32s2") else 0
        )  # bootloader offset
        with open(self.BL_IMAGE, "rb") as f:
            self.header = f.read(8)

    def test_keep_does_not_change_settings(self):
        # defaults should all be keep
        self.run_esptool(f"write_flash -fs keep {self.flash_offset:#x} {self.BL_IMAGE}")
        self.verify_readback(self.flash_offset, 8, self.BL_IMAGE, False)
        # can also explicitly set all options
        self.run_esptool(
            f"write_flash -fm keep -ff keep -fs keep "
            f"{self.flash_offset:#x} {self.BL_IMAGE}"
        )
        self.verify_readback(self.flash_offset, 8, self.BL_IMAGE, False)
        # verify_flash should also use 'keep'
        self.run_esptool(
            f"verify_flash -fs keep {self.flash_offset:#x} {self.BL_IMAGE}"
        )

    def test_detect_size_changes_size(self):
        self.run_esptool(
            f"write_flash -fs detect {self.flash_offset:#x} {self.BL_IMAGE}"
        )
        readback = self.readback(self.flash_offset, 8)
        assert self.header[:3] == readback[:3]  # first 3 bytes unchanged
        if arg_chip in ["esp8266", "esp32"]:
            assert self.header[3] != readback[3]  # size_freq byte changed
        else:
            # Not changed because protected by SHA256 digest
            assert self.header[3] == readback[3]  # size_freq byte unchanged
        assert self.header[4:] == readback[4:]  # rest unchanged

    @pytest.mark.skipif(
        arg_chip not in ["esp8266", "esp32"],
        reason="Bootloader header needs to be modifiable - without sha256",
    )
    def test_explicit_set_size_freq_mode(self):
        self.run_esptool(
            f"write_flash -fs 2MB -fm dout -ff 80m "
            f"{self.flash_offset:#x} {self.BL_IMAGE}"
        )

        readback = self.readback(self.flash_offset, 8)
        assert self.header[0] == readback[0]
        assert self.header[1] == readback[1]
        assert (0x3F if arg_chip == "esp8266" else 0x1F) == readback[3]  # size_freq

        assert 3 != self.header[2]  # original image not dout mode
        assert 3 == readback[2]  # value in flash is dout mode

        assert self.header[3] != readback[3]  # size/freq values have changed
        assert self.header[4:] == readback[4:]  # entrypoint address hasn't changed

        # verify_flash should pass if we match params, fail otherwise
        self.run_esptool(
            f"verify_flash -fs 2MB -fm dout -ff 80m "
            f"{self.flash_offset:#x} {self.BL_IMAGE}"
        )
        self.run_esptool_error(f"verify_flash {self.flash_offset:#x} {self.BL_IMAGE}")


@pytest.mark.skipif(
    arg_chip in ["esp32s2", "esp32s3", "esp32c3", "esp32c2"],
    reason=f"TODO: write a IRAM test binary for {arg_chip}",
)
class TestLoadRAM(EsptoolTestCase):
    # flashing an application not supporting USB-CDC will make
    # /dev/ttyACM0 disappear and USB-CDC tests will not work anymore
    def test_load_ram(self):
        """Verify load_ram command

        The "hello world" binary programs for each chip print
        "Hello world!\n" to the serial port.
        """
        self.run_esptool(f"load_ram images/ram_helloworld/helloworld-{arg_chip}.bin")
        p = serial.serial_for_url(arg_port, arg_baud)
        p.timeout = 5
        output = p.read(100)
        print(f"Output: {output}")
        assert b"Hello world!" in output
        p.close()


class TestDeepSleepFlash(EsptoolTestCase):
    @pytest.mark.skipif(arg_chip != "esp8266", reason="ESP8266 only")
    def test_deep_sleep_flash(self):
        """Regression test for https://github.com/espressif/esptool/issues/351

        ESP8266 deep sleep can disable SPI flash chip,
        stub loader (or ROM loader) needs to re-enable it.

        NOTE: If this test fails, the ESP8266 may need a hard power cycle
        (probably with GPIO0 held LOW) to recover.
        """
        # not even necessary to wake successfully from sleep,
        # going into deep sleep is enough
        # (so GPIO16, etc, config is not important for this test)
        self.run_esptool("write_flash 0x0 images/esp8266_deepsleep.bin", baud=230400)

        time.sleep(0.25)  # give ESP8266 time to enter deep sleep

        self.run_esptool("write_flash 0x0 images/fifty_kb.bin", baud=230400)
        self.verify_readback(0, 50 * 1024, "images/fifty_kb.bin")


class TestBootloaderHeaderRewriteCases(EsptoolTestCase):
    def test_flash_header_rewrite(self):
        BL_OFFSET = 0x1000 if arg_chip in ("esp32", "esp32s2") else 0
        bl_image = BL_IMAGES[arg_chip]

        output = self.run_esptool(
            f"write_flash -fm dout -ff 20m {BL_OFFSET:#x} {bl_image}"
        )
        if arg_chip in ["esp8266", "esp32"]:
            # There is no SHA256 digest so the header can be changed - ESP8266 doesn't
            # support this; The test image for ESP32 just doesn't have it.
            "Flash params set to" in output
        else:
            assert "Flash params set to" not in output
            "not changing the flash mode setting" in output
            "not changing the flash frequency setting" in output

    def test_flash_header_no_magic_no_rewrite(self):
        # first image doesn't start with magic byte, second image does
        # but neither are valid bootloader binary images for either chip
        BL_OFFSET = 0x1000 if arg_chip in ("esp32", "esp32s2") else 0
        for image in ["images/one_kb.bin", "images/one_kb_all_ef.bin"]:
            output = self.run_esptool(
                f"write_flash -fm dout -ff 20m {BL_OFFSET:#x} {image}"
            )
            "not changing any flash settings" in output
            self.verify_readback(BL_OFFSET, 1024, image)


class TestAutoDetect(EsptoolTestCase):
    def _check_output(self, output):
        expected_chip_name = {
            "esp8266": "ESP8266",
            "esp32": "ESP32",
            "esp32s2": "ESP32-S2",
            "esp32s3beta2": "ESP32-S3(beta2)",
            "esp32s3": "ESP32-S3",
            "esp32c3": "ESP32-C3",
            "esp32c2": "ESP32-C2",
        }[arg_chip]
        assert f"Detecting chip type... {expected_chip_name}" in output
        assert f"Chip is {expected_chip_name}" in output

    def test_auto_detect(self):
        output = self.run_esptool("chip_id", chip_name="auto")
        self._check_output(output)


@pytest.mark.flaky(reruns=5)
class TestVirtualPort(TestAutoDetect):
    def test_auto_detect_virtual_port(self):
        with ESPRFC2217Server() as server:
            output = self.run_esptool(
                "chip_id",
                chip_name="auto",
                rfc2217_port=f"rfc2217://localhost:{str(server.port)}?ign_set_control",
            )
            self._check_output(output)

    def test_highspeed_flash_virtual_port(self):
        with ESPRFC2217Server() as server:
            rfc2217_port = f"rfc2217://localhost:{str(server.port)}?ign_set_control"
            self.run_esptool(
                "write_flash 0x0 images/fifty_kb.bin",
                baud=921600,
                rfc2217_port=rfc2217_port,
            )
        self.verify_readback(0, 50 * 1024, "images/fifty_kb.bin")


class TestReadWriteMemory(EsptoolTestCase):
    def _test_read_write(self, esp):
        # find the start of one of these named memory regions
        test_addr = None
        for test_region in [
            "RTC_DRAM",
            "RTC_DATA",
            "DRAM",
        ]:  # find a probably-unused memory type
            region = esp.get_memory_region(test_region)
            if region:
                # Write at the end of DRAM on ESP32-C2 to avoid overwriting the stub
                test_addr = region[1] - 8 if arg_chip == "esp32c2" else region[0]
                break

        print(f"Using test address {test_addr:#x}")

        val = esp.read_reg(test_addr)  # verify we can read this word at all

        try:
            esp.write_reg(test_addr, 0x1234567)
            assert esp.read_reg(test_addr) == 0x1234567

            esp.write_reg(test_addr, 0, delay_us=100)
            assert esp.read_reg(test_addr) == 0

            esp.write_reg(test_addr, 0x555, delay_after_us=100)
            assert esp.read_reg(test_addr) == 0x555
        finally:
            esp.write_reg(test_addr, val)  # write the original value, non-destructive

    def test_read_write_memory_rom(self):
        esp = esptool.get_default_connected_device(
            [arg_port], arg_port, 10, 115200, arg_chip
        )
        self._test_read_write(esp)

    def test_read_write_memory_stub(self):
        esp = esptool.get_default_connected_device(
            [arg_port], arg_port, 10, 115200, arg_chip
        )
        esp = esp.run_stub()
        self._test_read_write(esp)
