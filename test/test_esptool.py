# Unit tests (really integration tests) for esptool using the pytest framework
# Uses a device connected to the serial port.
#
# RUNNING THIS WILL MESS UP THE DEVICE'S SPI FLASH CONTENTS
#
# How to use:
#
# Run with a physical connection to a chip:
#  - `pytest test_esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 115200`
#
# where  - --port       - a serial port for esptool operation
#        - --chip       - ESP chip name
#        - --baud       - baud rate
#        - --with-trace - trace all interactions (True or False)
#
# To run the tests in USB-OTG mode, ground the boot mode straping pin
# and set ESPTOOL_TEST_USB_OTG environment variable to any value.
#
# To run the tests in USB-Serial/JTAG mode, set both --port and --preload-port
# options. The --preload-port needs to be connected to a USB-to-UART bridge,
# while --port needs to be connected to the USB-Serial/JTAG peripheral.

import os
import os.path
import random
import re
import struct
import subprocess
import sys
import tempfile
from io import StringIO
from socket import AF_INET, SOCK_STREAM, socket
from time import sleep
from unittest.mock import MagicMock
from unittest.mock import patch

# Link command line options --port, --chip, --baud, --with-trace, and --preload-port
from conftest import (
    arg_baud,
    arg_chip,
    arg_port,
    arg_preload_port,
    arg_trace,
    need_to_install_package_err,
)


import pytest

try:
    import esptool
    import espefuse
    from esptool.cmds import (
        detect_chip,
        erase_flash,
        attach_flash,
        flash_id,
        image_info,
        merge_bin,
        read_flash_sfdp,
        read_flash,
        read_mac,
        reset_chip,
        verify_flash,
        version,
        write_flash,
    )
except ImportError:
    need_to_install_package_err()

import serial


TEST_DIR = os.path.abspath(os.path.dirname(__file__))

print("Running esptool tests...")


class ESPRFC2217Server(object):
    """Creates a virtual serial port accessible through rfc2217 port."""

    def __init__(self, rfc2217_port=None):
        self.port = rfc2217_port or self.get_free_port()
        self.cmd = [
            sys.executable,
            os.path.join(TEST_DIR, "..", "esp_rfc2217_server"),
            "-p",
            str(self.port),
            arg_port,
        ]
        self.server_output_file = open(f"{TEST_DIR}/{str(arg_chip)}_server.out", "a")
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


# Re-run all tests at least once if failure happens in USB-JTAG/Serial
@pytest.mark.flaky(reruns=1, condition=arg_preload_port is not False)
class EsptoolTestCase:
    def run_espsecure(self, args):
        cmd = [sys.executable, "-m", "espsecure"] + args.split(" ")
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

    def run_esptool(self, args, baud=None, chip=None, port=None, preload=True):
        """
        Run esptool with the specified arguments. --chip, --port and --baud
        are filled in automatically from the command line.
        (These can be overridden with their respective params.)

        Additional args passed in args parameter as a string.

        Preloads a dummy binary if --preload_port is specified.
        This is needed in USB-JTAG/Serial mode to disable the
        RTC watchdog, which causes the port to periodically disappear.

        Returns output from esptool as a string if there is any.
        Raises an exception if esptool fails.
        """

        def run_esptool_process(cmd):
            print("Executing {}...".format(" ".join(cmd)))
            try:
                output = subprocess.check_output(
                    [str(s) for s in cmd],
                    cwd=TEST_DIR,
                    stderr=subprocess.STDOUT,
                )
                return output.decode("utf-8")
            except subprocess.CalledProcessError as e:
                print(e.output.decode("utf-8"))
                raise e

        try:
            # Used for flasher_stub/run_tests_with_stub.sh
            esptool = [os.environ["ESPTOOL_PY"]]
        except KeyError:
            # Run the installed esptool module
            esptool = ["-m", "esptool"]
        trace_arg = ["--trace"] if arg_trace else []
        base_cmd = [sys.executable] + esptool + trace_arg
        if chip or arg_chip is not None and chip != "auto":
            base_cmd += ["--chip", chip or arg_chip]
        if port or arg_port is not None:
            base_cmd += ["--port", port or arg_port]
        if baud or arg_baud is not None:
            base_cmd += ["--baud", str(baud or arg_baud)]
        usb_jtag_serial_reset = ["--before", "usb-reset"] if arg_preload_port else []
        usb_otg_dont_reset = (
            ["--after", "no-reset-stub"] if "ESPTOOL_TEST_USB_OTG" in os.environ else []
        )
        full_cmd = (
            base_cmd + usb_jtag_serial_reset + usb_otg_dont_reset + args.split(" ")
        )

        # Preload a dummy binary to disable the RTC watchdog, needed in USB-JTAG/Serial
        if (
            preload
            and arg_preload_port
            and arg_chip
            in [
                "esp32c3",
                "esp32s3",
                "esp32c6",
                "esp32h2",
                "esp32p4",
                "esp32c5",
                "esp32c61",
            ]  # With U-JS
        ):
            port_index = base_cmd.index("--port") + 1
            base_cmd[port_index] = arg_preload_port  # Set the port to the preload one
            preload_cmd = base_cmd + [
                "--no-stub",
                "load-ram",
                f"{TEST_DIR}/images/ram_helloworld/helloworld-{arg_chip}.bin",
            ]
            print("\nPreloading dummy binary to disable RTC watchdog...")
            run_esptool_process(preload_cmd)
            print("Dummy binary preloaded successfully.")
            sleep(0.3)  # Wait for the app to run and port to appear

        # Run the command
        print(f'\nRunning the "{args}" command...')
        output = run_esptool_process(full_cmd)
        print(output)  # for more complete stdout logs on failure

        if "ESPTOOL_TEST_USB_OTG" in os.environ:
            sleep(0.5)  # Wait for the port to enumerate between tests

        return output

    def run_esptool_error(self, args, baud=None, chip=None):
        """
        Run esptool similar to run_esptool, but expect an error.

        Verifies the error is an expected error not an unhandled exception,
        and returns the output from esptool as a string.
        """
        with pytest.raises(subprocess.CalledProcessError) as fail:
            self.run_esptool(args, baud, chip)
        failure = fail.value
        assert failure.returncode in [1, 2]  # UnsupportedCmdError and FatalError codes
        return failure.output.decode("utf-8")

    @classmethod
    def setup_class(self):
        print()
        print(50 * "*")
        # Save the current working directory to be restored later
        self.stored_dir = os.getcwd()
        os.chdir(TEST_DIR)

    @classmethod
    def teardown_class(self):
        # Restore the stored working directory
        os.chdir(self.stored_dir)

    def readback(self, offset, length, spi_connection=None):
        """Read contents of flash back, return to caller."""
        dump_file = tempfile.NamedTemporaryFile(delete=False)  # a file we can read into
        try:
            cmd = (
                f"--before default-reset read-flash {offset} {length} {dump_file.name}"
            )
            if spi_connection:
                cmd += f" --spi-connection {spi_connection}"
            self.run_esptool(cmd)
            with open(dump_file.name, "rb") as f:
                rb = f.read()

            rb_len = len(rb)
            assert length == rb_len, (
                f"read-flash length {length} offset {offset:#x} yielded {rb_len} bytes!"
            )
            return rb
        finally:
            dump_file.close()
            os.unlink(dump_file.name)

    def diff(self, readback, compare_to):
        for rb_b, ct_b, offs in zip(readback, compare_to, range(len(readback))):
            assert rb_b == ct_b, (
                f"First difference at offset {offs:#x} Expected {ct_b} got {rb_b}"
            )

    def verify_readback(
        self, offset, length, compare_to, is_bootloader=False, spi_connection=None
    ):
        rb = self.readback(offset, length, spi_connection)
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
        self.diff(rb, ct)

    def verify_output(self, expected_out: list[bytes]):
        """Verify that at least one element of expected_out is in serial output"""
        # Setting rtscts to true enables hardware flow control.
        # This removes unwanted RTS logic level changes for some machines
        # (and, therefore, chip resets)
        # when the port is opened by the following function.
        # As a result, if an app loaded to RAM, it has a chance to run and send
        # "Hello world" data without unwanted chip reset.
        with serial.serial_for_url(arg_port, arg_baud, rtscts=True) as p:
            p.timeout = 5
            output = p.read(100)
            print(f"Output: {output}")
            assert any(item in output for item in expected_out)


@pytest.mark.skipif(arg_chip != "esp32", reason="ESP32 only")
class TestFlashEncryption(EsptoolTestCase):
    def valid_key_present(self):
        try:
            esp = esptool.ESP32ROM(arg_port)
            esp.connect()
            efuse_cls = espefuse.init_commands(esp=esp)
            blk1_rd_en = efuse_cls.efuses["BLOCK1"].is_readable()
            return not blk1_rd_en
        finally:
            esp._port.close()

    def test_blank_efuse_encrypt_write_abort(self):
        """
        since flash crypt config is not set correctly, this test should abort write
        """
        if self.valid_key_present() is True:
            pytest.skip("Valid encryption key already programmed, aborting the test")

        self.run_esptool(
            "write-flash 0x1000 images/bootloader_esp32.bin "
            "0x8000 images/partitions_singleapp.bin "
            "0x10000 images/ram_helloworld/helloworld-esp32.bin"
        )
        output = self.run_esptool_error(
            "write-flash --encrypt 0x10000 images/ram_helloworld/helloworld-esp32.bin"
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
            "write-flash --encrypt --ignore-flash-enc-efuse "
            "0x10000 images/ram_helloworld/helloworld-esp32.bin"
        )
        self.run_esptool("read-flash 0x10000 192 images/read_encrypted_flash.bin")
        self.run_espsecure(
            "encrypt-flash-data --address 0x10000 --keyfile images/aes_key.bin "
            "--flash-crypt-conf 0 --output images/local_enc.bin "
            "images/ram_helloworld/helloworld-esp32.bin"
        )

        try:
            with open("images/read_encrypted_flash.bin", "rb") as file1:
                read_file1 = file1.read()

            with open("images/local_enc.bin", "rb") as file2:
                read_file2 = file2.read()

            for rf1, rf2, i in zip(read_file1, read_file2, range(len(read_file2))):
                assert rf1 == rf2, (
                    f"Encrypted write failed: file mismatch at byte position {i}"
                )

            print("Encrypted write success")
        finally:
            os.remove("images/read_encrypted_flash.bin")
            os.remove("images/local_enc.bin")

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
            "write-flash --encrypt --ignore-flash-enc-efuse "
            "0x10000 images/ram_helloworld/helloworld-esp32_edit.bin"
        )
        self.run_esptool("read-flash 0x10000 192 images/read_encrypted_flash.bin")
        self.run_espsecure(
            "encrypt-flash-data --address 0x10000 --keyfile images/aes_key.bin "
            "--flash-crypt-conf 0 --output images/local_enc.bin "
            "images/ram_helloworld/helloworld-esp32.bin"
        )

        try:
            with open("images/read_encrypted_flash.bin", "rb") as file1:
                read_file1 = file1.read()

            with open("images/local_enc.bin", "rb") as file2:
                read_file2 = file2.read()

            mismatch = any(rf1 != rf2 for rf1, rf2 in zip(read_file1, read_file2))
            assert mismatch, "Files should mismatch"

        finally:
            os.remove("images/read_encrypted_flash.bin")
            os.remove("images/local_enc.bin")


class TestFlashing(EsptoolTestCase):
    @pytest.mark.quick_test
    def test_short_flash(self):
        self.run_esptool("write-flash 0x0 images/one_kb.bin")
        self.verify_readback(0, 1024, "images/one_kb.bin")

    @pytest.mark.skipif(arg_chip != "esp32", reason="Don't need to test multiple times")
    def test_short_flash_deprecated(self):
        out = self.run_esptool(
            "--before default_reset write_flash 0x0 images/one_kb.bin --flash_size keep"
        )
        assert (
            "Deprecated: Choice 'default_reset' for option '--before' is deprecated. "
            "Use 'default-reset' instead." in out
        )
        assert (
            "Deprecated: Option '--flash_size' is deprecated. "
            "Use '--flash-size' instead." in out
        )
        assert (
            "Deprecated: Command 'write_flash' is deprecated. "
            "Use 'write-flash' instead." in out
        )
        self.verify_readback(0, 1024, "images/one_kb.bin")

    @pytest.mark.quick_test
    def test_highspeed_flash(self):
        self.run_esptool("write-flash 0x0 images/fifty_kb.bin", baud=921600)
        self.verify_readback(0, 50 * 1024, "images/fifty_kb.bin")

    def test_adjacent_flash(self):
        self.run_esptool("write-flash 0x0 images/sector.bin 0x1000 images/fifty_kb.bin")
        self.verify_readback(0, 4096, "images/sector.bin")
        self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")

    def test_short_flash_hex(self):
        fd, f = tempfile.mkstemp(suffix=".hex")
        try:
            self.run_esptool(f"merge-bin --format hex 0x0 images/one_kb.bin -o {f}")
            # make sure file is closed before running next command (mainly for Windows)
            os.close(fd)
            self.run_esptool(f"write-flash 0x0 {f}")
            self.verify_readback(0, 1024, "images/one_kb.bin")
        finally:
            os.unlink(f)

    def test_adjacent_flash_hex(self):
        fd1, f1 = tempfile.mkstemp(suffix=".hex")
        fd2, f2 = tempfile.mkstemp(suffix=".hex")
        try:
            self.run_esptool(f"merge-bin --format hex 0x0 images/sector.bin -o {f1}")
            # make sure file is closed before running next command (mainly for Windows)
            os.close(fd1)
            self.run_esptool(
                f"merge-bin --format hex 0x1000 images/fifty_kb.bin -o {f2}"
            )
            os.close(fd2)
            self.run_esptool(f"write-flash 0x0 {f1} 0x1000 {f2}")
            self.verify_readback(0, 4096, "images/sector.bin")
            self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")
        finally:
            os.unlink(f1)
            os.unlink(f2)

    def test_adjacent_flash_mixed(self):
        fd, f = tempfile.mkstemp(suffix=".hex")
        try:
            self.run_esptool(
                f"merge-bin --format hex 0x1000 images/fifty_kb.bin -o {f}"
            )
            # make sure file is closed before running next command (mainly for Windows)
            os.close(fd)
            self.run_esptool(f"write-flash 0x0 images/sector.bin 0x1000 {f}")
            self.verify_readback(0, 4096, "images/sector.bin")
            self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")
        finally:
            os.unlink(f)

    def test_adjacent_independent_flash(self):
        self.run_esptool("write-flash 0x0 images/sector.bin")
        self.verify_readback(0, 4096, "images/sector.bin")
        self.run_esptool("write-flash 0x1000 images/fifty_kb.bin")
        self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")
        # writing flash the second time shouldn't have corrupted the first time
        self.verify_readback(0, 4096, "images/sector.bin")

    @pytest.mark.skipif(
        int(os.getenv("ESPTOOL_TEST_FLASH_SIZE", "0")) < 32, reason="needs 32MB flash"
    )
    def test_last_bytes_of_32M_flash(self):
        flash_size = 32 * 1024 * 1024
        image_size = 1024
        offset = flash_size - image_size
        self.run_esptool("write-flash {} images/one_kb.bin".format(hex(offset)))
        # Some of the functions cannot handle 32-bit addresses - i.e. addresses
        # accessing the higher 16MB will manipulate with the lower 16MB flash area.
        offset2 = offset & 0xFFFFFF
        self.run_esptool("write-flash {} images/one_kb_all_ef.bin".format(hex(offset2)))
        self.verify_readback(offset, image_size, "images/one_kb.bin")

    @pytest.mark.skipif(
        int(os.getenv("ESPTOOL_TEST_FLASH_SIZE", "0")) < 32, reason="needs 32MB flash"
    )
    def test_write_larger_area_to_32M_flash(self):
        offset = 18 * 1024 * 1024
        self.run_esptool("write-flash {} images/one_mb.bin".format(hex(offset)))
        # Some of the functions cannot handle 32-bit addresses - i.e. addresses
        # accessing the higher 16MB will manipulate with the lower 16MB flash area.
        offset2 = offset & 0xFFFFFF
        self.run_esptool("write-flash {} images/one_kb_all_ef.bin".format(hex(offset2)))
        self.verify_readback(offset, 1 * 1024 * 1024, "images/one_mb.bin")

    def test_correct_offset(self):
        """Verify writing at an offset actually writes to that offset."""
        self.run_esptool("write-flash 0x2000 images/sector.bin")
        sleep(0.1)
        three_sectors = self.readback(0, 0x3000)
        last_sector = three_sectors[0x2000:]
        with open("images/sector.bin", "rb") as f:
            ct = f.read()
        assert last_sector == ct

    @pytest.mark.quick_test
    def test_no_compression_flash(self):
        self.run_esptool(
            "write-flash -u 0x0 images/sector.bin 0x1000 images/fifty_kb.bin"
        )
        self.verify_readback(0, 4096, "images/sector.bin")
        self.verify_readback(4096, 50 * 1024, "images/fifty_kb.bin")

    @pytest.mark.quick_test
    @pytest.mark.skipif(arg_chip == "esp8266", reason="Added in ESP32")
    def test_compressed_nostub_flash(self):
        self.run_esptool(
            "--no-stub write-flash -z 0x0 images/sector.bin 0x1000 images/fifty_kb.bin"
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
        self._test_partition_table_then_bootloader("write-flash --force")

    def test_partition_table_then_bootloader_no_compression(self):
        self._test_partition_table_then_bootloader("write-flash --force -u")

    def test_partition_table_then_bootloader_nostub(self):
        self._test_partition_table_then_bootloader("--no-stub write-flash --force")

    # note: there is no "partition table then bootloader" test that
    # uses --no-stub and -z, as the ESP32 ROM over-erases and can't
    # flash this set of files in this order.  we do
    # test_compressed_nostub_flash() instead.

    def test_length_not_aligned_4bytes(self):
        self.run_esptool("write-flash 0x0 images/not_4_byte_aligned.bin")

    def test_length_not_aligned_4bytes_no_compression(self):
        self.run_esptool("write-flash -u 0x0 images/not_4_byte_aligned.bin")

    @pytest.mark.quick_test
    @pytest.mark.host_test
    def test_write_overlap(self):
        output = self.run_esptool_error(
            "write-flash 0x0 images/bootloader_esp32.bin 0x1000 images/one_kb.bin"
        )
        assert "Detected overlap at address: 0x1000 " in output

    @pytest.mark.quick_test
    @pytest.mark.host_test
    def test_repeated_address(self):
        output = self.run_esptool_error(
            "write-flash 0x0 images/one_kb.bin 0x0 images/one_kb.bin"
        )
        assert "Detected overlap at address: 0x0 " in output

    @pytest.mark.quick_test
    @pytest.mark.host_test
    def test_write_sector_overlap(self):
        # These two 1KB files don't overlap,
        # but they do both touch sector at 0x1000 so should fail
        output = self.run_esptool_error(
            "write-flash 0xd00 images/one_kb.bin 0x1d00 images/one_kb.bin"
        )
        assert "Detected overlap at address: 0x1d00" in output

    def test_write_no_overlap(self):
        output = self.run_esptool(
            "write-flash 0x0 images/one_kb.bin 0x2000 images/one_kb.bin"
        )
        assert "Detected overlap at address" not in output

    def test_compressible_file(self):
        try:
            input_file = tempfile.NamedTemporaryFile(delete=False)
            file_size = 1024 * 1024
            input_file.write(b"\x00" * file_size)
            input_file.close()
            self.run_esptool(f"write-flash 0x10000 {input_file.name}")
        finally:
            os.unlink(input_file.name)

    def test_compressible_non_trivial_file(self):
        try:
            input_file = tempfile.NamedTemporaryFile(delete=False)
            file_size = 1000 * 1000
            same_bytes = 8000
            for _ in range(file_size // same_bytes):
                input_file.write(
                    struct.pack("B", random.randrange(0, 1 << 8)) * same_bytes
                )
            input_file.close()
            self.run_esptool(f"write-flash 0x10000 {input_file.name}")
        finally:
            os.unlink(input_file.name)

    @pytest.mark.quick_test
    def test_zero_length(self):
        # Zero length files are skipped with a warning
        output = self.run_esptool(
            "write-flash 0x10000 images/one_kb.bin 0x11000 images/zerolength.bin"
        )
        self.verify_readback(0x10000, 1024, "images/one_kb.bin")
        assert "'images/zerolength.bin' is empty" in output

    @pytest.mark.quick_test
    def test_single_byte(self):
        self.run_esptool("write-flash 0x0 images/onebyte.bin")
        self.verify_readback(0x0, 1, "images/onebyte.bin")

    def test_erase_range_messages(self):
        output = self.run_esptool(
            "write-flash 0x1000 images/sector.bin 0x0FC00 images/one_kb.bin"
        )
        assert "Flash will be erased from 0x00001000 to 0x00001fff..." in output
        assert (
            "Flash address 0x0000fc00 is not aligned to a 0x1000 "
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
            "write-flash 0x0 images/esp32s3_header.bin 0x1000 images/one_kb.bin"
        )
        assert "Unexpected chip ID in image." in output
        assert "value was 9. Is this image for a different chip model?" in output
        assert "'images/esp32s3_header.bin' is not an " in output
        assert "image. Use the force argument to flash anyway." in output

    @pytest.mark.skipif(
        arg_chip == "esp8266", reason="chip_id field exist in ESP32 and later images"
    )
    @pytest.mark.skipif(
        arg_chip != "esp32s3", reason="This check happens only on a valid image"
    )
    def test_write_image_for_another_revision(self):
        output = self.run_esptool_error(
            "write-flash 0x0 images/one_kb.bin 0x1000 images/esp32s3_header.bin"
        )
        assert "'images/esp32s3_header.bin' requires chip revision 10" in output
        assert "or higher (this chip is revision" in output
        assert "Use the force argument to flash anyway." in output

    @pytest.mark.skipif(
        arg_chip != "esp32c3", reason="This check happens only on a valid image"
    )
    def test_flash_with_min_max_rev(self):
        """Use min/max_rev_full field to specify chip revision"""
        output = self.run_esptool_error(
            "write-flash 0x0 images/one_kb.bin 0x1000 images/esp32c3_header_min_rev.bin"
        )
        assert (
            "'images/esp32c3_header_min_rev.bin' "
            "requires chip revision in range [v2.55 - max rev not set]" in output
        )
        assert "Use the force argument to flash anyway." in output

    @pytest.mark.quick_test
    def test_erase_before_write(self):
        output = self.run_esptool("write-flash --erase-all 0x0 images/one_kb.bin")
        assert "Flash memory erased successfully" in output
        assert "Hash of data verified" in output

    @pytest.mark.quick_test
    def test_flash_not_aligned_nostub(self):
        output = self.run_esptool("--no-stub write-flash 0x1 images/one_kb.bin")
        assert (
            "Flash address 0x00000001 is not aligned to a 0x1000 byte flash sector. "
            "0x1 bytes before this address will be erased." in output
        )
        if "ESPTOOL_TEST_USB_OTG" not in os.environ:
            assert "Hard resetting" in output

    @pytest.mark.skipif(arg_preload_port is False, reason="USB-JTAG/Serial only")
    @pytest.mark.skipif(arg_chip != "esp32c3", reason="ESP32-C3 only")
    def test_flash_overclocked(self):
        SYSTEM_BASE_REG = 0x600C0000
        SYSTEM_CPU_PER_CONF_REG = SYSTEM_BASE_REG + 0x008
        SYSTEM_CPUPERIOD_SEL_S = 0
        SYSTEM_CPUPERIOD_MAX = 1  # CPU_CLK frequency is 160 MHz

        SYSTEM_SYSCLK_CONF_REG = SYSTEM_BASE_REG + 0x058
        SYSTEM_SOC_CLK_SEL_S = 10
        SYSTEM_SOC_CLK_MAX = 1

        output = self.run_esptool(
            "--after no-reset-stub write-flash 0x0 images/one_mb.bin", preload=False
        )
        faster = re.search(r"(\d+(\.\d+)?)\s+seconds", output)
        assert faster, "Duration summary not found in the output"

        with esptool.cmds.detect_chip(
            port=arg_port, connect_mode="no-reset"
        ) as reg_mod:
            reg_mod.write_reg(
                SYSTEM_SYSCLK_CONF_REG,
                0,
                mask=(SYSTEM_SOC_CLK_MAX << SYSTEM_SOC_CLK_SEL_S),
            )
            sleep(0.1)
            reg_mod.write_reg(
                SYSTEM_CPU_PER_CONF_REG,
                0,
                mask=(SYSTEM_CPUPERIOD_MAX << SYSTEM_CPUPERIOD_SEL_S),
            )

        output = self.run_esptool(
            "--before no-reset write-flash 0x0 images/one_mb.bin", preload=False
        )
        slower = re.search(r"(\d+(\.\d+)?)\s+seconds", output)
        assert slower, "Duration summary not found in the output"
        assert float(slower.group(1)) - float(faster.group(1)) > 1, (
            "Overclocking failed"
        )

    @pytest.mark.skipif(arg_preload_port is False, reason="USB-JTAG/Serial only")
    @pytest.mark.skipif(arg_chip != "esp32c3", reason="ESP32-C3 only")
    def test_flash_watchdogs(self):
        RTC_WDT_ENABLE = 0xC927FA00  # Valid only for ESP32-C3

        with esptool.cmds.detect_chip(port=arg_port) as reg_mod:
            # Enable RTC WDT
            reg_mod.write_reg(
                reg_mod.RTC_CNTL_WDTWPROTECT_REG, reg_mod.RTC_CNTL_WDT_WKEY
            )
            reg_mod.write_reg(reg_mod.RTC_CNTL_WDTCONFIG0_REG, RTC_WDT_ENABLE)
            reg_mod.write_reg(reg_mod.RTC_CNTL_WDTWPROTECT_REG, 0)

            # Disable automatic feeding of SWD
            reg_mod.write_reg(
                reg_mod.RTC_CNTL_SWD_WPROTECT_REG, reg_mod.RTC_CNTL_SWD_WKEY
            )
            reg_mod.write_reg(
                reg_mod.RTC_CNTL_SWD_CONF_REG, 0, mask=reg_mod.RTC_CNTL_SWD_AUTO_FEED_EN
            )
            reg_mod.write_reg(reg_mod.RTC_CNTL_SWD_WPROTECT_REG, 0)

            reg_mod.sync_stub_detected = False
            reg_mod.run_stub()

        output = self.run_esptool(
            "--before no-reset --after no-reset-stub flash-id", preload=False
        )
        assert "Stub flasher is already running. No upload is necessary." in output

        sleep(10)  # Wait if RTC WDT triggers

        with esptool.cmds.detect_chip(
            port=arg_port, connect_mode="no-reset"
        ) as reg_mod:
            output = reg_mod.read_reg(reg_mod.RTC_CNTL_WDTCONFIG0_REG)
            assert output == 0, "RTC WDT is not disabled"

            output = reg_mod.read_reg(reg_mod.RTC_CNTL_SWD_CONF_REG)
            print(f"RTC_CNTL_SWD_CONF_REG: {output}")
            assert output & 0x80000000, "SWD auto feeding is not disabled"


@pytest.mark.skipif(
    arg_chip in ["esp8266", "esp32"],
    reason="get-security-info command is supported on ESP32S2 and later",
)
class TestSecurityInfo(EsptoolTestCase):
    def test_show_security_info(self):
        res = self.run_esptool("get-security-info")
        assert "Flags" in res
        assert "Crypt Count" in res
        if arg_chip != "esp32c2":
            assert "Key Purposes" in res
        if arg_chip != "esp32s2":
            try:
                esp = esptool.get_default_connected_device(
                    [arg_port], arg_port, 10, 115200, arg_chip
                )
                assert f"Chip ID: {esp.IMAGE_CHIP_ID}" in res
                assert "API Version" in res
            finally:
                esp._port.close()
        assert "Secure Boot" in res
        assert "Flash Encryption" in res


class TestFlashSizes(EsptoolTestCase):
    def test_high_offset(self):
        self.run_esptool("write-flash -fs 4MB 0x300000 images/one_kb.bin")
        self.verify_readback(0x300000, 1024, "images/one_kb.bin")

    def test_high_offset_no_compression(self):
        self.run_esptool("write-flash -u -fs 4MB 0x300000 images/one_kb.bin")
        self.verify_readback(0x300000, 1024, "images/one_kb.bin")

    def test_large_image(self):
        self.run_esptool("write-flash -fs 4MB 0x280000 images/one_mb.bin")
        self.verify_readback(0x280000, 0x100000, "images/one_mb.bin")

    def test_large_no_compression(self):
        self.run_esptool("write-flash -u -fs 4MB 0x280000 images/one_mb.bin")
        self.verify_readback(0x280000, 0x100000, "images/one_mb.bin")

    @pytest.mark.quick_test
    @pytest.mark.host_test
    def test_invalid_size_arg(self):
        self.run_esptool_error("write-flash -fs 10MB 0x6000 images/one_kb.bin")

    def test_write_past_end_fails(self):
        output = self.run_esptool_error(
            "write-flash -fs 1MB 0x280000 images/one_kb.bin"
        )
        assert "File 'images/one_kb.bin'" in output
        assert "will not fit" in output

    @pytest.mark.skipif(arg_chip != "esp32", reason="Don't need to test multiple times")
    def test_read_past_end_fails(self):
        output = self.run_esptool_error(
            "read-flash 0xffffff 1 out.bin"
        )  # 0xffffff is well past the end of the flash in most cases (16MB)
        assert "Can't access flash regions larger than detected flash size" in output

    def test_write_no_compression_past_end_fails(self):
        output = self.run_esptool_error(
            "write-flash -u -fs 1MB 0x280000 images/one_kb.bin"
        )
        assert "File 'images/one_kb.bin'" in output
        assert "will not fit" in output

    @pytest.mark.skipif(
        arg_chip not in ["esp8266", "esp32", "esp32c3"],
        reason="Don't run on every chip, so other bootloader images are not needed",
    )
    def test_flash_size_keep(self):
        offset = 0x1000 if arg_chip in ["esp32", "esp32s2"] else 0x0

        # this image is configured for 2MB (512KB on ESP8266) flash by default.
        # assume this is not the flash size in use
        image = f"images/bootloader_{arg_chip}.bin"

        with open(image, "rb") as f:
            f.seek(0, 2)
            image_len = f.tell()
        self.run_esptool(f"write-flash -fs keep {offset} {image}")
        # header should be the same as in the .bin file
        self.verify_readback(offset, image_len, image)

    @pytest.mark.skipif(
        arg_chip == "esp8266", reason="ESP8266 does not support read_flash_slow"
    )
    def test_read_nostub_high_offset(self):
        offset = 0x300000
        length = 1024
        self.run_esptool(f"write-flash -fs detect {offset} images/one_kb.bin")
        dump_file = tempfile.NamedTemporaryFile(delete=False)
        # readback with no-stub and flash-size set
        try:
            self.run_esptool(
                f"--no-stub read-flash -fs detect {offset} 1k {dump_file.name}"
            )
            with open(dump_file.name, "rb") as f:
                rb = f.read()
            rb_len = len(rb)
            assert length == rb_len, (
                f"read-flash length {length} offset {offset:#x} yielded {rb_len} bytes!"
            )
        finally:
            dump_file.close()
            os.unlink(dump_file.name)
        # compare files
        with open("images/one_kb.bin", "rb") as f:
            ct = f.read()
        self.diff(rb, ct)


class TestFlashDetection(EsptoolTestCase):
    @pytest.mark.quick_test
    def test_flash_id(self):
        """Test manufacturer and device response of flash detection."""
        res = self.run_esptool("flash-id")
        assert "Manufacturer:" in res
        assert "Device:" in res

    @pytest.mark.quick_test
    def test_flash_id_expand_args(self):
        """
        Test manufacturer and device response of flash detection with expandable arg
        """
        try:
            arg_file = tempfile.NamedTemporaryFile(delete=False)
            arg_file.write(b"flash-id\n")
            arg_file.close()
            res = self.run_esptool(f"@{arg_file.name}")
            assert "Manufacturer:" in res
            assert "Device:" in res
        finally:
            os.unlink(arg_file.name)

    @pytest.mark.quick_test
    def test_flash_id_trace(self):
        """Test trace functionality on flash detection, running without stub"""
        res = self.run_esptool("--trace flash-id")
        # read register command
        assert (
            re.search(r"TRACE \+\d.\d{3}   --- Cmd READ_REG \(0x0a\) .*", res)
            is not None
        )
        # write register command
        assert (
            re.search(r"TRACE \+\d.\d{3}   --- Cmd WRITE_REG \(0x09\) .*", res)
            is not None
        )
        assert re.search(r"TRACE \+\d.\d{3}   Read \d* bytes:", res) is not None
        assert re.search(r"TRACE \+\d.\d{3}   Write \d+ bytes:", res) is not None
        assert (
            re.search(r"TRACE \+\d.\d{3}   Received full packet: .*", res) is not None
        )
        # flasher stub handshake
        assert (
            re.search(r"TRACE \+\d.\d{3}   Received full packet: 4f484149", res)
            is not None
        )
        assert "Manufacturer:" in res
        assert "Device:" in res

    @pytest.mark.quick_test
    @pytest.mark.skipif(
        arg_chip not in ["esp32c2"],
        reason="This test make sense only for EPS32-C2",
    )
    def test_flash_size(self):
        """Test ESP32-C2 efuse block for flash size feature"""
        # ESP32-C2 class inherits methods from ESP32-C3 class
        # but it does not have the same amount of efuse blocks
        # the methods are overwritten
        # in case anything changes this test will fail to remind us
        res = self.run_esptool("flash-id")
        lines = res.splitlines()
        for line in lines:
            assert "embedded flash" not in line.lower()

    @pytest.mark.quick_test
    def test_flash_sfdp(self):
        """Test manufacturer and device response of flash detection."""
        res = self.run_esptool("read-flash-sfdp 0 4")
        assert "SFDP[0..3]: 0x53 0x46 0x44 0x50" in res
        res = self.run_esptool("read-flash-sfdp 1 3")
        assert "SFDP[1..3]: 0x46 0x44 0x50" in res


@pytest.mark.skipif(
    os.getenv("ESPTOOL_TEST_SPI_CONN") is None, reason="Needs external flash"
)
class TestExternalFlash(EsptoolTestCase):
    conn = os.getenv("ESPTOOL_TEST_SPI_CONN")

    def test_short_flash_to_external_stub(self):
        # First flash internal flash, then external
        self.run_esptool("write-flash 0x0 images/one_kb.bin")
        self.run_esptool(
            f"write-flash --spi-connection {self.conn} 0x0 images/sector.bin"
        )

        self.verify_readback(0, 1024, "images/one_kb.bin")
        self.verify_readback(0, 1024, "images/sector.bin", spi_connection=self.conn)

        # First flash external flash, then internal
        self.run_esptool(
            f"write-flash --spi-connection {self.conn} 0x0 images/one_kb.bin"
        )
        self.run_esptool("write-flash 0x0 images/sector.bin")

        self.verify_readback(0, 1024, "images/sector.bin")
        self.verify_readback(0, 1024, "images/one_kb.bin", spi_connection=self.conn)

    def test_short_flash_to_external_ROM(self):
        # First flash internal flash, then external
        self.run_esptool("--no-stub write-flash 0x0 images/one_kb.bin")
        self.run_esptool(
            f"--no-stub write-flash --spi-connection {self.conn} 0x0 images/sector.bin"
        )

        self.verify_readback(0, 1024, "images/one_kb.bin")
        self.verify_readback(0, 1024, "images/sector.bin", spi_connection=self.conn)

        # First flash external flash, then internal
        self.run_esptool(
            f"--no-stub write-flash --spi-connection {self.conn} 0x0 images/one_kb.bin"
        )
        self.run_esptool("--no-stub write-flash 0x0 images/sector.bin")

        self.verify_readback(0, 1024, "images/sector.bin")
        self.verify_readback(0, 1024, "images/one_kb.bin", spi_connection=self.conn)


@pytest.mark.skipif(
    "ESPTOOL_TEST_USB_OTG" in os.environ,
    reason="USB-OTG tests require --after no-reset for stability.",
)
class TestStubReuse(EsptoolTestCase):
    def test_stub_reuse_with_synchronization(self):
        """Keep the flasher stub running and reuse it the next time."""
        res = self.run_esptool(
            "--after no-reset-stub flash-id"
        )  # flasher stub keeps running after this
        assert "Manufacturer:" in res
        res = self.run_esptool(
            "--before no-reset flash-id",
            preload=False,
        )  # do sync before (without reset it talks to the flasher stub)
        assert "Manufacturer:" in res

    def test_stub_reuse_without_synchronization(self):
        """
        Keep the flasher stub running and reuse it the next time
        without synchronization.
        """
        res = self.run_esptool("--after no-reset-stub flash-id")
        assert "Manufacturer:" in res
        res = self.run_esptool("--before no-reset-no-sync flash-id", preload=False)
        assert "Manufacturer:" in res


class TestErase(EsptoolTestCase):
    @pytest.mark.quick_test
    def test_chip_erase(self):
        self.run_esptool("write-flash 0x10000 images/one_kb.bin")
        self.verify_readback(0x10000, 0x400, "images/one_kb.bin")
        self.run_esptool("erase-flash")
        empty = self.readback(0x10000, 0x400)
        assert empty == b"\xff" * 0x400

    def test_region_erase(self):
        self.run_esptool("write-flash 0x10000 images/one_kb.bin")
        self.run_esptool("write-flash 0x11000 images/sector.bin")
        self.verify_readback(0x10000, 0x400, "images/one_kb.bin")
        self.verify_readback(0x11000, 0x1000, "images/sector.bin")
        # erase only the flash sector containing one_kb.bin
        self.run_esptool("erase-region 0x10000 0x1000")
        self.verify_readback(0x11000, 0x1000, "images/sector.bin")
        empty = self.readback(0x10000, 0x1000)
        assert empty == b"\xff" * 0x1000

    def test_region_erase_all(self):
        res = self.run_esptool("erase-region 0x0 ALL")
        assert re.search(r"Detected flash size: \d+[KM]B", res) is not None

    def test_large_region_erase(self):
        # verifies that erasing a large region doesn't time out
        self.run_esptool("erase-region 0x0 0x100000")

    @pytest.mark.skipif(arg_chip == "esp8266", reason="Not supported on ESP8266")
    def test_region_erase_no_stub(self):
        self.run_esptool("write-flash 0x10000 images/one_kb.bin")
        self.run_esptool("write-flash 0x11000 images/sector.bin")
        self.verify_readback(0x10000, 0x400, "images/one_kb.bin")
        self.verify_readback(0x11000, 0x1000, "images/sector.bin")
        # erase only the flash sector containing one_kb.bin
        self.run_esptool("--no-stub erase-region 0x10000 0x1000")
        self.verify_readback(0x11000, 0x1000, "images/sector.bin")
        empty = self.readback(0x10000, 0x1000)
        assert empty == b"\xff" * 0x1000


class TestSectorBoundaries(EsptoolTestCase):
    def test_end_sector(self):
        self.run_esptool("write-flash 0x10000 images/sector.bin")
        self.run_esptool("write-flash 0x0FC00 images/one_kb.bin")
        self.verify_readback(0x0FC00, 0x400, "images/one_kb.bin")
        self.verify_readback(0x10000, 0x1000, "images/sector.bin")

    def test_end_sector_uncompressed(self):
        self.run_esptool("write-flash -u 0x10000 images/sector.bin")
        self.run_esptool("write-flash -u 0x0FC00 images/one_kb.bin")
        self.verify_readback(0x0FC00, 0x400, "images/one_kb.bin")
        self.verify_readback(0x10000, 0x1000, "images/sector.bin")

    def test_overlap(self):
        self.run_esptool("write-flash 0x20800 images/sector.bin")
        self.verify_readback(0x20800, 0x1000, "images/sector.bin")


class TestVerifyCommand(EsptoolTestCase):
    @pytest.mark.quick_test
    def test_verify_success(self):
        self.run_esptool("write-flash 0x5000 images/one_kb.bin")
        self.run_esptool("verify-flash 0x5000 images/one_kb.bin")

    def test_verify_failure(self):
        self.run_esptool("write-flash 0x6000 images/sector.bin")
        output = self.run_esptool_error("verify-flash --diff 0x6000 images/one_kb.bin")
        assert "Verification failed:" in output
        assert "first at 0x00006000:" in output

    def test_verify_unaligned_length(self):
        self.run_esptool("write-flash 0x0 images/not_4_byte_aligned.bin")
        self.run_esptool("verify-flash 0x0 images/not_4_byte_aligned.bin")


class TestReadIdentityValues(EsptoolTestCase):
    @pytest.mark.quick_test
    def test_read_mac(self):
        output = self.run_esptool("read-mac")
        mac = re.search(r"[0-9a-f:]{17}", output)
        assert mac is not None
        mac = mac.group(0)
        assert mac != "00:00:00:00:00:00"
        assert mac != "ff:ff:ff:ff:ff:ff"

    @pytest.mark.skipif(arg_chip != "esp8266", reason="ESP8266 only")
    def test_read_chip_id(self):
        output = self.run_esptool("chip-id")
        idstr = re.search("Chip ID: 0x([0-9a-f]+)", output)
        assert idstr is not None
        idstr = idstr.group(1)
        assert idstr != "0" * 8
        assert idstr != "f" * 8


class TestMemoryOperations(EsptoolTestCase):
    @pytest.mark.quick_test
    def test_memory_dump(self):
        output = self.run_esptool("dump-mem 0x50000000 128 memout.bin")
        assert "Dumped 128 bytes from 0x50000000" in output
        assert "to 'memout.bin'" in output
        os.remove("memout.bin")

    def test_memory_write(self):
        output = self.run_esptool("write-mem 0x400C0000 0xabad1dea 0x0000ffff")
        assert "Wrote 0xabad1dea" in output
        assert "mask 0x0000ffff" in output
        assert "to 0x400c0000" in output

    def test_memory_read(self):
        output = self.run_esptool("read-mem 0x400C0000")
        assert "0x400c0000 =" in output


class TestKeepImageSettings(EsptoolTestCase):
    """Tests for the -fm keep, -ff keep options for write-flash"""

    @classmethod
    def setup_class(self):
        super(TestKeepImageSettings, self).setup_class()
        self.BL_IMAGE = f"images/bootloader_{arg_chip}.bin"
        self.flash_offset = esptool.CHIP_DEFS[arg_chip].BOOTLOADER_FLASH_OFFSET
        with open(self.BL_IMAGE, "rb") as f:
            self.header = f.read(8)

    @pytest.mark.skipif(
        arg_chip not in ["esp8266", "esp32", "esp32c3"],
        reason="Don't run on every chip, so other bootloader images are not needed",
    )
    def test_keep_does_not_change_settings(self):
        # defaults should all be keep
        self.run_esptool(f"write-flash -fs keep {self.flash_offset:#x} {self.BL_IMAGE}")
        self.verify_readback(self.flash_offset, 8, self.BL_IMAGE, False)
        # can also explicitly set all options
        self.run_esptool(
            f"write-flash -fm keep -ff keep -fs keep "
            f"{self.flash_offset:#x} {self.BL_IMAGE}"
        )
        self.verify_readback(self.flash_offset, 8, self.BL_IMAGE, False)
        # verify-flash should also use 'keep'
        self.run_esptool(
            f"verify-flash -fs keep {self.flash_offset:#x} {self.BL_IMAGE}"
        )

    @pytest.mark.skipif(
        arg_chip not in ["esp8266", "esp32", "esp32c3"],
        reason="Don't run for every chip, so other bootloader images are not needed",
    )
    @pytest.mark.quick_test
    def test_detect_size_changes_size(self):
        self.run_esptool(
            f"write-flash -fs detect {self.flash_offset:#x} {self.BL_IMAGE}"
        )
        readback = self.readback(self.flash_offset, 8)
        assert self.header[:3] == readback[:3]  # first 3 bytes unchanged
        assert self.header[3] != readback[3]  # size_freq byte changed
        assert self.header[4:] == readback[4:]  # rest unchanged

    @pytest.mark.skipif(
        arg_chip not in ["esp8266", "esp32"],
        reason="Bootloader header needs to be modifiable - without sha256",
    )
    def test_explicit_set_size_freq_mode(self):
        self.run_esptool(
            f"write-flash -fs 2MB -fm dout -ff 80m "
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

        # verify-flash should pass if we match params, fail otherwise
        self.run_esptool(
            f"verify-flash -fs 2MB -fm dout -ff 80m "
            f"{self.flash_offset:#x} {self.BL_IMAGE}"
        )
        self.run_esptool_error(f"verify-flash {self.flash_offset:#x} {self.BL_IMAGE}")


@pytest.mark.skipif(
    arg_chip in ["esp32s2", "esp32s3", "esp32p4"],
    reason="Not supported on targets with USB-CDC.",
)
class TestLoadRAM(EsptoolTestCase):
    # flashing an application not supporting USB-CDC will make
    # /dev/ttyACM0 disappear and USB-CDC tests will not work anymore

    def verify_output(self, expected_out: list[bytes]):
        """Verify that at least one element of expected_out is in serial output"""
        # Setting rtscts to true enables hardware flow control.
        # This removes unwanted RTS logic level changes for some machines
        # (and, therefore, chip resets)
        # when the port is opened by the following function.
        # As a result, the app loaded to RAM has a chance to run and send
        # "Hello world" data without unwanted chip reset.
        with serial.serial_for_url(arg_port, arg_baud, rtscts=True) as p:
            p.timeout = 5
            output = p.read(100)
            print(f"Output: {output}")
            assert any(item in output for item in expected_out)

    @pytest.mark.quick_test
    def test_load_ram(self):
        """Verify load-ram command

        The "hello world" binary programs for each chip print
        "Hello world!\n" to the serial port.
        """
        self.run_esptool(f"load-ram images/ram_helloworld/helloworld-{arg_chip}.bin")
        self.verify_output(
            [b"Hello world!", b'\xce?\x13\x05\x04\xd0\x97A\x11"\xc4\x06\xc67\x04']
        )

    def test_load_ram_hex(self):
        """Verify load-ram command with hex file as input

        The "hello world" binary programs for each chip print
        "Hello world!\n" to the serial port.
        """
        fd, f = tempfile.mkstemp(suffix=".hex")
        try:
            self.run_esptool(
                f"merge-bin --format hex -o {f} 0x0 "
                f"images/ram_helloworld/helloworld-{arg_chip}.bin"
            )
            # make sure file is closed before running next command (mainly for Windows)
            os.close(fd)
            self.run_esptool(f"load-ram {f}")
            self.verify_output(
                [b"Hello world!", b'\xce?\x13\x05\x04\xd0\x97A\x11"\xc4\x06\xc67\x04']
            )
        finally:
            os.unlink(f)


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
        self.run_esptool("write-flash 0x0 images/esp8266_deepsleep.bin", baud=230400)

        sleep(0.25)  # give ESP8266 time to enter deep sleep

        self.run_esptool("write-flash 0x0 images/fifty_kb.bin", baud=230400)
        self.verify_readback(0, 50 * 1024, "images/fifty_kb.bin")


class TestBootloaderHeaderRewriteCases(EsptoolTestCase):
    @pytest.mark.skipif(
        arg_chip not in ["esp8266", "esp32", "esp32c3"],
        reason="Don't run on every chip, so other bootloader images are not needed",
    )
    @pytest.mark.quick_test
    def test_flash_header_rewrite(self):
        bl_offset = esptool.CHIP_DEFS[arg_chip].BOOTLOADER_FLASH_OFFSET
        bl_image = f"images/bootloader_{arg_chip}.bin"

        output = self.run_esptool(
            f"write-flash -fm dout -ff 20m {bl_offset:#x} {bl_image}"
        )
        if arg_chip in ["esp8266", "esp32"]:
            # ESP8266 lacks this feature; ESP32 test image doesn't include it
            assert "Flash parameters set to" in output
        else:
            assert "Flash parameters set to" in output
            # Since SHA recalculation is supported for changed bootloader header
            assert "SHA digest in image updated" in output

    def test_flash_header_no_magic_no_rewrite(self):
        # first image doesn't start with magic byte, second image does
        # but neither are valid bootloader binary images for either chip
        bl_offset = esptool.CHIP_DEFS[arg_chip].BOOTLOADER_FLASH_OFFSET
        for image in ["images/one_kb.bin", "images/one_kb_all_ef.bin"]:
            output = self.run_esptool(
                f"write-flash -fm dout -ff 20m {bl_offset:#x} {image}"
            )
            "not changing any flash settings" in output
            self.verify_readback(bl_offset, 1024, image)


class TestAutoDetect(EsptoolTestCase):
    def _check_output(self, output):
        expected_chip_name = esptool.util.expand_chip_name(arg_chip)
        assert f"Detecting chip type... {expected_chip_name}" in output
        assert f"{'Chip type:':<20}{expected_chip_name}" in output

    @pytest.mark.quick_test
    def test_auto_detect(self):
        output = self.run_esptool("chip-id", chip="auto")
        self._check_output(output)


class TestChipDetectionValidation(EsptoolTestCase):
    """Test the chip detection validation logic in ESPLoader.connect() method.

    This tests the section that validates if the connected chip matches the
    specified chip argument, covering scenarios with:
    - Chips that use chip ID detection (ESP32-S3 and later)
    - Chips that use magic value detection (ESP8266, ESP32, ESP32-S2)
    - ESP32-S2 in Secure Download Mode (SDM)
    - Correct chip argument vs wrong chip argument detection
    """

    def _find_different_chip(self, chip_name, detection_method):
        """Find a different chip from the specified chip name
        based on the detection method, except ESP32-S2.

        Args:
            chip_name: The name of the chip to find a different chip for.
            detection_method: The detection method to use.

        Returns:
            The name of the different chip.
        """
        for chip in esptool.CHIP_DEFS:
            if chip != chip_name and chip != "esp32s2":
                if (
                    detection_method == "chip_id"
                    and not esptool.CHIP_DEFS[chip].USES_MAGIC_VALUE
                ):
                    if (
                        esptool.CHIP_DEFS[chip].IMAGE_CHIP_ID
                        != esptool.CHIP_DEFS[chip_name].IMAGE_CHIP_ID
                    ):
                        return chip
                elif (
                    detection_method == "magic_value"
                    and esptool.CHIP_DEFS[chip].USES_MAGIC_VALUE
                ):
                    if (
                        esptool.CHIP_DEFS[chip].MAGIC_VALUE
                        != esptool.CHIP_DEFS[chip_name].MAGIC_VALUE
                    ):
                        return chip

    @pytest.mark.quick_test
    def test_chips_with_chip_id_detection(self):
        # First verify the correct chip works
        output = self.run_esptool(f"--chip {arg_chip} flash-id")
        assert "Stub flasher running." in output

        # Find a different chip with different chip ID to test mismatch detection
        different_chip_id = self._find_different_chip(arg_chip, "chip_id")
        error_output = self.run_esptool_error(f"--chip {different_chip_id} flash-id")
        assert (
            f"This chip is {arg_chip.upper()}, not {different_chip_id.upper()}."
            in error_output
            or "Wrong chip argument?" in error_output
        )

        # Find a different chip with different magic value to test mismatch detection
        different_chip_magic = self._find_different_chip(arg_chip, "magic_value")
        error_output = self.run_esptool_error(f"--chip {different_chip_magic} flash-id")
        assert (
            f"This chip is {arg_chip.upper()}, not {different_chip_magic.upper()}."
            in error_output
            or "Wrong chip argument?" in error_output
        )

        if arg_chip != "esp32s2":
            # ESP32-S2 is special case that has security info, but not chip ID
            error_output = self.run_esptool_error("--chip esp32s2 flash-id")
            assert (
                f"This chip is {arg_chip.upper()}, not ESP32-S2." in error_output
                or "Wrong chip argument?" in error_output
            )


class TestUSBMode(EsptoolTestCase):
    @pytest.mark.quick_test
    def test_usb_mode(self):
        output = self.run_esptool("chip-id")
        expected_usb_mode = (
            "USB-OTG"
            if os.environ.get("ESPTOOL_TEST_USB_OTG") == "1"
            else "USB-Serial/JTAG"
            if arg_preload_port
            else None
        )

        if expected_usb_mode:
            assert "USB mode: " in output
            assert expected_usb_mode in output


@pytest.mark.flaky(reruns=5)
@pytest.mark.skipif(arg_preload_port is not False, reason="USB-to-UART bridge only")
@pytest.mark.skipif(os.name == "nt", reason="Linux/MacOS only")
class TestVirtualPort(TestAutoDetect):
    def test_auto_detect_virtual_port(self):
        with ESPRFC2217Server() as server:
            output = self.run_esptool(
                "chip-id",
                chip="auto",
                port=f"rfc2217://localhost:{str(server.port)}?ign_set_control",
            )
            self._check_output(output)

    def test_highspeed_flash_virtual_port(self):
        with ESPRFC2217Server() as server:
            rfc2217_port = f"rfc2217://localhost:{str(server.port)}?ign_set_control"
            self.run_esptool(
                "write-flash 0x0 images/fifty_kb.bin",
                baud=921600,
                port=rfc2217_port,
            )
        self.verify_readback(0, 50 * 1024, "images/fifty_kb.bin")

    @pytest.fixture
    def pty_port(self):
        import pty

        master_fd, slave_fd = pty.openpty()
        yield os.ttyname(slave_fd)
        os.close(master_fd)
        os.close(slave_fd)

    @pytest.mark.host_test
    def test_pty_port(self, pty_port):
        cmd = [sys.executable, "-m", "esptool", "--port", pty_port, "chip-id"]
        output = subprocess.run(
            cmd,
            cwd=TEST_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        # no chip connected so command should fail
        assert output.returncode != 0
        output = output.stdout.decode("utf-8")
        print(output)  # for logging
        assert "Chip was NOT reset." in output


@pytest.mark.quick_test
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
                if arg_chip == "esp32c61":
                    # Write into the "BYTE_ACCESSIBLE" space and after the stub
                    region = esp.get_memory_region("DRAM")
                    test_addr = region[1] - 0x2FFFF
                elif arg_chip == "esp32c2":
                    # Write at the end of DRAM on ESP32-C2 to avoid overwriting the stub
                    test_addr = region[1] - 8
                else:
                    test_addr = region[0]
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
            esp._port.close()

    def test_read_write_memory_rom(self):
        try:
            esp = esptool.get_default_connected_device(
                [arg_port], arg_port, 10, 115200, arg_chip
            )
            self._test_read_write(esp)
        finally:
            esp._port.close()

    def test_read_write_memory_stub(self):
        try:
            esp = esptool.get_default_connected_device(
                [arg_port], arg_port, 10, 115200, arg_chip
            )
            esp = esp.run_stub()
            self._test_read_write(esp)
        finally:
            esp._port.close()

    @pytest.mark.skipif(
        arg_chip != "esp32", reason="Could be unsupported by different flash"
    )
    def test_read_write_flash_status(self):
        """Read flash status and write back the same status"""
        res = self.run_esptool("read-flash-status")
        match = re.search(r"Flash memory status: (0x[\d|a-f]*)", res)
        assert match is not None
        res = self.run_esptool(f"write-flash-status {match.group(1)}")
        assert f"Initial flash memory status: {match.group(1)}" in res
        assert f"Setting flash memory status: {match.group(1)}" in res
        assert f"After flash memory status:   {match.group(1)}" in res

    def test_read_chip_description(self):
        try:
            esp = esptool.get_default_connected_device(
                [arg_port], arg_port, 10, 115200, arg_chip
            )
            chip = esp.get_chip_description()
            assert "unknown" not in chip.lower()
        finally:
            esp._port.close()

    def test_read_get_chip_features(self):
        try:
            esp = esptool.get_default_connected_device(
                [arg_port], arg_port, 10, 115200, arg_chip
            )

            if hasattr(esp, "get_flash_cap") and esp.get_flash_cap() == 0:
                esp.get_flash_cap = MagicMock(return_value=1)
            if hasattr(esp, "get_psram_cap") and esp.get_psram_cap() == 0:
                esp.get_psram_cap = MagicMock(return_value=1)

            features = ", ".join(esp.get_chip_features())
            assert "Unknown Embedded Flash" not in features
            assert "Unknown Embedded PSRAM" not in features
        finally:
            esp._port.close()


@pytest.mark.skipif(
    "ESPTOOL_TEST_USB_OTG" in os.environ or arg_preload_port is not False,
    reason="Boot mode strapping pin pulled constantly low, "
    "can't reset out of bootloader",
)
class TestReset(EsptoolTestCase):
    def test_watchdog_reset(self):
        # Erase the bootloader to get "invalid header" output + test watchdog reset
        res = self.run_esptool("--after watchdog-reset erase-region 0x0 0x4000")
        if arg_chip in ["esp8266", "esp32", "esp32h2", "esp32c6"]:
            assert "Watchdog hard reset is not supported" in res
            assert "Hard resetting via RTS pin..." in res
        else:
            assert "Hard resetting with a watchdog..." in res
            # If there is no output, the chip did not reset
            # Mangled bytes are for C2 26 MHz when the baudrate doesn't match
            self.verify_output(
                [b"invalid header", b"\x02b\xe2n\x9e\xe0p\x12n\x9c\x0cn"]
            )


@pytest.mark.skipif(arg_chip != "esp32", reason="Don't need to test multiple times")
@pytest.mark.quick_test
class TestConfigFile(EsptoolTestCase):
    class ConfigFile:
        """
        A class-based context manager to create
        a custom config file and delete it after usage.
        """

        def __init__(self, file_path, file_content):
            self.file_path = file_path
            self.file_content = file_content

        def __enter__(self):
            with open(self.file_path, "w") as cfg_file:
                cfg_file.write(self.file_content)
                return cfg_file

        def __exit__(self, exc_type, exc_value, exc_tb):
            os.unlink(self.file_path)
            assert not os.path.exists(self.file_path)

    dummy_config = (
        "[esptool]\nconnect_attempts = 5\nreset_delay = 1\nserial_write_timeout = 12"
    )

    @pytest.mark.host_test
    def test_load_config_file(self):
        # Test a valid file is loaded
        config_file_path = os.path.join(os.getcwd(), "esptool.cfg")
        with self.ConfigFile(config_file_path, self.dummy_config):
            output = self.run_esptool("version")
            assert f"Loaded custom configuration from {config_file_path}" in output
            assert "Ignoring unknown config file option" not in output
            assert "Ignoring invalid config file" not in output

        # Test invalid files are ignored
        # Wrong section header, no config gets loaded
        with self.ConfigFile(config_file_path, "[wrong section name]"):
            output = self.run_esptool("version")
            assert f"Loaded custom configuration from {config_file_path}" not in output

        # Correct header, but options are unparsable
        faulty_config = "[esptool]\nconnect_attempts = 5\nconnect_attempts = 9\n"
        with self.ConfigFile(config_file_path, faulty_config):
            output = self.run_esptool("version")
            assert f"Ignoring invalid config file {config_file_path}" in output
            assert (
                "option 'connect_attempts' in section 'esptool' already exists"
                in output
            )

        # Correct header, unknown option (or a typo)
        faulty_config = "[esptool]\nconnect_attempts = 9\ntimoout = 2\nbits = 2"
        with self.ConfigFile(config_file_path, faulty_config):
            output = self.run_esptool("version")
            assert "Ignoring unknown config file options: bits, timoout" in output

        # Test other config files (setup.cfg, tox.ini) are loaded
        config_file_path = os.path.join(os.getcwd(), "tox.ini")
        with self.ConfigFile(config_file_path, self.dummy_config):
            output = self.run_esptool("version")
            assert f"Loaded custom configuration from {config_file_path}" in output

    @pytest.mark.host_test
    def test_load_config_file_with_env_var(self):
        config_file_path = os.path.join(TEST_DIR, "custom_file.ini")
        with self.ConfigFile(config_file_path, self.dummy_config):
            # Try first without setting the env var, check that no config gets loaded
            output = self.run_esptool("version")
            assert f"Loaded custom configuration from {config_file_path}" not in output

            # Set the env var and try again, check that config was loaded
            tmp = os.environ.get("ESPTOOL_CFGFILE")  # Save the env var if it is set

            os.environ["ESPTOOL_CFGFILE"] = config_file_path
            output = self.run_esptool("version")
            assert f"Loaded custom configuration from {config_file_path}" in output
            assert "(set with ESPTOOL_CFGFILE)" in output

            if tmp is not None:  # Restore the env var or unset it
                os.environ["ESPTOOL_CFGFILE"] = tmp
            else:
                os.environ.pop("ESPTOOL_CFGFILE", None)

    def test_custom_reset_sequence(self):
        # This reset sequence will fail to reset the chip to bootloader,
        # the flash-id operation should therefore fail.
        # Also tests the number of connection attempts.
        reset_seq_config = (
            "[esptool]\n"
            "custom_reset_sequence = D0|W0.1|R1|R0|W0.1|R1|R0\n"
            "connect_attempts = 1\n"
        )
        config_file_path = os.path.join(os.getcwd(), "esptool.cfg")
        with self.ConfigFile(config_file_path, reset_seq_config):
            output = self.run_esptool_error("flash-id")
            assert f"Loaded custom configuration from {config_file_path}" in output
            assert "A fatal error occurred: Failed to connect to" in output
            # Connection attempts are represented with dots,
            # there are enough dots for two attempts here, but only one is executed
            assert "Connecting............." not in output

        # Test invalid custom_reset_sequence format is not accepted
        invalid_reset_seq_config = "[esptool]\ncustom_reset_sequence = F0|R1|C0|A5\n"
        with self.ConfigFile(config_file_path, invalid_reset_seq_config):
            output = self.run_esptool_error("flash-id")
            assert f"Loaded custom configuration from {config_file_path}" in output
            assert "Invalid custom reset sequence option format:" in output

    def test_open_port_attempts(self):
        # Test that the open_port_attempts option is loaded correctly
        connect_attempts = 5
        config = (
            "[esptool]\n"
            f"open_port_attempts = {connect_attempts}\n"
            "connect_attempts = 1\n"
            "custom_reset_sequence = D0\n"
        )  # Invalid reset sequence to make sure connection fails
        config_file_path = os.path.join(os.getcwd(), "esptool.cfg")
        with self.ConfigFile(config_file_path, config):
            output = self.run_esptool_error("flash-id")
            assert f"Loaded custom configuration from {config_file_path}" in output
            assert "Retrying failed connection" in output
            for _ in range(connect_attempts):
                assert "Connecting........" in output


@pytest.mark.skipif(
    "ESPTOOL_TEST_USB_OTG" in os.environ,
    reason="May cause port disappearing in USB-OTG mode on CI.",
)
class TestESPObjectOperations(EsptoolTestCase):
    def capture_stdout(test_function):
        """Decorator to capture stdout."""

        def wrapper(*args, **kwargs):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                test_function(*args, **kwargs, fake_out=fake_out)

        return wrapper

    @pytest.mark.skipif(
        arg_chip in ["esp32s2", "esp32p4"],
        reason="ESP32-S2 attaches the flash even without explicit attach",
    )
    @pytest.mark.quick_test
    @capture_stdout
    def test_attach_flash(self, fake_out):
        with esptool.CHIP_DEFS[arg_chip](port=arg_port) as esp:
            # Try communicating with the flash chip without attaching it
            esp.connect()
            flash_id(esp)
            read_flash_sfdp(esp, 0, 4)
            output_pre = fake_out.getvalue()
            # Clear the output buffer
            fake_out.truncate(0)
            fake_out.seek(0)
            # Attach the flash chip and try again
            attach_flash(esp)
            flash_id(esp)
            read_flash_sfdp(esp, 0, 4)
            reset_chip(esp, "hard-reset")
            output_post = fake_out.getvalue()
        assert "Detected flash size: Unknown" in output_pre
        assert "Device: ffff" in output_pre or "Device: 0000" in output_pre
        assert (
            "SFDP[0..3]: 0xff 0xff 0xff 0xff" in output_pre
            or "SFDP[0..3]: 0x00 0x00 0x00 0x00" in output_pre
        )
        assert "Detected flash size: Unknown" not in output_post
        assert "Device: ffff" not in output_post
        assert "SFDP[0..3]: 0x53 0x46 0x44 0x50" in output_post

    @pytest.mark.quick_test
    @capture_stdout
    def test_stub_run(self, fake_out):
        with esptool.CHIP_DEFS[arg_chip](port=arg_port) as esp:
            esp.connect()
            esp = esp.run_stub()
            read_mac(esp)
            reset_chip(esp, "hard-reset")
            output = fake_out.getvalue()
        assert "Stub flasher running" in output
        assert "MAC:" in output

    @capture_stdout
    def test_flash_operations(self, fake_out):
        with detect_chip(port=arg_port) as esp:  # Test with chip autodetection
            esp = esp.run_stub()
            try:
                attach_flash(esp)
                with open("images/one_kb.bin", "rb") as input:
                    write_flash(esp, [(0x0, input), (0x2000, input)])
                    read_flash(esp, 0x0, 0x2400, "output.bin")
                    verify_flash(esp, [(0x0, input), (0x2000, input)])
                with open("output.bin", "rb") as output:
                    verify_flash(esp, [(0x0, output)])
                erase_flash(esp)
                read_flash(esp, 0x0, 0x10, "output.bin")
            finally:
                reset_chip(esp, "hard-reset")
                os.remove("output.bin")
        output = fake_out.getvalue()
        assert "Stub flasher running" in output
        assert "Hash of data verified" in output
        assert "Read 9216 bytes" in output
        assert "Verification successful (digest matched)" in output
        assert "Flash memory erased successfully" in output
        assert "Hard resetting" in output

    @pytest.mark.quick_test
    @pytest.mark.host_test
    @capture_stdout
    def test_non_esp_operations(self, fake_out):
        image_info("images/bootloader_esp32.bin")
        with open("images/one_kb.bin", "rb") as input:
            try:
                merge_bin([(0x0, input), (0x2000, input)], arg_chip, "output.bin")
            finally:
                os.remove("output.bin")
        version()
        output = fake_out.getvalue()
        assert "Detected image type: ESP32" in output
        assert "Checksum: 0x83 (valid)" in output
        assert "Wrote 0x2400 bytes to file 'output.bin'" in output
        assert esptool.__version__ in output


@pytest.mark.host_test
class TestOldScripts:
    def test_esptool_py(self):
        output = subprocess.check_output(["esptool.py", "-h"])
        decoded = output.decode("utf-8")
        assert "esptool.py" in decoded
        assert "DEPRECATED" in decoded

    def test_espefuse_py(self):
        output = subprocess.check_output(["espefuse.py", "-h"])
        decoded = output.decode("utf-8")
        assert "espefuse.py" in decoded
        assert "DEPRECATED" in decoded

    def test_espsecure_py(self):
        output = subprocess.check_output(["espsecure.py", "-h"])
        decoded = output.decode("utf-8")
        assert "espsecure.py" in decoded
        assert "DEPRECATED" in decoded

    def test_esp_rfc2217_server_py(self):
        output = subprocess.check_output(["esp_rfc2217_server.py", "-h"])
        decoded = output.decode("utf-8")
        assert "esp_rfc2217_server.py" in decoded
        assert "DEPRECATED" in decoded
