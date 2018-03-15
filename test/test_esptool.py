#!/usr/bin/env python
"""
esptool.py "unit" tests (really integration tests). Uses a device connected to the serial port.

WILL MESS UP THE DEVICE'S SPI FLASH CONTENTS

Chip name & serial port are passed in as arguments to test. Same test suite
runs on esp8266 & esp32 (some addresses will change, see below.)

"""
import os
import os.path
import re
import subprocess
import sys
import tempfile
import time
import unittest
import serial

# point is this file is not 4 byte aligned in length
NODEMCU_FILE = "nodemcu-master-7-modules-2017-01-19-11-10-03-integer.bin"

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
os.chdir(os.path.dirname(__file__))
try:
    ESPTOOL_PY = os.environ["ESPTOOL_PY"]
except KeyError:
    ESPTOOL_PY = os.path.join(TEST_DIR, "..", "esptool.py")

# Command line options for test environment
global default_baudrate, chip, serialport, trace_enabled
default_baudrate = 115200
chip = None
serialport = None
trace_enabled = False

RETURN_CODE_FATAL_ERROR = 2

class EsptoolTestCase(unittest.TestCase):

    def run_esptool(self, args, baud=None):
        """ Run esptool with the specified arguments. --chip, --port and --baud
        are filled in automatically from the command line. (can override default baud rate with baud param.)

        Additional args passed in args parameter as a string.

        Returns output from esptool.py as a string if there is any. Raises an exception if esptool.py fails.
        """
        if baud is None:
            baud = default_baudrate
        trace_args = [ "--trace" ] if trace_enabled else []
        cmd = [sys.executable, ESPTOOL_PY ] + trace_args + [ "--chip", chip, "--port", serialport, "--baud", str(baud) ] + args.split(" ")
        print("Running %s..." % (" ".join(cmd)))
        try:
            output = subprocess.check_output([str(s) for s in cmd], cwd=TEST_DIR, stderr=subprocess.STDOUT)
            print(output)  # for more complete stdout logs on failure
            return output.decode("utf-8")
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise e

    def run_esptool_error(self, args, baud=None):
        """ Run esptool.py similar to run_esptool, but expect an
        error.

        Verifies the error is an expected error not an unhandled exception,
        and returns the output from esptool.py as a string.
        """
        with self.assertRaises(subprocess.CalledProcessError) as fail:
            self.run_esptool(args, baud)
        failure = fail.exception
        self.assertEqual(RETURN_CODE_FATAL_ERROR, failure.returncode)
        return failure.output.decode("utf-8")

    def setUp(self):
        self.tempfiles = []
        print(50*"*")

    def tearDown(self):
        for t in self.tempfiles:
            try:
                os.remove(t)
            except OSError:
                pass

    def readback(self, offset, length):
        """ Read contents of flash back, return to caller. """
        tf = tempfile.NamedTemporaryFile(delete=False)  # need a file we can read into
        self.tempfiles.append(tf.name)
        tf.close()
        self.run_esptool("read_flash %d %d %s" % (offset, length, tf.name))
        with open(tf.name, "rb") as f:
            rb = f.read()

        self.assertEqual(length, len(rb), "read_flash length %d offset 0x%x yielded %d bytes!" % (length, offset, len(rb)))
        return rb

    def verify_readback(self, offset, length, compare_to, is_bootloader=False):
        rb = self.readback(offset, length)
        with open(compare_to, "rb") as f:
            ct = f.read()
        if len(rb) != len(ct):
            print("WARNING: Expected length %d doesn't match comparison %d")
        print("Readback %d bytes" % len(rb))
        if is_bootloader:
            # writing a bootloader image to bootloader offset can set flash size/etc,
            # so don't compare the 8 byte header
            self.assertEqual(ct[0], rb[0], "First bytes should be identical")
            rb = rb[8:]
            ct = ct[8:]
        for rb_b,ct_b,offs in zip(rb,ct,range(len(rb))):
            if rb_b != ct_b:
                self.fail("First difference at offset 0x%x Expected %r got %r" % (offs, ct_b, rb_b))


class TestFlashing(EsptoolTestCase):

    def test_short_flash(self):
        self.run_esptool("write_flash 0x0 images/one_kb.bin")
        self.verify_readback(0, 1024, "images/one_kb.bin")

    def test_highspeed_flash(self):
        self.run_esptool("write_flash 0x0 images/fifty_kb.bin", baud=921600)
        self.verify_readback(0, 50*1024, "images/fifty_kb.bin")

    def test_adjacent_flash(self):
        self.run_esptool("write_flash 0x0 images/sector.bin 0x1000 images/fifty_kb.bin")
        self.verify_readback(0, 4096, "images/sector.bin")
        self.verify_readback(4096, 50*1024, "images/fifty_kb.bin")

    def test_adjacent_independent_flash(self):
        self.run_esptool("write_flash 0x0 images/sector.bin")
        self.verify_readback(0, 4096, "images/sector.bin")
        self.run_esptool("write_flash 0x1000 images/fifty_kb.bin")
        self.verify_readback(4096, 50*1024, "images/fifty_kb.bin")
        # writing flash the second time shouldn't have corrupted the first time
        self.verify_readback(0, 4096, "images/sector.bin")

    def test_correct_offset(self):
        """ Verify writing at an offset actually writes to that offset. """
        self.run_esptool("write_flash 0x2000 images/sector.bin")
        time.sleep(0.1)
        three_sectors = self.readback(0, 0x3000)
        last_sector = three_sectors[0x2000:]
        with open("images/sector.bin", "rb") as f:
            ct = f.read()
        self.assertEqual(last_sector, ct)

    def test_no_compression_flash(self):
        self.run_esptool("write_flash -u 0x0 images/sector.bin 0x1000 images/fifty_kb.bin")
        self.verify_readback(0, 4096, "images/sector.bin")
        self.verify_readback(4096, 50*1024, "images/fifty_kb.bin")

    def test_compressed_nostub_flash(self):
        if chip == "esp32":
            self.run_esptool("--no-stub write_flash -z 0x0 images/sector.bin 0x1000 images/fifty_kb.bin")
            self.verify_readback(0, 4096, "images/sector.bin")
            self.verify_readback(4096, 50*1024, "images/fifty_kb.bin")

    def _test_partition_table_then_bootloader(self, args):
        self.run_esptool(args + " 0x4000 images/partitions_singleapp.bin")
        self.verify_readback(0x4000, 96, "images/partitions_singleapp.bin")
        self.run_esptool(args + " 0x1000 images/bootloader.bin")
        self.verify_readback(0x1000, 7888, "images/bootloader.bin", True)
        self.verify_readback(0x4000, 96, "images/partitions_singleapp.bin")

    def test_partition_table_then_bootloader(self):
        self._test_partition_table_then_bootloader("write_flash")

    def test_partition_table_then_bootloader_no_compression(self):
        self._test_partition_table_then_bootloader("write_flash -u")

    def test_partition_table_then_bootloader_nostub(self):
        self._test_partition_table_then_bootloader("--no-stub write_flash")

    # note: there is no "partition table then bootloader" test that
    # uses --no-stub and -z, as the ESP32 ROM over-erases and can't
    # flash this set of files in this order.  we do
    # test_compressed_nostub_flash() instead.

    def test_length_not_aligned_4bytes(self):
        nodemcu = "nodemcu-master-7-modules-2017-01-19-11-10-03-integer.bin"
        size = 390411
        self.run_esptool("write_flash 0x0 images/%s" % nodemcu)

    def test_length_not_aligned_4bytes_no_compression(self):
        self.run_esptool("write_flash -u 0x0 images/%s" % NODEMCU_FILE)

    def test_write_overlap(self):
        output = self.run_esptool_error("write_flash 0x0 images/bootloader.bin 0x1000 images/one_kb.bin")
        self.assertIn("Detected overlap at address: 0x1000 ", output)

    def test_write_sector_overlap(self):
        # These two 1KB files don't overlap, but they do both touch sector at 0x1000 so should fail
        output = self.run_esptool_error("write_flash 0xd00 images/one_kb.bin 0x1d00 images/one_kb.bin")
        self.assertIn("Detected overlap at address: 0x1d00", output)

    def test_write_no_overlap(self):
        output = self.run_esptool("write_flash 0x0 images/bootloader.bin 0x2000 images/one_kb.bin")
        self.assertNotIn("Detected overlap at address", output)

    def test_compressible_file(self):
        self.run_esptool("write_flash 0x10000 images/one_mb_zeroes.bin")

    def test_zero_length(self):
        # Zero length files are skipped with a warning
        output = self.run_esptool("write_flash 0x10000 images/one_kb.bin 0x11000 images/zerolength.bin")
        self.verify_readback(0x10000, 1024, "images/one_kb.bin")
        self.assertIn("zerolength.bin is empty", output)

    def test_single_byte(self):
        output = self.run_esptool("write_flash 0x0 images/onebyte.bin")
        self.verify_readback(0x0, 1, "images/onebyte.bin")


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
        output = self.run_esptool_error("write_flash -fs 1MB 0x280000 images/one_kb.bin")
        self.assertIn("File images/one_kb.bin", output)
        self.assertIn("will not fit", output)

    def test_write_no_compression_past_end_fails(self):
        output = self.run_esptool_error("write_flash -u -fs 1MB 0x280000 images/one_kb.bin")
        self.assertIn("File images/one_kb.bin", output)
        self.assertIn("will not fit", output)


class TestFlashDetection(EsptoolTestCase):
    def test_correct_offset(self):
        """ Verify writing at an offset actually writes to that offset. """
        res = self.run_esptool("flash_id")
        self.assertTrue("Manufacturer:" in res)
        self.assertTrue("Device:" in res)

class TestErase(EsptoolTestCase):

    def test_chip_erase(self):
        self.run_esptool("write_flash 0x10000 images/one_kb.bin")
        self.verify_readback(0x10000, 0x400, "images/one_kb.bin")
        self.run_esptool("erase_flash")
        empty = self.readback(0x10000, 0x400)
        self.assertTrue(empty == b'\xFF'*0x400)

    def test_region_erase(self):
        self.run_esptool("write_flash 0x10000 images/one_kb.bin")
        self.run_esptool("write_flash 0x11000 images/sector.bin")
        self.verify_readback(0x10000, 0x400, "images/one_kb.bin")
        self.verify_readback(0x11000, 0x1000, "images/sector.bin")
        # erase only the flash sector containing one_kb.bin
        self.run_esptool("erase_region 0x10000 0x1000")
        self.verify_readback(0x11000, 0x1000, "images/sector.bin")
        empty = self.readback(0x10000, 0x1000)
        self.assertTrue(empty == b'\xFF'*0x1000)

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
        output = self.run_esptool_error("verify_flash --diff=yes 0x6000 images/one_kb.bin")
        self.assertIn("verify FAILED", output)
        self.assertIn("first @ 0x00006000", output)

    def test_verify_unaligned_length(self):
        self.run_esptool("write_flash 0x0 images/%s" % NODEMCU_FILE)
        self.run_esptool("verify_flash 0x0 images/%s" % NODEMCU_FILE)


class TestReadIdentityValues(EsptoolTestCase):

    def test_read_mac(self):
        output = self.run_esptool("read_mac")
        mac = re.search(r"[0-9a-f:]{17}", output)
        self.assertIsNotNone(mac)
        mac = mac.group(0)
        self.assertNotEqual("00:00:00:00:00:00", mac)
        self.assertNotEqual("ff:ff:ff:ff:ff:ff", mac)

    def test_read_chip_id(self):
        if chip == "esp8266":
            output = self.run_esptool("chip_id")
            idstr = re.search("Chip ID: 0x([0-9a-f]+)", output)
            self.assertIsNotNone(idstr)
            idstr = idstr.group(1)
            self.assertNotEqual("0"*8, idstr)
            self.assertNotEqual("f"*8, idstr)

class TestKeepImageSettings(EsptoolTestCase):
    """ Tests for the -fm keep, -ff keep options for write_flash """
    HEADER_ONLY = "images/image_header_only.bin"  # 8 byte file, contains image header
    def setUp(self):
        super(TestKeepImageSettings, self).setUp()
        self.flash_offset = 0x1000 if chip == "esp32" else 0  # bootloader offset
        with open(self.HEADER_ONLY, "rb") as f:
            self.header = f.read(8)

    def test_keep_does_not_change_settings(self):
        # defaults should be keep, except for flash size which has to match header
        flash_size = "1MB" if chip == "esp32" else "512KB"  # hex 0
        self.run_esptool("write_flash -fs %s 0x%x %s" % (flash_size, self.flash_offset, self.HEADER_ONLY))
        self.verify_readback(self.flash_offset, 8, self.HEADER_ONLY, False)
        # can also explicitly set these options
        self.run_esptool("write_flash -fm keep -ff keep -fs %s 0x%x %s" % (flash_size, self.flash_offset, self.HEADER_ONLY))
        self.verify_readback(self.flash_offset, 8, self.HEADER_ONLY, False)
        # verify_flash should also use 'keep'
        self.run_esptool("verify_flash -fs %s 0x%x %s" % (flash_size, self.flash_offset, self.HEADER_ONLY))

    def test_detect_size_changes_size(self):
        self.run_esptool("write_flash 0x%x %s" % (self.flash_offset, self.HEADER_ONLY))
        readback = self.readback(self.flash_offset, 8)
        self.assertEqual(self.header[:3], readback[:3])  # first 3 bytes unchanged
        self.assertNotEqual(self.header[3], readback[3]) # size_freq byte changed
        self.assertEqual(self.header[4:], readback[4:]) # rest unchanged

    def test_explicit_set_size_freq_mode(self):
        self.run_esptool("write_flash -fs 2MB -fm qio -ff 80m 0x%x %s" % (self.flash_offset, self.HEADER_ONLY))

        def val(x):
            try:
                return ord(x)  # converts character to integer on Python 2
            except TypeError:
                return x       # throws TypeError on Python 3 where x is already an integer

        header = list(self.header)
        readback = self.readback(self.flash_offset, 8)
        self.assertEqual(self.header[0], readback[0])
        self.assertEqual(self.header[1], readback[1])
        self.assertEqual(0, val(readback[2]))  # qio mode
        self.assertNotEqual(0, val(self.header[2]))
        self.assertEqual(0x1f if chip == "esp32" else 0x3f, val(readback[3]))  # size_freq
        self.assertNotEqual(self.header[3], readback[3])
        self.assertEqual(self.header[4:], readback[4:])
        # verify_flash should pass if we match params, fail otherwise
        self.run_esptool("verify_flash -fs 2MB -fm qio -ff 80m 0x%x %s" % (self.flash_offset, self.HEADER_ONLY))
        self.run_esptool_error("verify_flash 0x%x %s" % (self.flash_offset, self.HEADER_ONLY))


class TestLoadRAM(EsptoolTestCase):
    def test_load_ram(self):
        """ Verify load_ram command

        The "hello world" binary programs for each chip print
        "Hello world!\n" to the serial port.
        """
        self.run_esptool("load_ram images/helloworld-%s.bin" % chip)
        p = serial.serial_for_url(serialport, default_baudrate)
        p.timeout = 0.2
        self.assertIn(b"Hello world!", p.read(32))
        p.close()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: %s [--trace] <serial port> <chip name> [optional default baud rate] [optional tests]" % sys.argv[0])
        sys.exit(1)
    if sys.argv[1] == "--trace":
        trace_enabled = True
        sys.argv.pop(1)
    serialport = sys.argv[1]
    chip = sys.argv[2]
    args_used = 2
    try:
        default_baudrate = int(sys.argv[3])
        args_used = 3
    except IndexError:
        pass # no additional args
    except ValueError:
        pass # arg3 not a number, must be a test name
    # unittest also uses argv, so trim the args we used
    print("Running esptool.py tests...")
    sys.argv = [ sys.argv[0] ] + sys.argv[args_used + 1:]
    unittest.main(buffer=True)
