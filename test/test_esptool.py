#!/usr/bin/env python
"""
esptool.py "unit" tests (really integration tests). Uses a device connected to the serial port.

WILL MESS UP THE DEVICE'S SPI FLASH CONTENTS

Serial port and (optional) baud rate are passed in as arguments to test.

"""
from __future__ import print_function, unicode_literals, division


import subprocess
import unittest
import sys
import os.path
import os
import tempfile
import warnings
import time


TEST_DIR = os.path.abspath(os.path.dirname(__file__))
os.chdir(os.path.dirname(__file__))
try:
    ESPTOOL_PY = os.environ["ESPTOOL_PY"]
except KeyError:
    ESPTOOL_PY = os.path.join(TEST_DIR, "..", "esptool.py")

global default_baudrate, chip, serialport
default_baudrate = 115200 # can override on command line
serialport = None # set on command line

RETURN_CODE_FATAL_ERROR = 2

class EsptoolTestCase(unittest.TestCase):

    def run_esptool(self, args, baud=None):
        """ Run esptool with the specified arguments. --chip, --port and --baud
        are filled in automatically from the command line. (can override default baud rate with baud param.)

        Additional args passed in args parameter as a string.

        Returns output from esptool.py if there is anything. Raises an exception if esptool.py fails.
        """
        if baud is None:
            baud = default_baudrate
        cmd = [sys.executable, ESPTOOL_PY, "--port", serialport, "--baud", str(baud) ] + args.split(" ")
        print("Running %s..." % (" ".join(cmd)))
        try:
            output = subprocess.check_output([str(s) for s in cmd], cwd=TEST_DIR, stderr=subprocess.STDOUT)
            print(output)  # for more complete stdout logs on failure
            return output
        except subprocess.CalledProcessError as e:
            print(e)
            print(e.output)
            raise e

    def run_esptool_error(self, args, baud=None):
        """ Run esptool.py similar to run_esptool, but expect an
        error.

        Verifies the error is an expected error not an unhandled exception,
        and returns the output from esptool.py
        """
        with self.assertRaises(subprocess.CalledProcessError) as fail:
            self.run_esptool(args, baud)
        failure = fail.exception
        self.assertEqual(RETURN_CODE_FATAL_ERROR, failure.returncode)
        return failure.output

    def get_tempfile(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with tempfile.NamedTemporaryFile(prefix="test_esptool", delete=False) as f:
                result = f.name
        self.tempfiles.append(result)
        return result

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
        temp = self.get_tempfile()
        self.run_esptool("read_flash %d %d %s" % (offset, length, temp))
        with open(temp, "rb") as f:
            rb = f.read()
        self.assertEqual(length, len(rb), "read_flash length %d offset 0x%x yielded %d bytes!" % (length, offset, len(rb)))
        return rb

    def verify_readback(self, offset, length, compare_to):
        rb = self.readback(offset, length)
        with open(compare_to, "rb") as f:
            ct = f.read()
        if len(rb) != len(ct):
            print("WARNING: Expected length %d doesn't match comparison %d")
        print("Readback %d bytes" % len(rb))
        for rb_b,ct_b,offs in zip(rb,ct,range(len(rb))):
            if rb_b != ct_b:
                self.fail("First difference at offset 0x%x Expected %r got %r" % (offs, ct_b, rb_b))


class TestFlashing(EsptoolTestCase):

    def test_short_flash(self):
        self.run_esptool("write_flash 0x0 images/one_kb.bin")
        self.verify_readback(0, 1024, "images/one_kb.bin")

    def test_highspeed_flash(self):
        self.run_esptool("write_flash 0x0 images/fifty_kb.bin", baud=920600)
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

class TestFlashSizes(EsptoolTestCase):

    def test_high_offset(self):
        self.run_esptool("write_flash -fs 32m 0x300000 images/one_kb.bin")
        self.verify_readback(0x300000, 1024, "images/one_kb.bin")

    def test_invalid_size_arg(self):
        self.run_esptool_error("write_flash -fs 10MB 0x6000 images/one_kb.bin")


class TestErase(EsptoolTestCase):

    def test_chip_erase(self):
        self.run_esptool("write_flash 0x10000 images/one_kb.bin")
        self.verify_readback(0x10000, 0x400, "images/one_kb.bin")
        self.run_esptool("erase_flash")
        empty = self.readback(0x10000, 0x400)
        self.assertTrue(empty == b'\xFF'*0x400)

class TestVerifyCommand(EsptoolTestCase):

    def test_verify_success(self):
        self.run_esptool("write_flash 0x5000 images/one_kb.bin")
        self.run_esptool("verify_flash 0x5000 images/one_kb.bin")

    def test_verify_failure(self):
        self.run_esptool("write_flash 0x6000 images/sector.bin")
        output = self.run_esptool_error("verify_flash --diff=yes 0x6000 images/one_kb.bin")
        self.assertIn(b"verify FAILED", output)
        self.assertIn(b"first @ 0x00006000", output)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: %s <serial port> [optional default baud rate] [optional tests]" % sys.argv[0])
        sys.exit(1)
    serialport = sys.argv[1]
    args_used = 1
    try:
        default_baudrate = int(sys.argv[2])
        args_used = 2
    except IndexError:
        pass # no additional args
    except ValueError:
        pass # arg3 not a number, must be a test name
    # unittest also uses argv, so trim the args we used
    print("Running esptool.py tests...")
    sys.argv = [ sys.argv[0] ] + sys.argv[args_used + 1:]
    unittest.main(buffer=True)
