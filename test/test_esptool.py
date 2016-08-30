#!/usr/bin/env python
"""
esptool.py "unit" tests (really integration tests). Uses a device connected to the serial port.

WILL MESS UP THE DEVICE'S SPI FLASH CONTENTS

Chip name & serial port are passed in as arguments to test. Same test suite
runs on esp8266 & esp32 (some addresses will change, see below.)

"""
import subprocess
import unittest
import sys
import os.path
import os
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
chip = None # set on command line
serialport = None # set on command line

class EsptoolTestCase(unittest.TestCase):

    def run_esptool(self, args, baud=None):
        if baud is None:
            baud = default_baudrate
        cmd = [sys.executable, ESPTOOL_PY, "--chip", chip, "--port", serialport, "--baud", str(baud) ] + args.split(" ")
        print("Running %s..." % (" ".join(cmd)))
        try:
            output = subprocess.check_output([str(s) for s in cmd], cwd=TEST_DIR)
            print(output)
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise e


class TestFlashing(EsptoolTestCase):
    def get_tempfile(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = os.tempnam(None, "test_elf2image")
        self.tempfiles.append(result)
        return result

    def setUp(self):
        self.tempfiles = []
        print 50*"*"

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
        with open(temp) as f:
            rb = f.read()
        self.assertEqual(length, len(rb), "read_flash length %d offset 0x%x yielded %d bytes!" % (length, offset, len(rb)))
        return rb

    def verify_readback(self, offset, length, compare_to):
        rb = self.readback(offset, length)
        with open(compare_to) as f:
            ct = f.read()
        if len(rb) != len(ct):
            print "WARNING: Expected length %d doesn't match comparison %d"
        print("Readback %d bytes" % len(rb))
        for rb_b,ct_b,offs in zip(rb,ct,range(len(rb))):
            if rb_b != ct_b:
                self.fail("First difference at offset 0x%x Expected %c got %c" % (offs, ct_b, rb_b))

    # actual test cases start here

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
        with open("images/sector.bin") as f:
            ct = f.read()
        self.assertEqual(last_sector, ct)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "Usage: %s <serial port> <chip name> [optional default baud rate] [optional tests]" % sys.argv[0]
        sys.exit(1)
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
    sys.argv = [ sys.argv[0] ] + sys.argv[args_used + 1:]
    unittest.main(buffer=True)
