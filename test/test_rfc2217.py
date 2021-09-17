#!/usr/bin/env python
"""
Temporarily isolated rfc2217 "unit" tests (really integration tests).
Uses a device connected to the serial port.

WILL MESS UP THE DEVICE'S SPI FLASH CONTENTS

Chip name & serial port are passed in as arguments to test. Same test suite
runs on esp8266 & esp32 (some addresses will change, see below.)

"""
from __future__ import division, print_function

import io
import os
import os.path
import subprocess
import sys
import tempfile
import unittest
from socket import AF_INET, SOCK_STREAM, socket
from time import sleep

sys.path.append('..')

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
os.chdir(os.path.dirname(__file__))
try:
    ESPTOOL_PY = os.environ["ESPTOOL_PY"]
except KeyError:
    ESPTOOL_PY = os.path.join(TEST_DIR, "..", "esptool.py")
ESPRFC2217SERVER_PY = os.path.join(TEST_DIR, "..", "esp_rfc2217_server.py")

# Command line options for test environment
global default_baudrate, chip, serialport, trace_enabled
default_baudrate = 115200
serialport = None
trace_enabled = False

try:
    if sys.argv[1] == "--trace":
        trace_enabled = True
        sys.argv.pop(1)
    chip = sys.argv[2]
except IndexError:
    chip = None  # fails in main()


class ESPRFC2217Server(object):
    """ Creates a virtual serial port accessible through rfc2217 port.
    """

    def __init__(self, rfc2217_port=None):
        self.port = rfc2217_port or self.get_free_port()
        self.cmd = [sys.executable, ESPRFC2217SERVER_PY, '-p', str(self.port), serialport]
        self.server_output_file = open(str(chip) + "_server.out", 'a')
        self.server_output_file.write("************************************")
        self.p = None
        self.wait_for_server_starts(attempts_count=5)

    @staticmethod
    def get_free_port():
        s = socket(AF_INET, SOCK_STREAM)
        s.bind(('', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def wait_for_server_starts(self, attempts_count):
        for attempt in range(attempts_count):
            try:
                self.p = subprocess.Popen(self.cmd, cwd=TEST_DIR, stdout=self.server_output_file,
                                          stderr=subprocess.STDOUT, close_fds=True)
                sleep(2)
                s = socket(AF_INET, SOCK_STREAM)
                result = s.connect_ex(('localhost', self.port))
                s.close()
                if result == 0:
                    print("Server started successfully.")
                    return
            except Exception as e:
                print(e)
            print("Server start failed." + (" Retrying . . ." if attempt < attempts_count - 1 else ""))
            self.p.terminate()
        raise Exception("Server not started successfully!")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.server_output_file.close()
        self.p.terminate()


class EsptoolTestCase(unittest.TestCase):

    def run_esptool(self, args, baud=None, chip_name=chip, rfc2217_port=None):
        """ Run esptool with the specified arguments. --chip, --port and --baud
        are filled in automatically from the command line. (can override default baud rate with baud param.)

        Additional args passed in args parameter as a string.

        Returns output from esptool.py as a string if there is any. Raises an exception if esptool.py fails.
        """
        if baud is None:
            baud = default_baudrate
        trace_args = ["--trace"] if trace_enabled else []
        cmd = [sys.executable, ESPTOOL_PY] + trace_args
        if chip_name:
            cmd += ["--chip", chip]
        cmd += ["--port", rfc2217_port or serialport, "--baud", str(baud)] + args.split(" ")
        print("Running %s..." % (" ".join(cmd)))
        try:
            output = subprocess.check_output([str(s) for s in cmd], cwd=TEST_DIR, stderr=subprocess.STDOUT)
            print(output)  # for more complete stdout logs on failure
            return output.decode("utf-8")
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise e

    def readback(self, offset, length):
        """ Read contents of flash back, return to caller. """
        with tempfile.NamedTemporaryFile(delete=False) as tf:  # need a file we can read into
            self.addCleanup(os.remove, tf.name)
        self.run_esptool("--before default_reset read_flash %d %d %s" % (offset, length, tf.name))
        with open(tf.name, "rb") as f:
            rb = f.read()

        self.assertEqual(length, len(rb), "read_flash length %d offset 0x%x yielded %d bytes!" % (length, offset, len(rb)))
        return rb

    def verify_readback(self, offset, length, compare_to, is_bootloader=False):
        rb = self.readback(offset, length)
        with open(compare_to, "rb") as f:
            ct = f.read()
        if len(rb) != len(ct):
            print("WARNING: Expected length %d doesn't match comparison %d" % (len(ct), len(rb)))
        print("Readback %d bytes" % len(rb))
        if is_bootloader:
            # writing a bootloader image to bootloader offset can set flash size/etc,
            # so don't compare the 8 byte header
            self.assertEqual(ct[0], rb[0], "First bytes should be identical")
            rb = rb[8:]
            ct = ct[8:]
        for rb_b, ct_b, offs in zip(rb, ct, range(len(rb))):
            if rb_b != ct_b:
                self.fail("First difference at offset 0x%x Expected %r got %r" % (offs, ct_b, rb_b))


class TestFlashing(EsptoolTestCase):

    def test_highspeed_flash_virtual_port(self):
        with ESPRFC2217Server() as server:
            rfc2217_port = 'rfc2217://localhost:' + str(server.port) + '?ign_set_control'
            self.run_esptool("write_flash 0x0 images/fifty_kb.bin", baud=921600, rfc2217_port=rfc2217_port)
        self.verify_readback(0, 50 * 1024, "images/fifty_kb.bin")


class TestAutoDetect(EsptoolTestCase):
    def _check_output(self, output):
        expected_chip_name = {
            "esp8266": "ESP8266",
            "esp32": "ESP32",
            "esp32s2": "ESP32-S2",
            "esp32s3beta2": "ESP32-S3(beta2)",
            "esp32s3": "ESP32-S3",
            "esp32c3": "ESP32-C3",
        }[chip]
        self.assertIn("Detecting chip type... " + expected_chip_name, output)
        self.assertIn("Chip is " + expected_chip_name, output)

    def test_auto_detect_virtual_port(self):
        with ESPRFC2217Server() as server:
            output = self.run_esptool("chip_id", chip_name=None,
                                      rfc2217_port='rfc2217://localhost:' + str(server.port) + '?ign_set_control')
            self._check_output(output)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: %s [--trace] <serial port> <chip name> [optional default baud rate] [optional tests]" % sys.argv[0])
        sys.exit(1)
    serialport = sys.argv[1]
    # chip is already set to sys.argv[2], so @skipUnless can evaluate against it
    args_used = 2
    try:
        default_baudrate = int(sys.argv[3])
        args_used = 3
    except IndexError:
        pass  # no additional args
    except ValueError:
        pass  # arg3 not a number, must be a test name

    # unittest also uses argv, so trim the args we used
    sys.argv = [sys.argv[0]] + sys.argv[args_used + 1:]

    # esptool skips strapping mode check in USB CDC case, if this is set
    os.environ["ESPTOOL_TESTING"] = "1"

    print("Running rfc2217 tests...")
    try:
        import xmlrunner  # it should come from the unittest-xml-reporting package and not from xmlrunner
        import pkg_resources

        try:
            pkg_resources.require('xmlrunner')
            raise ImportError('The unittest-xml-reporting package should be used instead of xmlrunner')
        except pkg_resources.DistributionNotFound:
            # it is desired that xmlrunner is not installed so it will not interfere with unittest-xml-reporting
            # (conflict of files)
            pass

        with io.open('report.xml', 'wb') as output:
            unittest.main(testRunner=xmlrunner.XMLTestRunner(output=output))
    except ImportError:
        unittest.main(buffer=True)
