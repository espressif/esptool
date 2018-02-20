#!/usr/bin/env python
#
# Tests for espefuse.py on ESP32
#
# IMPORTANT These are not designed to be run on a real ESP32 chip.
#
# If you force them to run on a real chip, you will corrupt
# the chip's efuses on the first run and not get any useful
# test results either.
#
# Connections:
# RTS (active low) to reset
# DTR (active high) to clear efuses
#
import unittest
import serial
import sys
import StringIO

from collections import namedtuple

sys.path.append('..')
import esptool, espefuse

global serialport
serialport = None

# Wrapper class containing all possible espefuse.py command line args
class EspEfuseArgs(object):
    def __init__(self):
        self.do_not_confirm = True
        self.no_protect_key = False
        self.force_write_always = False
        self.voltage = None
        self.block = None
        self.keyfile = None

class EfuseTestCase(unittest.TestCase):

    def setUp(self):
        # reset and zero efuses
        serialport.dtr = False
        serialport.rts = True
        serialport.rts = False
        serialport.dtr = True

        # connect & verify efuses are really zero
        self.esp = esptool.ESP32ROM(serialport)
        self.esp.connect('no_reset')  # takes ~7 seconds
        self.efuses = espefuse.EspEfuses(self.esp)

        # Check every efuse is zero (~1 second)
        for efuse in self.efuses:
            val = efuse.get_raw()
            BAD_EFUSE_MSG = "Efuse %s not all zeroes - either this is a real ESP32 chip (VERY BAD, read top of file), or the reset is not erasing all efuses correctly." % efuse.register_name
            try:
                self.assertEqual(b'\x00'*len(val), val, BAD_EFUSE_MSG)
            except TypeError:
                self.assertEqual(0, val, BAD_EFUSE_MSG)

    def _set_34_coding_scheme(self):
        self.efuses["CODING_SCHEME"].burn(1)
        # EspEfuses constructor needs to re-load CODING_SCHEME
        self.efuses = espefuse.EspEfuses(self.esp)

    def test_burn_key_no_coding_scheme(self):
        key_256bit = b"".join(chr(x+1) for x in range(32))
        self._test_burn_key_common(key_256bit, b"\x00"*32)

    def test_burn_key_34_coding_scheme(self):
        self._set_34_coding_scheme()
        key_192bit = b"".join(chr(x+0xAA) for x in range(24))
        self._test_burn_key_common(key_192bit, b"\x00"*24)

    def _test_burn_key_common(self, new_key, empty_key):
        # Burning key common routine, works in both coding schemes
        args = EspEfuseArgs()
        args.keyfile = StringIO.StringIO(new_key)
        args.do_not_confirm = True
        burn_params = (self.esp, self.efuses, args)

        # Burn BLK1 with no protection
        args.block = "BLK1"
        args.no_protect_key = True
        espefuse.burn_key(*burn_params)
        key_val = self.efuses["BLK1"].get_key()
        self.assertEqual(new_key, key_val)

        # Burn BLK2 and read/write protect
        args.no_protect_key = False
        args.block = "BLK2"
        espefuse.burn_key(*burn_params)
        key_val = self.efuses["BLK2"].get_key()
        self.assertEqual(empty_key, key_val)

        # Try to burn BLK1 again, will fail as not empty
        with self.assertRaises(esptool.FatalError) as fail:
            args.block = "BLK1"
            espefuse.burn_key(*burn_params)
        self.assertIn("already", str(fail.exception))

        # Try to burn BLK2 again, will fail as protected
        with self.assertRaises(esptool.FatalError) as fail:
            args.block = "BLK2"
            espefuse.burn_key(*burn_params)
        self.assertIn("already", str(fail.exception))

        # Force BLK1 to be burned again (and read protect this time)
        args.force_write_always = True
        args.block = "BLK1"
        espefuse.burn_key(*burn_params)
        key_val = self.efuses["BLK1"].get_key()
        self.assertEqual(empty_key, key_val)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: %s <serial port> [optional tests]" % sys.argv[0])
        sys.exit(1)
    serialport = serial.Serial(sys.argv[1], 115200)
    serialport.dtr = False
    serialport.rts = False

    # unittest also uses argv, so trim the args we used
    sys.argv = [ sys.argv[0] ] + sys.argv[2:]
    print("Running espefuse.py tests...")
    unittest.main(buffer=True)
