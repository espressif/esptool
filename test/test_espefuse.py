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
import struct
import sys
import StringIO
import time

from collections import namedtuple

sys.path.append('..')
import esptool, espefuse

global serialport
serialport = None

# Wrapper class containing all possible espefuse.py command line args
class EspEfuseArgs(object):
    def __init__(self):
        self.no_protect_key = False
        self.force_write_always = False
        self.voltage = None
        self.block = None
        self.keyfile = None
        self.no_write_protect = False

class EfuseTestCase(unittest.TestCase):

    def setUp(self):
        # reset and zero efuses
        serialport.dtr = False
        serialport.rts = True
        time.sleep(0.05)
        serialport.rts = False
        time.sleep(0.05)
        serialport.dtr = True

        # connect & verify efuses are really zero
        self.esp = espefuse.get_esp(serialport, 115200, "default_reset")
        # dict mapping register name to its efuse object
        self.efuses, self.operations = espefuse.get_efuses(esp=self.esp, do_not_confirm=True)
        if type(self.esp) is esptool.ESP32ROM:
            self.BLK1 = "BLK1"
            self.BLK2 = "BLK2"
            self.BLK3 = "BLK3"
            self.chip = "ESP32"
        else:
            self.BLK1 = "BLOCK_KEY1"
            self.BLK2 = "BLOCK_KEY2"
            self.BLK3 = "BLOCK_KEY3"
            self.chip = "ESP32-S2"

        for efuse in self.efuses:
            if efuse.name == "CLK8M_FREQ":
                continue
            val = efuse.get_raw()
            BAD_EFUSE_MSG = "Efuse %s not all zeroes - either this is a real ESP32 chip (VERY BAD, read top of file), or the reset is not erasing all efuses correctly." % efuse.name
            try:
                self.assertEqual(b'\x00'*len(val), val, BAD_EFUSE_MSG)
            except TypeError:
                self.assertEqual(0, val, BAD_EFUSE_MSG)

    def _set_34_coding_scheme(self):
        self.efuses["CODING_SCHEME"].burn(1)
        # EspEfuses constructor needs to re-load CODING_SCHEME
        self.efuses, self.operations = espefuse.get_efuses(esp=self.esp, do_not_confirm=True)


class TestBurnKey(EfuseTestCase):
    def test_burn_key_no_coding_scheme(self):
        key_256bit = b"".join(chr(x+1) for x in range(32))
        self._test_burn_key_common(key_256bit, b"\x00"*32)

    def test_burn_key_34_coding_scheme(self):
        if self.chip == "ESP32":
            self._set_34_coding_scheme()
            key_192bit = b"".join(chr(x+0xAA) for x in range(24))
            self._test_burn_key_common(key_192bit, b"\x00"*24)

    def _test_burn_key_common(self, new_key, empty_key):
        # Burning key common routine, works in both coding schemes
        args = EspEfuseArgs()

        # Burn BLK1 with no protection
        args.block = [self.BLK1]
        args.keyfile = [StringIO.StringIO(new_key)]
        if self.chip == "ESP32-S2":
            args.keypurpose = ["XTS_AES_256_KEY_1"]
            args.no_read_protect = True
        else:
            args.no_protect_key = True
        self.operations.burn_key(self.esp, self.efuses, args)
        key_val = self.efuses[self.BLK1].get_raw()
        self.assertEqual(new_key, key_val)

        # Burn BLK2 and read/write protect
        args.block = [self.BLK2]
        args.keyfile = [StringIO.StringIO(new_key)]
        if self.chip == "ESP32-S2":
            args.keypurpose = ["XTS_AES_256_KEY_1"]
            args.no_read_protect = False
        else:
            args.no_protect_key = False
        self.operations.burn_key(self.esp, self.efuses, args)
        key_val = self.efuses[self.BLK2].get_raw()
        self.assertEqual(empty_key, key_val)

        # Try to burn BLK1 again, will not fail as the value is the same
        args.block = [self.BLK1]
        args.keyfile = [StringIO.StringIO(new_key)]
        if self.chip == "ESP32-S2":
            args.keypurpose = ["XTS_AES_256_KEY_1"]
            args.no_read_protect = True
        else:
            args.no_protect_key = True
        self.operations.burn_key(self.esp, self.efuses, args)
        key_val = self.efuses[self.BLK1].get_raw()
        self.assertEqual(new_key, key_val)

        # Try to overwrite BLK1 with another key, will fail as it is not empty
        with self.assertRaises(esptool.FatalError) as fail:
            args.block = [self.BLK1]
            args.keyfile = [StringIO.StringIO(new_key[::-1])]
            if self.chip == "ESP32-S2":
                args.keypurpose = ["XTS_AES_256_KEY_1"]
                args.no_read_protect = False
            else:
                args.no_protect_key = False
            self.operations.burn_key(self.esp, self.efuses, args)
        self.assertIn("some bits that cannot be cleared", str(fail.exception))

        # Try to burn BLK2 again, will fail as protected
        with self.assertRaises(esptool.FatalError) as fail:
            args.block = [self.BLK2]
            args.keyfile = [StringIO.StringIO(new_key)]
            if self.chip == "ESP32-S2":
                args.keypurpose = ["XTS_AES_256_KEY_1"]
                args.no_read_protect = False
            else:
                args.no_protect_key = False
            self.operations.burn_key(self.esp, self.efuses, args)
        self.assertIn("already", str(fail.exception))

        # Force BLK1 to be burned again (and read protect this time)
        args.force_write_always = True
        args.block = [self.BLK1]
        args.keyfile = [StringIO.StringIO(new_key)]
        if self.chip == "ESP32-S2":
            args.keypurpose = ["XTS_AES_256_KEY_1"]
            args.no_read_protect = False
        else:
            args.no_protect_key = False
        self.operations.burn_key(self.esp, self.efuses, args)
        key_val = self.efuses[self.BLK1].get_raw()
        self.assertEqual(empty_key, key_val)

        self.assertEqual(0, self.efuses.get_coding_scheme_warnings())


class TestBurnBlockData(EfuseTestCase):

    def test_burn_block_data_normal(self):
        word_a = 0x1234
        word_b = 0x789A
        data = struct.pack("<II", word_a, word_b)

        args = EspEfuseArgs()
        args.block = [self.BLK1]
        args.datafile = [StringIO.StringIO(data)]
        args.offset = 4
        self.operations.burn_block_data(self.esp, self.efuses, args)

        words = self.efuses.blocks[self.efuses.get_index_block_by_name(self.BLK1)].get_words()
        self.assertEqual([0, word_a, word_b, 0, 0, 0, 0, 0], words)

        args.block = [self.BLK1]
        args.datafile = [StringIO.StringIO(data)]
        args.offset = 24
        args.force_write_always = True
        self.operations.burn_block_data(self.esp, self.efuses, args)

        words = self.efuses.blocks[self.efuses.get_index_block_by_name(self.BLK1)].get_words()
        self.assertEqual([0, word_a, word_b, 0, 0, 0, word_a, word_b], words)

        self.assertEqual(0, self.efuses.get_coding_scheme_warnings())

    def test_burn_block_data_34_coding(self):
        if self.chip == "ESP32":
            self._set_34_coding_scheme()
            data = b"1234EA"

            args = EspEfuseArgs()
            args.force_write_always = True
            args.block = [self.BLK3]
            args.datafile = [StringIO.StringIO(data)]
            args.offset = 6
            self.operations.burn_block_data(self.esp, self.efuses, args)

            words = self.efuses.blocks[self.efuses.get_index_block_by_name(self.BLK3)].get_words()
            self.assertEqual([0,
                            struct.unpack("<H", "12")[0] << 16,
                            struct.unpack("<I", "34EA")[0],
                            0,
                            0,
                            0], words)

            args.offset = 12
            args.block = [self.BLK3]
            args.datafile = [StringIO.StringIO(data)]
            self.operations.burn_block_data(self.esp, self.efuses, args)
            words = self.efuses.blocks[self.efuses.get_index_block_by_name(self.BLK3)].get_words()
            self.assertEqual([0,
                            struct.unpack("<H", "12")[0] << 16,
                            struct.unpack("<I", "34EA")[0],
                            struct.unpack("<I", "1234")[0],
                            struct.unpack("<H", "EA")[0],
                            0], words)
            self.assertEqual(0, self.efuses.get_coding_scheme_warnings())

class TestBurnEfuse(EfuseTestCase):
    def test_burn_efuses(self):
        args = EspEfuseArgs()
        if self.chip == "ESP32":
            args.name_value_pairs = {
                "KEY_STATUS": "1",
                "DISABLE_SDIO_HOST": "1",
                "MAC_VERSION": "1",
                "ABS_DONE_0": "1",
                }
        else:
            args.name_value_pairs = {
                "SOFT_DIS_JTAG": "1",
                "SPI_BOOT_CRYPT_CNT": "2",
                "KEY_PURPOSE_0": "2",
                # "KEY_PURPOSE_1": "XTS_AES_256_KEY_1", the string value is avalible from the command line interface.
                "SECURE_VERSION": "7",
                }
        self.operations.burn_efuse(self.esp, self.efuses, args)


class TestBurnBit(EfuseTestCase):
    def test_burn_bits(self):
        args = EspEfuseArgs()
        args.block = self.BLK3
        args.bit_number = [0, 1, 2, 4, 8, 16, 32, 64, 96, 128, 160, 192, 224, 255]
        self.operations.burn_bit(self.esp, self.efuses, args)
        words = self.efuses.blocks[self.efuses.get_index_block_by_name(self.BLK3)].get_bitstring()
        self.assertEqual("0x8000000100000001000000010000000100000001000000010000000100010117", words)


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
