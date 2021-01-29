#!/usr/bin/env python
from __future__ import division, print_function

import itertools
import os
import os.path
import subprocess
import sys
import tempfile
import unittest

IMAGES_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "images")
try:
    ESPTOOL_PY = os.environ["ESPTOOL_PY"]
except KeyError:
    ESPTOOL_PY = os.path.join(IMAGES_DIR, "../..", "esptool.py")

# import the version of esptool we are testing with
sys.path.append(os.path.dirname(ESPTOOL_PY))


from esptool import byte


def read_image(filename):
    with open(os.path.join(IMAGES_DIR, filename), "rb") as f:
        return f.read()


class MergeBinTests(unittest.TestCase):

    def run_merge_bin(self, chip, offsets_names, options=[]):
        """ Run merge_bin on a list of (offset, filename) tuples
        with output to a named temporary file.

        Filenames are relative to the 'test/images' directory.

        Returns the contents of the merged file if successful.
        """
        output_file = tempfile.NamedTemporaryFile(delete=False)
        try:
            output_file.close()

            cmd = [sys.executable, ESPTOOL_PY, "--chip", chip, "merge_bin", "-o", output_file.name] + options
            for (offset, name) in offsets_names:
                cmd += [hex(offset), name]
            print("Executing %s" % (" ".join(cmd)))

            output = str(subprocess.check_output(cmd, cwd=IMAGES_DIR, stderr=subprocess.STDOUT))
            print(output)
            self.assertFalse("warning" in output.lower(), "merge_bin should not output warnings")

            with open(output_file.name, "rb") as f:
                return f.read()
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise
        finally:
            os.unlink(output_file.name)

    def assertAllFF(self, some_bytes):
        # this may need some improving as the failed assert messages may be very long and/or useless!
        self.assertEqual(b'\xFF' * len(some_bytes), some_bytes)

    def test_simple_merge(self):
        merged = self.run_merge_bin("esp8266", [(0x0, "one_kb.bin"),
                                                (0x1000, "one_kb.bin"),
                                                (0x10000, "one_kb.bin")])
        one_kb = read_image("one_kb.bin")

        self.assertEqual(0x400, len(one_kb))

        self.assertEqual(0x10400, len(merged))
        self.assertEqual(one_kb, merged[:0x400])
        self.assertEqual(one_kb, merged[0x1000:0x1400])
        self.assertEqual(one_kb, merged[0x10000:])

        self.assertAllFF(merged[0x400:0x1000])
        self.assertAllFF(merged[0x1400:0x10000])

    def test_args_out_of_order(self):
        # no matter which order we supply arguments, the output should be the same
        args = [(0x0, "one_kb.bin"),
                (0x1000, "one_kb.bin"),
                (0x10000, "one_kb.bin")]
        merged_orders = [self.run_merge_bin("esp8266", perm_args) for perm_args in itertools.permutations(args)]
        for m in merged_orders:
            self.assertEqual(merged_orders[0], m)

    def test_error_overlap(self):
        args = [(0x1000, "one_mb.bin"),
                (0x20000, "one_kb.bin")]
        for perm_args in itertools.permutations(args):
            with self.assertRaises(subprocess.CalledProcessError) as fail:
                self.run_merge_bin("esp32", perm_args)
            self.assertIn(b"overlap", fail.exception.output)

    def test_leading_padding(self):
        merged = self.run_merge_bin("esp32c3", [(0x100000, "one_mb.bin")])
        self.assertAllFF(merged[:0x100000])
        self.assertEqual(read_image("one_mb.bin"), merged[0x100000:])

    def test_update_bootloader_params(self):
        merged = self.run_merge_bin("esp32", [(0x1000, "bootloader_esp32.bin"), (0x10000, "ram_helloworld/helloworld-esp32.bin")],
                                    ["--flash_size", "2MB", "--flash_mode", "dout"])
        self.assertAllFF(merged[:0x1000])

        bootloader = read_image("bootloader_esp32.bin")
        helloworld = read_image("ram_helloworld/helloworld-esp32.bin")

        # test the bootloader is unchanged apart from the header (updating the header doesn't change CRC,
        # and doesn't update the SHA although it will invalidate it!)
        self.assertEqual(merged[0x1010:0x1000 + len(bootloader)], bootloader[0x10:])

        # check the individual bytes in the header are as expected
        merged_hdr = merged[0x1000:0x1010]
        bootloader_hdr = bootloader[:0x10]
        self.assertEqual(bootloader_hdr[:2], merged_hdr[:2])
        self.assertEqual(3, byte(merged_hdr, 2))  # flash mode dout
        self.assertEqual(0x10, byte(merged_hdr, 3) & 0xF0)  # flash size 2MB (ESP32)
        self.assertEqual(byte(bootloader_hdr, 3) & 0x0F, byte(merged_hdr, 3) & 0x0F)  # flash speed is unchanged
        self.assertEqual(bootloader_hdr[4:], merged_hdr[4:])  # remaining field are unchanged

        # check all the padding is as expected
        self.assertAllFF(merged[0x1000 + len(bootloader):0x10000])
        self.assertEqual(merged[0x10000:0x10000 + len(helloworld)], helloworld)

    def test_target_offset(self):
        merged = self.run_merge_bin("esp32", [(0x1000, "bootloader_esp32.bin"), (0x10000, "ram_helloworld/helloworld-esp32.bin")],
                                    ["--target-offset", "0x1000"])

        bootloader = read_image("bootloader_esp32.bin")
        helloworld = read_image("ram_helloworld/helloworld-esp32.bin")
        self.assertEqual(bootloader, merged[:len(bootloader)])
        self.assertEqual(helloworld, merged[0xF000:0xF000 + len(helloworld)])
        self.assertAllFF(merged[0x1000 + len(bootloader):0xF000])

    def test_fill_flash_size(self):
        merged = self.run_merge_bin("esp32c3", [(0x0, "bootloader_esp32c3.bin")],
                                    ["--fill-flash-size", "4MB"])
        bootloader = read_image("bootloader_esp32c3.bin")

        self.assertEqual(0x400000, len(merged))
        self.assertEqual(bootloader, merged[:len(bootloader)])
        self.assertAllFF(merged[len(bootloader):])

    def test_fill_flash_size_w_target_offset(self):
        merged = self.run_merge_bin("esp32", [(0x1000, "bootloader_esp32.bin"), (0x10000, "ram_helloworld/helloworld-esp32.bin")],
                                    ["--target-offset", "0x1000", "--fill-flash-size", "2MB"])

        self.assertEqual(0x200000 - 0x1000, len(merged))  # full length is without target-offset arg

        bootloader = read_image("bootloader_esp32.bin")
        helloworld = read_image("ram_helloworld/helloworld-esp32.bin")
        self.assertEqual(bootloader, merged[:len(bootloader)])
        self.assertEqual(helloworld, merged[0xF000:0xF000 + len(helloworld)])
        self.assertAllFF(merged[0xF000 + len(helloworld):])


if __name__ == '__main__':
    unittest.main(buffer=True)
