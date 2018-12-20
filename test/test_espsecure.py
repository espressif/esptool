#!/usr/bin/env python
#
# Tests for espsecure.py
#
# Assumes openssl binary is in the PATH
import unittest
import subprocess
import os
import os.path
import io
import sys
import tempfile
from collections import namedtuple

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
os.chdir(TEST_DIR)

try:
    import espsecure
except ImportError:
    sys.path.insert(0, os.path.join(TEST_DIR, ".."))
    import espsecure

import esptool

class EspSecureTestCase(unittest.TestCase):

    def run_espsecure(self, args):
        """ Run espsecure.py with the specified arguments

        Returns output as a string if there is any, raises an exception if espsecure.py fails
        """
        cmd = [sys.executable, ESPSECURE_PY ] + args.split(" ")
        print("Running %s..." % (" ".join(cmd)))

        try:
            output = subprocess.check_output([str(s) for s in cmd],
                                             cwd=TEST_DIR,
                                             stderr=subprocess.STDOUT)
            print(output)
            return output.decode("utf-8")
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise e

def _open(image_file):
    return open(os.path.join('secure_images', image_file), 'rb')

class ESP32SecureBootloaderTests(unittest.TestCase):

    def test_digest_bootloader(self):
        DBArgs = namedtuple('digest_bootloader_args', [
            'keyfile',
            'output',
            'iv',
            'image' ])

        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            args = DBArgs(_open('256bit_key.bin'),
                          output_file.name,
                          _open('256bit_iv.bin'),
                          _open('bootloader.bin'))
            espsecure.digest_secure_bootloader(args)

            with open(output_file.name, 'rb') as of:
                with _open('bootloader_digested.bin') as ef:
                    self.assertEqual(ef.read(), of.read())
        finally:
            os.unlink(output_file.name)

class ECDSASigningTests(unittest.TestCase):

    def test_sign_data(self):
        SignArgs = namedtuple('sign_data_args', [
            'keyfile',
            'output',
            'datafile' ])

        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            # Note: signing bootloader is not actually needed
            # for ESP32, it's just a handy file to sign
            args = SignArgs(_open('ecdsa_secure_boot_signing_key.pem'),
                            output_file.name,
                            _open('bootloader.bin'))
            espsecure.sign_data(args)

            with open(output_file.name, 'rb') as of:
                with _open('bootloader_signed.bin') as ef:
                    self.assertEqual(ef.read(), of.read())

        finally:
            os.unlink(output_file.name)

    def test_verify_signature(self):
        VerifyArgs = namedtuple('verify_signature_args', [
            'keyfile',
            'datafile' ])

        args = VerifyArgs(_open('ecdsa_secure_boot_signing_key.pem'),
                          _open('bootloader_signed.bin'))
        espsecure.verify_signature(args)


if __name__ == '__main__':
    print("Running espsecure tests...")
    print("Using espsecure %s at %s" % (esptool.__version__, os.path.abspath(espsecure.__file__)))
    unittest.main(buffer=True)
