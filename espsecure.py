#!/usr/bin/env python
# ESP32 secure boot utility
# https://github.com/themadinventor/esptool
#
# Copyright (C) 2016 Espressif Systems (Shanghai) PTE LTD
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.
import esptool
import argparse
import sys
import os
import hashlib
import pyaes

def get_chunks(source, chunk_len):
    """ Returns an iterator over 'chunk_len' chunks of 'source' """
    return (source[i: i+chunk_len] for i in range(0, len(source), chunk_len))

def generate_key(args):
    if os.path.exists(args.keyfile):
        raise FatalError("Output key file %s already exists." % args.keyfile)
    with open(args.keyfile, "wb") as f:
        # Python docs say os.urandom is "suitable for cryptographic use"
        f.write(os.urandom(32))


def digest_secure_bootloader(args):
    if args.iv is not None:
        print "WARNING: --iv argument is for TESTING PURPOSES ONLY"
        iv = args.iv.read(128)
    else:
        iv = os.urandom(128)
    plaintext_image = args.image.read()
    plaintext = iv + plaintext_image

    # secure boot engine reads in 128 byte blocks (ie SHA512 block
    # size) , so pad plaintext image with 0xFF (ie unwritten flash)
    if len(plaintext) % 128 != 0:
        plaintext += "\xFF" * (128 - (len(plaintext) % 128))

    # Secure Boot digest algorithm in hardware uses AES256 ECB to
    # produce a ciphertext, then feeds output through SHA-512 to
    # produce the digest. Each block in/out of ECB is reordered
    # (due to hardware quirks not for security.)

    key = args.keyfile.read()
    aes = pyaes.AESModeOfOperationECB(key)
    digest = hashlib.sha512()

    for block in get_chunks(plaintext, 16):
        block = block[::-1]  # reverse each input block

        cipher_block = aes.encrypt(block)
        # reverse and then byte swap each word in the output block
        cipher_block = cipher_block[::-1]
        for block in get_chunks(cipher_block, 4):
            # Python hashlib can build each SHA block internally
            digest.update(block[::-1])

    if args.output is None:
        args.output = os.path.splitext(args.image.name)[0] + "-digest-0x0000.bin"
    with open(args.output, "wb") as f:
        f.write(iv)
        digest = digest.digest()
        for word in get_chunks(digest, 4):
            f.write(word[::-1])  # swap word order in the result
        f.write('\xFF' * (0x1000 - f.tell()))  # pad to 0x1000
        f.write(plaintext_image)

    print "digest+image written to %s" % args.output
    print "To load into chip, run:"
    print "espefuse.py --port PORT burn_key %s" % args.keyfile.name
    print "esptool.py --port PORT write_flash 0x0 %s" % args.output


def main():
    parser = argparse.ArgumentParser(description='espsecure.py v%s - ESP32 Secure Boot & Flash Encryption tool' % esptool.__version__, prog='espsecure')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run espefuse.py {command} -h for additional help')

    p = subparsers.add_parser('generate_key', help='Generate a random 256 bit key for either secure boot or flash encryption')
    p.add_argument('keyfile', help="Name of key file to generate")

    p = subparsers.add_parser('digest_secure_bootloader',
                          help='Take a bootloader binary image and a secure boot key, and output a combined digest+binary suitable for flashing along with the precalculated secure boot key.')
    p.add_argument('--keyfile', '-k', help="256 bit key for secure boot digest.", type=file, required=True)
    p.add_argument('--output', '-o', help="Output file for signed digest image.")
    p.add_argument('--iv', help="128 byte IV file. Supply a file for testing purposes only, if not supplied an IV will be randomly generated.", type=file)
    p.add_argument('image', help="Bootloader image file to calculate digest from", type=file)

    args = parser.parse_args()
    print 'espsecure.py v%s' % esptool.__version__
    # each 'operation' is a module-level function of the same name
    operation_func = globals()[args.operation]
    operation_func(args)


if __name__ == '__main__':
    try:
        main()
    except esptool.FatalError as e:
        print '\nA fatal error occurred: %s' % e
        sys.exit(2)
