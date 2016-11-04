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
import struct
import pyaes
import ecdsa

def get_chunks(source, chunk_len):
    """ Returns an iterator over 'chunk_len' chunks of 'source' """
    return (source[i: i+chunk_len] for i in range(0, len(source), chunk_len))


def digest_secure_bootloader(args):
    """ Calculate the digest of a bootloader image, in the same way the hardware
    secure boot engine would do so. Can be used with a pre-loaded key to update a
    secure bootloader. """
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
    if len(key) != 32:
        raise esptool.FatalError("Key file contains wrong length (%d bytes), 32 expected." % len(key))
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


def generate_signing_key(args):
    """ Generate an ECDSA signing key for signing secure boot images (post-bootloader) """
    if os.path.exists(args.keyfile):
        raise esptool.FatalError("ERROR: Key file %s already exists" % args.keyfile)
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    with open(args.keyfile, "wb") as f:
        f.write(sk.to_pem())
    print("ECDSA NIST256p private key in PEM format written to %s" % args.keyfile)


def _load_key(args):
    sk = ecdsa.SigningKey.from_pem(args.keyfile.read())
    if sk.curve != ecdsa.NIST256p:
        raise esptool.FatalError("Signing key uses incorrect curve. ESP32 Secure Boot only supports NIST256p (openssl calls this curve 'prime256v1")
    return sk

def sign_data(args):
    """ Sign a data file with a ECDSA private key, append binary signature to file contents """
    sk = _load_key(args)

    # calculate SHA512 digest of binary & sign it
    digest = hashlib.sha512()
    binary_content = args.datafile.read()
    digest.update(binary_content)
    signature = sk.sign_deterministic(digest.digest())

    if args.output is None or os.path.abspath(args.output) == os.path.abspath(args.datafile.name):  # append signature to input file
        args.datafile.close()
        outfile = open(args.datafile.name, "ab")
    else:  # write file & signature to new file
        outfile = open(args.output, "wb")
        outfile.write(binary_content)
    outfile.write(struct.pack("I", 0))  # Version indicator, allow for different curves/formats later
    outfile.write(signature)
    outfile.close()
    print "Signed %d bytes of data from %s with key %s" % (len(binary_content), args.datafile.name, args.keyfile.name)


def extract_public_key(args):
    """ Load an ECDSA private key and extract the embedded public key as raw binary data. """
    sk = _load_key(args)
    vk = sk.get_verifying_key()
    args.public_keyfile.write(vk.to_string())
    print "%s public key extracted to %s" % (args.keyfile.name, args.public_keyfile.name)


def digest_private_key(args):
    sk = _load_key(args)
    repr(sk.to_string())
    digest = hashlib.sha256()
    digest.update(sk.to_string())
    args.digest_file.write(digest.digest())
    print "SHA-256 digest of private key %s written to %s" % (args.keyfile.name, args.digest_file.name)


def main():
    parser = argparse.ArgumentParser(description='espsecure.py v%s - ESP32 Secure Boot & Flash Encryption tool' % esptool.__version__, prog='espsecure')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run espefuse.py {command} -h for additional help')

    p = subparsers.add_parser('digest_secure_bootloader',
                          help='Take a bootloader binary image and a secure boot key, and output a combined digest+binary suitable for flashing along with the precalculated secure boot key.')
    p.add_argument('--keyfile', '-k', help="256 bit key for secure boot digest.", type=argparse.FileType('rb'), required=True)
    p.add_argument('--output', '-o', help="Output file for signed digest image.")
    p.add_argument('--iv', help="128 byte IV file. Supply a file for testing purposes only, if not supplied an IV will be randomly generated.", type=argparse.FileType('rb'))
    p.add_argument('image', help="Bootloader image file to calculate digest from", type=argparse.FileType('rb'))

    p = subparsers.add_parser('generate_signing_key',
                              help='Generate a private key for signing secure boot images. Key file is generated in PEM format, and contains a ECDSA NIST256p private key and matching public key.')
    p.add_argument('keyfile', help="Filename for private key file (embedded public key)")

    p = subparsers.add_parser('sign_data',
                              help='Sign a data file for use with secure boot. Signing algorithm is determinsitic ECDSA w/ SHA-512.')
    p.add_argument('--keyfile', '-k', help="Private key file for signing. Key is in PEM format, ECDSA NIST256p curve. generate_signing_key command can be used to generate a suitable signing key.", type=argparse.FileType('rb'), required=True)
    p.add_argument('--output', '-o', help="Output file for signed digest image. Default is to append signature to existing file.")
    p.add_argument('datafile', help="Data file to sign.", type=argparse.FileType('rb'))

    p = subparsers.add_parser('extract_public_key',
                              help='Extract the public verification key for signatures, save it as a raw binary file.')
    p.add_argument('--keyfile', '-k', help="Private key file to extract the public verification key from.", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('public_keyfile', help="File to save new public key) into", type=argparse.FileType('wb'))

    p = subparsers.add_parser('digest_private_key', help='Generate an SHA-256 digest of the private signing key. This can be used as a reproducible secure bootloader key.')
    p.add_argument('--keyfile', '-k', help="Private key file to generate a digest from.", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('digest_file', help="File to write 32 byte digest into", type=argparse.FileType('wb'))

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
