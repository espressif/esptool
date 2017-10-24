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
from __future__ import division, print_function

import argparse
import hashlib
import os
import struct
import sys

import ecdsa
import esptool
import pyaes


def get_chunks(source, chunk_len):
    """ Returns an iterator over 'chunk_len' chunks of 'source' """
    return (source[i: i + chunk_len] for i in range(0, len(source), chunk_len))


def endian_swap_words(source):
    """ Endian-swap each word in 'source' bitstring """
    assert len(source) % 4 == 0
    words = "I" * (len(source) // 4)
    return struct.pack("<" + words, *struct.unpack(">" + words, source))


def swap_word_order(source):
    """ Swap the order of the words in 'source' bitstring """
    assert len(source) % 4 == 0
    words = "I" * (len(source) // 4)
    return struct.pack(words, *reversed(struct.unpack(words, source)))


def digest_secure_bootloader(args):
    """ Calculate the digest of a bootloader image, in the same way the hardware
    secure boot engine would do so. Can be used with a pre-loaded key to update a
    secure bootloader. """
    if args.iv is not None:
        print("WARNING: --iv argument is for TESTING PURPOSES ONLY")
        iv = args.iv.read(128)
    else:
        iv = os.urandom(128)
    plaintext_image = args.image.read()

    # secure boot engine reads in 128 byte blocks (ie SHA512 block
    # size) , so pad plaintext image with 0xFF (ie unwritten flash)
    if len(plaintext_image) % 128 != 0:
        plaintext_image += "\xFF" * (128 - (len(plaintext_image) % 128))

    plaintext = iv + plaintext_image

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
        f.write(b'\xFF' * (0x1000 - f.tell()))  # pad to 0x1000
        f.write(plaintext_image)
    print("digest+image written to %s" % args.output)


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

    # calculate signature of binary data
    binary_content = args.datafile.read()
    signature = sk.sign_deterministic(binary_content, hashlib.sha256)

    # back-verify signature
    vk = sk.get_verifying_key()
    vk.verify(signature, binary_content, hashlib.sha256)  # throws exception on failure

    if args.output is None or os.path.abspath(args.output) == os.path.abspath(args.datafile.name):  # append signature to input file
        args.datafile.close()
        outfile = open(args.datafile.name, "ab")
    else:  # write file & signature to new file
        outfile = open(args.output, "wb")
        outfile.write(binary_content)
    outfile.write(struct.pack("I", 0))  # Version indicator, allow for different curves/formats later
    outfile.write(signature)
    outfile.close()
    print("Signed %d bytes of data from %s with key %s" % (len(binary_content), args.datafile.name, args.keyfile.name))


def verify_signature(args):
    """ Verify a previously signed binary image, using the ECDSA public key """
    try:
        sk = _load_key(args)  # try to load as private key first
        vk = sk.get_verifying_key()
    except Exception:  # this is a catchall because ecdsa can throw private Exceptions
        args.keyfile.seek(0)
        vk = ecdsa.VerifyingKey.from_pem(args.keyfile.read())
    if vk.curve != ecdsa.NIST256p:
        raise esptool.FatalError("Public key uses incorrect curve. ESP32 Secure Boot only supports NIST256p (openssl calls this curve 'prime256v1")

    binary_content = args.datafile.read()
    data = binary_content[0:-68]
    sig_version, signature = struct.unpack("I64s", binary_content[-68:])
    if sig_version != 0:
        raise esptool.FatalError("Signature block has version %d. This version  of espsecure only supports version 0." % sig_version)
    print("Verifying %d bytes of data" % len(data))
    try:
        if vk.verify(signature, data, hashlib.sha256):
            print("Signature is valid")
        else:
            raise esptool.FatalError("Signature is not valid")
    except ecdsa.keys.BadSignatureError:
        raise esptool.FatalError("Signature is not valid")


def extract_public_key(args):
    """ Load an ECDSA private key and extract the embedded public key as raw binary data. """
    sk = _load_key(args)
    vk = sk.get_verifying_key()
    args.public_keyfile.write(vk.to_string())
    print("%s public key extracted to %s" % (args.keyfile.name, args.public_keyfile.name))


def digest_private_key(args):
    sk = _load_key(args)
    repr(sk.to_string())
    digest = hashlib.sha256()
    digest.update(sk.to_string())
    args.digest_file.write(digest.digest())
    print("SHA-256 digest of private key %s written to %s" % (args.keyfile.name, args.digest_file.name))


# flash encryption key tweaking pattern: the nth bit of the key is
# flipped if the kth bit in the flash offset is set, where mapping
# from n to k is provided by this list of 'n' bit offsets (range k)
_FLASH_ENCRYPTION_TWEAK_PATTERN = [
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
    8, 7, 6, 5
]
assert len(_FLASH_ENCRYPTION_TWEAK_PATTERN) == 256


def _flash_encryption_tweak_range(flash_crypt_config=0xF):
    """ Return a list of the bit indexes that the "key tweak" applies to,
    as determined by the FLASH_CRYPT_CONFIG 4 bit efuse value.
    """
    tweak_range = []
    if (flash_crypt_config & 1) != 0:
        tweak_range += range(67)
    if (flash_crypt_config & 2) != 0:
        tweak_range += range(67, 132)
    if (flash_crypt_config & 4) != 0:
        tweak_range += range(132, 195)
    if (flash_crypt_config & 8) != 0:
        tweak_range += range(195, 256)
    return tweak_range


def _flash_encryption_tweak_key(key, offset, tweak_range):
    """Apply XOR "tweak" values to the key, derived from flash offset
    'offset'. This matches the ESP32 hardware flash encryption.

    tweak_range is a list of bit indexes to apply the tweak to, as
    generated by _flash_encryption_tweak_range() from the
    FLASH_CRYPT_CONFIG efuse value.

    Return tweaked key
    """
    key = [ord(k) for k in key]
    offset_bits = [(offset & (1 << x)) != 0 for x in range(24)]

    for bit in tweak_range:
        if offset_bits[_FLASH_ENCRYPTION_TWEAK_PATTERN[bit]]:
            # note that each byte has a backwards bit order, compared
            # to how it is looked up in the tweak pattern table
            key[bit // 8] ^= 1 << (7 - (bit % 8))

    return b"".join(chr(k) for k in key)


def generate_flash_encryption_key(args):
    args.key_file.write(os.urandom(32))


def _flash_encryption_operation(output_file, input_file, flash_address, keyfile, flash_crypt_conf, do_decrypt):
    key = keyfile.read()
    if len(key) != 32:
        raise esptool.FatalError("Key file contains wrong length (%d bytes), 32 expected." % len(key))

    if flash_address % 16 != 0:
        raise esptool.FatalError("Starting flash address 0x%x must be a multiple of 16" % flash_address)

    if flash_crypt_conf == 0:
        print("WARNING: Setting FLASH_CRYPT_CONF to zero is not recommended")
    tweak_range = _flash_encryption_tweak_range(flash_crypt_conf)

    aes = None
    while True:
        block_offs = flash_address + input_file.tell()
        block = input_file.read(16)
        if len(block) == 0:
            break
        elif len(block) < 16:
            if do_decrypt:
                raise esptool.FatalError("Data length is not a multiple of 16 bytes")
            pad = 16 - len(block)
            block = block + os.urandom(pad)
            print("WARNING: Padding with %d bytes of random data (encrypted data must be multiple of 16 bytes long)" % pad)

        if (block_offs % 32 == 0) or aes is None:
            # each bit of the flash encryption key is XORed with tweak bits derived from the offset of 32 byte block of flash
            block_key = _flash_encryption_tweak_key(key, block_offs, tweak_range)
            aes = pyaes.AESModeOfOperationECB(block_key)

        block = block[::-1]  # reverse input block byte order

        # note AES is used inverted for flash encryption, so
        # "decrypting" flash uses AES encrypt algorithm and vice
        # versa. (This does not weaken AES.)
        if do_decrypt:
            block = aes.encrypt(block)
        else:
            block = aes.decrypt(block)

        block = block[::-1]  # reverse output block byte order
        output_file.write(block)


def decrypt_flash_data(args):
    return _flash_encryption_operation(args.output, args.encrypted_file, args.address, args.keyfile, args.flash_crypt_conf, True)


def encrypt_flash_data(args):
    return _flash_encryption_operation(args.output, args.plaintext_file, args.address, args.keyfile, args.flash_crypt_conf, False)


def main():
    parser = argparse.ArgumentParser(description='espsecure.py v%s - ESP32 Secure Boot & Flash Encryption tool' % esptool.__version__, prog='espsecure')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run espsecure.py {command} -h for additional help')

    p = subparsers.add_parser('digest_secure_bootloader',
                              help='Take a bootloader binary image and a secure boot key, and output a combined digest+binary ' +
                              'suitable for flashing along with the precalculated secure boot key.')
    p.add_argument('--keyfile', '-k', help="256 bit key for secure boot digest.", type=argparse.FileType('rb'), required=True)
    p.add_argument('--output', '-o', help="Output file for signed digest image.")
    p.add_argument('--iv', help="128 byte IV file. Supply a file for testing purposes only, if not supplied an IV will be randomly generated.",
                   type=argparse.FileType('rb'))
    p.add_argument('image', help="Bootloader image file to calculate digest from", type=argparse.FileType('rb'))

    p = subparsers.add_parser('generate_signing_key',
                              help='Generate a private key for signing secure boot images. Key file is generated in PEM format, ' +
                              'and contains a ECDSA NIST256p private key and matching public key.')
    p.add_argument('keyfile', help="Filename for private key file (embedded public key)")

    p = subparsers.add_parser('sign_data',
                              help='Sign a data file for use with secure boot. Signing algorithm is determinsitic ECDSA w/ SHA-512.')
    p.add_argument('--keyfile', '-k', help="Private key file for signing. Key is in PEM format, ECDSA NIST256p curve. " +
                   "generate_signing_key command can be used to generate a suitable signing key.", type=argparse.FileType('rb'), required=True)
    p.add_argument('--output', '-o', help="Output file for signed digest image. Default is to append signature to existing file.")
    p.add_argument('datafile', help="Data file to sign.", type=argparse.FileType('rb'))

    p = subparsers.add_parser('verify_signature',
                              help='Verify a data file previously signed by "sign_data", using the public key.')
    p.add_argument('--keyfile', '-k', help="Public key file for verification. Can be the private key file (public key is embedded).",
                   type=argparse.FileType('rb'), required=True)
    p.add_argument('datafile', help="Signed data file to verify signature.", type=argparse.FileType('rb'))

    p = subparsers.add_parser('extract_public_key',
                              help='Extract the public verification key for signatures, save it as a raw binary file.')
    p.add_argument('--keyfile', '-k', help="Private key file to extract the public verification key from.", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('public_keyfile', help="File to save new public key) into", type=argparse.FileType('wb'))

    p = subparsers.add_parser('digest_private_key', help='Generate an SHA-256 digest of the private signing key. ' +
                              'This can be used as a reproducible secure bootloader or flash encryption key.')
    p.add_argument('--keyfile', '-k', help="Private key file to generate a digest from.", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('digest_file', help="File to write 32 byte digest into", type=argparse.FileType('wb'))

    p = subparsers.add_parser('generate_flash_encryption_key', help='Generate a development-use 32 byte flash encryption key with random data.')
    p.add_argument('key_file', help="File to write 32 byte digest into", type=argparse.FileType('wb'))

    p = subparsers.add_parser('decrypt_flash_data', help='Decrypt some data read from encrypted flash (using known key)')
    p.add_argument('encrypted_file', help="File with encrypted flash contents", type=argparse.FileType('rb'))
    p.add_argument('--keyfile', '-k', help="File with flash encryption key", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('--output', '-o', help="Output file for plaintext data.", type=argparse.FileType('wb'),
                   required=True)
    p.add_argument('--address', '-a', help="Address offset in flash that file was read from.", required=True, type=esptool.arg_auto_int)
    p.add_argument('--flash_crypt_conf', help="Override FLASH_CRYPT_CONF efuse value (default is 0XF).", required=False, default=0xF, type=esptool.arg_auto_int)

    p = subparsers.add_parser('encrypt_flash_data', help='Encrypt some data suitable for encrypted flash (using known key)')
    p.add_argument('--keyfile', '-k', help="File with flash encryption key", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('--output', '-o', help="Output file for encrypted data.", type=argparse.FileType('wb'),
                   required=True)
    p.add_argument('--address', '-a', help="Address offset in flash where file will be flashed.", required=True, type=esptool.arg_auto_int)
    p.add_argument('--flash_crypt_conf', help="Override FLASH_CRYPT_CONF efuse value (default is 0XF).", required=False, default=0xF, type=esptool.arg_auto_int)
    p.add_argument('plaintext_file', help="File with plaintext content for encrypting", type=argparse.FileType('rb'))

    args = parser.parse_args()
    print('espsecure.py v%s' % esptool.__version__)
    if args.operation is None:
        parser.print_help()
        parser.exit(1)

    # each 'operation' is a module-level function of the same name
    operation_func = globals()[args.operation]
    operation_func(args)


def _main():
    try:
        main()
    except esptool.FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)


if __name__ == '__main__':
    _main()
