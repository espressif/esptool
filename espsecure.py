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
import operator
import os
import struct
import sys
import zlib
from collections import namedtuple

from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import int_to_bytes


import ecdsa

import esptool

try:
    _string_type = basestring
except NameError:
    # this has to be done with exception in order to avoid flake8 error
    # Python 3
    _string_type = str


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


def _load_hardware_key(keyfile):
    """ Load a 256-bit key, similar to stored in efuse, from a file

    192-bit keys will be extended to 256-bit using the same algorithm used
    by hardware if 3/4 Coding Scheme is set.
    """
    key = keyfile.read()
    if len(key) not in [24, 32]:
        raise esptool.FatalError("Key file contains wrong length (%d bytes), 24 or 32 expected." % len(key))
    if len(key) == 24:
        key = key + key[8:16]
        print("Using 192-bit key (extended)")
    else:
        print("Using 256-bit key")

    assert len(key) == 32
    return key


def digest_secure_bootloader(args):
    """ Calculate the digest of a bootloader image, in the same way the hardware
    secure boot engine would do so. Can be used with a pre-loaded key to update a
    secure bootloader. """
    _check_output_is_not_input(args.keyfile, args.output)
    _check_output_is_not_input(args.image, args.output)
    _check_output_is_not_input(args.iv, args.output)
    if args.iv is not None:
        print("WARNING: --iv argument is for TESTING PURPOSES ONLY")
        iv = args.iv.read(128)
    else:
        iv = os.urandom(128)
    plaintext_image = args.image.read()
    args.image.seek(0)

    # secure boot engine reads in 128 byte blocks (ie SHA512 block
    # size), but also doesn't look for any appended SHA-256 digest
    fw_image = esptool.ESP32FirmwareImage(args.image)
    if fw_image.append_digest:
        if len(plaintext_image) % 128 <= 32:
            # ROM bootloader will read to the end of the 128 byte block, but not
            # to the end of the SHA-256 digest at the end
            new_len = len(plaintext_image) - (len(plaintext_image) % 128)
            plaintext_image = plaintext_image[:new_len]

    # if image isn't 128 byte multiple then pad with 0xFF (ie unwritten flash)
    # as this is what the secure boot engine will see
    if len(plaintext_image) % 128 != 0:
        plaintext_image += b"\xFF" * (128 - (len(plaintext_image) % 128))

    plaintext = iv + plaintext_image

    # Secure Boot digest algorithm in hardware uses AES256 ECB to
    # produce a ciphertext, then feeds output through SHA-512 to
    # produce the digest. Each block in/out of ECB is reordered
    # (due to hardware quirks not for security.)

    key = _load_hardware_key(args.keyfile)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    digest = hashlib.sha512()

    for block in get_chunks(plaintext, 16):
        block = block[::-1]  # reverse each input block

        cipher_block = encryptor.update(block)
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
    if os.path.exists(args.keyfile):
        raise esptool.FatalError("ERROR: Key file %s already exists" % args.keyfile)
    if args.version == "1":
        """ Generate an ECDSA signing key for signing secure boot images (post-bootloader) """
        sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        with open(args.keyfile, "wb") as f:
            f.write(sk.to_pem())
        print("ECDSA NIST256p private key in PEM format written to %s" % args.keyfile)
    elif args.version == "2":
        """ Generate a RSA 3072 signing key for signing secure boot images """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
            backend=default_backend()
        ).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(args.keyfile, "wb") as f:
            f.write(private_key)
        print("RSA 3072 private key in PEM format written to %s" % args.keyfile)


def _load_ecdsa_signing_key(keyfile):
    sk = ecdsa.SigningKey.from_pem(keyfile.read())
    if sk.curve != ecdsa.NIST256p:
        raise esptool.FatalError("Signing key uses incorrect curve. ESP32 Secure Boot only supports NIST256p (openssl calls this curve 'prime256v1")
    return sk


def _load_sbv2_rsa_signing_key(keydata):
    sk = serialization.load_pem_private_key(keydata, password=None, backend=default_backend())
    if not isinstance(sk, rsa.RSAPrivateKey):
        raise esptool.FatalError("Incorrect RSA Signing key.")
    if sk.key_size != 3072:
        raise esptool.FatalError("Key file has length %d bits. Secure boot v2 only supports RSA-3072." % sk.key_size)
    return sk


def _load_sbv2_rsa_pub_key(keydata):
    vk = serialization.load_pem_public_key(keydata, backend=default_backend())
    if not isinstance(vk, rsa.RSAPublicKey):
        raise esptool.FatalError("Public key incorrect. Secure boot v2 requires RSA 3072 public key")
    if vk.key_size != 3072:
        raise esptool.FatalError("Key file has length %d bits. Secure boot v2 only supports RSA-3072." % vk.key_size)
    return vk


def _get_sbv2_rsa_pub_key(keyfile):
    key_data = keyfile.read()
    if b"-BEGIN RSA PRIVATE KEY" in key_data:
        vk = _load_sbv2_rsa_signing_key(key_data).public_key()
    elif b"-BEGIN PUBLIC KEY" in key_data:
        vk = _load_sbv2_rsa_pub_key(key_data)
    else:
        raise esptool.FatalError("Verification key does not appear to be an RSA Private or Public key in PEM format. Unsupported")
    return vk


def _get_sbv2_rsa_primitives(public_key):
    primitives = namedtuple('primitives', ['n', 'e', 'm', 'rinv'])
    numbers = public_key.public_numbers()
    primitives.n = numbers.n  #
    primitives.e = numbers.e  # two public key components

    # Note: this cheats and calls a private 'rsa' method to get the modular
    # inverse calculation.
    primitives.m = - rsa._modinv(primitives.n, 1 << 32)

    rr = 1 << (public_key.key_size * 2)
    primitives.rinv = rr % primitives.n
    return primitives


def sign_data(args):
    _check_output_is_not_input(args.keyfile, args.output)
    _check_output_is_not_input(args.datafile, args.output)
    if args.version == '1':
        return sign_secure_boot_v1(args)
    elif args.version == '2':
        return sign_secure_boot_v2(args)


def sign_secure_boot_v1(args):
    """ Sign a data file with a ECDSA private key, append binary signature to file contents """
    if len(args.keyfile) > 1:
        raise esptool.FatalError("Secure Boot V1 only supports one signing key")
    sk = _load_ecdsa_signing_key(args.keyfile[0])

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
    print("Signed %d bytes of data from %s with key %s" % (len(binary_content), args.datafile.name, args.keyfile[0].name))


def sign_secure_boot_v2(args):
    """ Sign a firmware app image with an RSA private key using RSA-PSS, write output file with a
    Secure Boot V2 header appended.
    """
    SECTOR_SIZE = 4096
    SIG_BLOCK_SIZE = 1216
    SIG_BLOCK_MAX_COUNT = 3

    signature_sector = b""
    key_count = len(args.keyfile)
    contents = args.datafile.read()

    if key_count > SIG_BLOCK_MAX_COUNT:
        print("WARNING: Upto %d signing keys are supported for ESP32-S2. For ESP32-ECO3 only 1 signing key is supported", SIG_BLOCK_MAX_COUNT)

    if len(contents) % SECTOR_SIZE != 0:
        pad_by = SECTOR_SIZE - (len(contents) % SECTOR_SIZE)
        print("Padding data contents by %d bytes so signature sector aligns at sector boundary" % pad_by)
        contents += b'\xff' * pad_by
    elif args.append_signatures:
        sig_block_num = 0

        while sig_block_num < SIG_BLOCK_MAX_COUNT:
            sig_block = validate_signature_block(contents, sig_block_num)
            if sig_block is None:
                break
            signature_sector += sig_block  # Signature sector is populated with already valid blocks
            sig_block_num += 1

        assert len(signature_sector) % SIG_BLOCK_SIZE == 0

        if sig_block_num == 0:
            print("No valid signature blocks found. Discarding --append-signature and proceeding to sign the image afresh.")
        else:
            print("%d valid signature block(s) already present in the signature sector." % sig_block_num)

            empty_signature_blocks = SIG_BLOCK_MAX_COUNT - sig_block_num
            if key_count > empty_signature_blocks:
                raise esptool.FatalError("Number of keys(%d) more than the empty signature blocks.(%d)" % (key_count, empty_signature_blocks))

            contents = contents[:len(contents) - SECTOR_SIZE]  # Signature stripped off the content (the legitimate blocks are included in signature_sector)

    print("%d signing key(s) found." % key_count)
    # Calculate digest of data file
    digest = hashlib.sha256()
    digest.update(contents)
    digest = digest.digest()

    for keyfile in args.keyfile:
        private_key = _load_sbv2_rsa_signing_key(keyfile.read())
        # Sign
        signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            utils.Prehashed(hashes.SHA256())
        )

        rsa_primitives = _get_sbv2_rsa_primitives(private_key.public_key())

        # Encode in signature block format
        #
        # Note: the [::-1] is to byte swap all of the bignum
        # values (signatures, coefficients) to little endian
        # for use with the RSA peripheral, rather than big endian
        # which is conventionally used for RSA.
        signature_block = struct.pack("<BBxx32s384sI384sI384s",
                                      0xe7,  # magic byte
                                      0x02,  # version
                                      digest,
                                      int_to_bytes(rsa_primitives.n)[::-1],
                                      rsa_primitives.e,
                                      int_to_bytes(rsa_primitives.rinv)[::-1],
                                      rsa_primitives.m & 0xFFFFFFFF,
                                      signature[::-1])

        signature_block += struct.pack("<I", zlib.crc32(signature_block) & 0xffffffff)
        signature_block += b'\x00' * 16   # padding

        assert len(signature_block) == SIG_BLOCK_SIZE
        signature_sector += signature_block

    assert len(signature_sector) > 0 and len(signature_sector) <= SIG_BLOCK_SIZE * 3 and len(signature_sector) % SIG_BLOCK_SIZE == 0
    total_sig_blocks = len(signature_sector) // SIG_BLOCK_SIZE

    # Pad signature_sector to sector
    signature_sector = signature_sector + \
        (b'\xff' * (SECTOR_SIZE - len(signature_sector)))
    assert len(signature_sector) == SECTOR_SIZE

    # Write to output file, or append to existing file
    if args.output is None:
        args.datafile.close()
        args.output = args.datafile.name
    with open(args.output, "wb") as f:
        f.write(contents + signature_sector)
    print("Signed %d bytes of data from %s. Signature sector now has %d signature blocks." % (len(contents), args.datafile.name, total_sig_blocks))


def verify_signature(args):
    if args.version == '1':
        return verify_signature_v1(args)
    elif args.version == '2':
        return verify_signature_v2(args)


def verify_signature_v1(args):
    """ Verify a previously signed binary image, using the ECDSA public key """
    key_data = args.keyfile.read()
    if b"-BEGIN EC PRIVATE KEY" in key_data:
        sk = ecdsa.SigningKey.from_pem(key_data)
        vk = sk.get_verifying_key()
    elif b"-BEGIN PUBLIC KEY" in key_data:
        vk = ecdsa.VerifyingKey.from_pem(key_data)
    elif len(key_data) == 64:
        vk = ecdsa.VerifyingKey.from_string(key_data,
                                            curve=ecdsa.NIST256p)
    else:
        raise esptool.FatalError("Verification key does not appear to be an EC key in PEM format or binary EC public key data. Unsupported")

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


def validate_signature_block(image_content, sig_blk_num):
    SECTOR_SIZE = 4096
    SIG_BLOCK_SIZE = 1216  # Refer to secure boot v2 signature block format for more details.

    offset = -SECTOR_SIZE + sig_blk_num * SIG_BLOCK_SIZE
    sig_blk = image_content[offset: offset + SIG_BLOCK_SIZE]
    assert(len(sig_blk) == SIG_BLOCK_SIZE)

    sig_data = struct.unpack("<BBxx32s384sI384sI384sI16x", sig_blk)
    crc = zlib.crc32(sig_blk[:1196])  # The signature block(1216 bytes) consists of the data part(1196 bytes) followed by a crc32(4 byte) and a 16 byte pad.

    if sig_data[0] != 0xe7 or sig_data[1] != 0x02 or sig_data[-1] != crc & 0xffffffff:  # Signature block invalid
        return None

    print("Signature block %d is valid. " % sig_blk_num)
    return sig_blk


def verify_signature_v2(args):
    """ Verify a previously signed binary image, using the RSA public key """
    SECTOR_SIZE = 4096
    SIG_BLOCK_MAX_COUNT = 3

    vk = _get_sbv2_rsa_pub_key(args.keyfile)
    image_content = args.datafile.read()
    if len(image_content) < SECTOR_SIZE or len(image_content) % SECTOR_SIZE != 0:
        raise esptool.FatalError("Invalid datafile. Data size should be non-zero & a multiple of 4096.")

    digest = digest = hashlib.sha256()
    digest.update(image_content[:-SECTOR_SIZE])
    digest = digest.digest()

    for sig_blk_num in range(SIG_BLOCK_MAX_COUNT):
        sig_blk = validate_signature_block(image_content, sig_blk_num)
        if sig_blk is None:
            raise esptool.FatalError("Signature block %d invalid. Signature could not be verified with the provided key." % sig_blk_num)
        sig_data = struct.unpack("<BBxx32s384sI384sI384sI16x", sig_blk)

        if sig_data[2] != digest:
            raise esptool.FatalError("Signature block image digest does not match the actual image digest %s. Expected %s." % (digest, sig_data[2]))

        try:
            vk.verify(
                sig_data[-2][::-1],
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                utils.Prehashed(hashes.SHA256())
            )
            print("Signature block %d verification successful with %s." % (sig_blk_num, args.keyfile.name))
            return
        except exceptions.InvalidSignature:
            print("Signature block %d is not signed by %s. Checking the next block" % (sig_blk_num, args.keyfile.name))
            continue
    raise esptool.FatalError("Checked all blocks. Signature could not be verified with the provided key.")


def extract_public_key(args):
    _check_output_is_not_input(args.keyfile, args.public_keyfile)
    if args.version == "1":
        """ Load an ECDSA private key and extract the embedded public key as raw binary data. """
        sk = _load_ecdsa_signing_key(args.keyfile)
        vk = sk.get_verifying_key()
        args.public_keyfile.write(vk.to_string())
    elif args.version == "2":
        """ Load an RSA private key and extract the public key as raw binary data. """
        sk = _load_sbv2_rsa_signing_key(args.keyfile.read())
        vk = sk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        args.public_keyfile.write(vk)
    print("%s public key extracted to %s" % (args.keyfile.name, args.public_keyfile.name))


def _sha256_digest(data):
    digest = hashlib.sha256()
    digest.update(data)
    return digest.digest()


def signature_info_v2(args):
    """ Validates the signature block and prints the rsa public key digest for valid blocks """
    SECTOR_SIZE = 4096
    SIG_BLOCK_MAX_COUNT = 3
    SIG_BLOCK_SIZE = 1216  # Refer to secure boot v2 signature block format for more details.

    image_content = args.datafile.read()
    if len(image_content) < SECTOR_SIZE or len(image_content) % SECTOR_SIZE != 0:
        raise esptool.FatalError("Invalid datafile. Data size should be non-zero & a multiple of 4096.")

    digest = _sha256_digest(image_content[:-SECTOR_SIZE])

    for sig_blk_num in range(SIG_BLOCK_MAX_COUNT):
        sig_blk = validate_signature_block(image_content, sig_blk_num)
        if sig_blk is None:
            print("Signature block %d absent/invalid. Skipping checking next blocks." % sig_blk_num)
            return

        sig_data = struct.unpack("<BBxx32s384sI384sI384sI16x", sig_blk)
        if sig_data[2] != digest:
            raise esptool.FatalError("Digest in signature block %d doesn't match the image digest." % (sig_blk_num))

        offset = -SECTOR_SIZE + sig_blk_num * SIG_BLOCK_SIZE
        sig_blk = image_content[offset: offset + SIG_BLOCK_SIZE]
        key_digest = _sha256_digest(sig_blk[36:812])

        print("Public key digest for block %d: %s" % (sig_blk_num, " ".join("{:02x}".format(c) for c in bytearray(key_digest))))


def _digest_rsa_public_key(keyfile):
    public_key = _get_sbv2_rsa_pub_key(keyfile)
    rsa_primitives = _get_sbv2_rsa_primitives(public_key)

    # Encode in the same way it is represented in the signature block
    #
    # Note: the [::-1] is to byte swap all of the bignum
    # values (signatures, coefficients) to little endian
    # for use with the RSA peripheral, rather than big endian
    # which is conventionally used for RSA.
    binary_format = struct.pack("<384sI384sI",
                                int_to_bytes(rsa_primitives.n)[::-1],
                                rsa_primitives.e,
                                int_to_bytes(rsa_primitives.rinv)[::-1],
                                rsa_primitives.m & 0xFFFFFFFF)

    return hashlib.sha256(binary_format).digest()


def digest_rsa_public_key(args):
    _check_output_is_not_input(args.keyfile, args.output)
    public_key_digest = _digest_rsa_public_key(args.keyfile)
    with open(args.output, "wb") as f:
        print("Writing the public key digest of %s to %s." % (args.keyfile.name, args.output))
        f.write(public_key_digest)


def digest_private_key(args):
    _check_output_is_not_input(args.keyfile, args.digest_file)
    sk = _load_ecdsa_signing_key(args.keyfile)
    repr(sk.to_string())
    digest = hashlib.sha256()
    digest.update(sk.to_string())
    result = digest.digest()
    if args.keylen == 192:
        result = result[0:24]
    args.digest_file.write(result)
    print("SHA-256 digest of private key %s%s written to %s" % (args.keyfile.name,
                                                                "" if args.keylen == 256
                                                                else " (truncated to 192 bits)",
                                                                args.digest_file.name))


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


def _flash_encryption_tweak_range_bits(flash_crypt_config=0xF):
    """ Return bits (in reverse order) that the "key tweak" applies to,
    as determined by the FLASH_CRYPT_CONFIG 4 bit efuse value.
    """
    tweak_range = 0
    if (flash_crypt_config & 1) != 0:
        tweak_range |= 0xFFFFFFFFFFFFFFFFE00000000000000000000000000000000000000000000000
    if (flash_crypt_config & 2) != 0:
        tweak_range |= 0x00000000000000001FFFFFFFFFFFFFFFF0000000000000000000000000000000
    if (flash_crypt_config & 4) != 0:
        tweak_range |= 0x000000000000000000000000000000000FFFFFFFFFFFFFFFE000000000000000
    if (flash_crypt_config & 8) != 0:
        tweak_range |= 0x0000000000000000000000000000000000000000000000001FFFFFFFFFFFFFFF
    return tweak_range


# Forward bit order masks
mul1        = 0x0000200004000080000004000080001000000200004000080000040000800010
mul2        = 0x0000000000000000200000000000000010000000000000002000000000000001

mul1_mask   = 0xffffffffffffff801ffffffffffffff00ffffffffffffff81ffffffffffffff0
mul2_mask   = 0x000000000000007fe00000000000000ff000000000000007e00000000000000f


def _flash_encryption_tweak_key(key, offset, tweak_range):
    """Apply XOR "tweak" values to the key, derived from flash offset
    'offset'. This matches the ESP32 hardware flash encryption.

    tweak_range is a list of bit indexes to apply the tweak to, as
    generated by _flash_encryption_tweak_range() from the
    FLASH_CRYPT_CONFIG efuse value.

    Return tweaked key
    """
    if esptool.PYTHON2:
        key = [ord(k) for k in key]
        assert len(key) == 32

        offset_bits = [(offset & (1 << x)) != 0 for x in range(24)]

        for bit in tweak_range:
            if offset_bits[_FLASH_ENCRYPTION_TWEAK_PATTERN[bit]]:
                # note that each byte has a backwards bit order, compared
                # to how it is looked up in the tweak pattern table
                key[bit // 8] ^= 1 << (7 - (bit % 8))

        key = b"".join(chr(k) for k in key)
        return key

    else:
        addr = offset >> 5
        key ^= ((mul1 * addr) | ((mul2 * addr) & mul2_mask)) & tweak_range
        return int.to_bytes(key, length=32, byteorder='big', signed=False)


def generate_flash_encryption_key(args):
    print("Writing %d random bits to key file %s" % (args.keylen, args.key_file.name))
    args.key_file.write(os.urandom(args.keylen // 8))


def _flash_encryption_operation_esp32(output_file, input_file, flash_address, keyfile, flash_crypt_conf, do_decrypt):
    key = _load_hardware_key(keyfile)

    if flash_address % 16 != 0:
        raise esptool.FatalError("Starting flash address 0x%x must be a multiple of 16" % flash_address)

    if flash_crypt_conf == 0:
        print("WARNING: Setting FLASH_CRYPT_CONF to zero is not recommended")

    if esptool.PYTHON2:
        tweak_range = _flash_encryption_tweak_range(flash_crypt_conf)
    else:
        tweak_range = _flash_encryption_tweak_range_bits(flash_crypt_conf)
        key = int.from_bytes(key, byteorder='big', signed=False)

    backend = default_backend()

    cipher = None
    block_offs = flash_address
    while True:
        block = input_file.read(16)
        if len(block) == 0:
            break
        elif len(block) < 16:
            if do_decrypt:
                raise esptool.FatalError("Data length is not a multiple of 16 bytes")
            pad = 16 - len(block)
            block = block + os.urandom(pad)
            print("Note: Padding with %d bytes of random data (encrypted data must be multiple of 16 bytes long)" % pad)

        if block_offs % 32 == 0 or cipher is None:
            # each bit of the flash encryption key is XORed with tweak bits derived from the offset of 32 byte block of flash
            block_key = _flash_encryption_tweak_key(key, block_offs, tweak_range)

            if cipher is None:  # first pass
                cipher = Cipher(algorithms.AES(block_key), modes.ECB(), backend=backend)

                # note AES is used inverted for flash encryption, so
                # "decrypting" flash uses AES encrypt algorithm and vice
                # versa. (This does not weaken AES.)
                actor = cipher.encryptor() if do_decrypt else cipher.decryptor()
            else:
                # performance hack: changing the key using pyca-cryptography API requires recreating
                # 'actor'. With openssl backend, this re-initializes the openssl cipher context. To save some time,
                # manually call EVP_CipherInit_ex() in the openssl backend to update the key.
                # If it fails, fall back to recreating the entire context via public API.
                try:
                    backend = actor._ctx._backend
                    res = backend._lib.EVP_CipherInit_ex(
                        actor._ctx._ctx,
                        backend._ffi.NULL,
                        backend._ffi.NULL,
                        backend._ffi.from_buffer(block_key),
                        backend._ffi.NULL,
                        actor._ctx._operation,
                    )
                    backend.openssl_assert(res != 0)
                except AttributeError:
                    # backend is not an openssl backend, or implementation has changed: fall back to the slow safe version
                    cipher.algorithm.key = block_key
                    actor = cipher.encryptor() if do_decrypt else cipher.decryptor()

        block = block[::-1]  # reverse input block byte order
        block = actor.update(block)

        output_file.write(block[::-1])  # reverse output block byte order
        block_offs += 16


def _flash_encryption_operation_aes_xts(output_file, input_file, flash_address, keyfile, do_decrypt):
    """
    Apply the AES-XTS algorithm with the hardware addressing scheme used by Espressif

    key = AES-XTS key (32 or 64 bytes)
    flash_address = address in flash to encrypt at. Must be multiple of 16 bytes.
    indata = Data to encrypt/decrypt. Must be multiple of 16 bytes.
    encrypt = True to Encrypt indata, False to decrypt indata.

    Returns a bitstring of the ciphertext or plaintext result.
    """

    backend = default_backend()
    key = _load_hardware_key(keyfile)
    indata = input_file.read()

    if flash_address % 16 != 0:
        raise esptool.FatalError("Starting flash address 0x%x must be a multiple of 16" % flash_address)

    if len(indata) % 16 != 0:
        raise esptool.FatalError("Input data length (%d) must be a multiple of 16" % len(indata))

    if len(indata) == 0:
        raise esptool.FatalError("Input data must be longer than 0")

    # left pad for a 1024-bit aligned address
    pad_left = flash_address % 0x80
    indata = (b"\x00" * pad_left) + indata

    # right pad for full 1024-bit blocks
    pad_right = len(indata) % 0x80
    if pad_right > 0:
        pad_right = 0x80 - pad_right
    indata = indata + (b"\x00" * pad_right)

    inblocks = _split_blocks(indata, 0x80)  # split into 1024 bit blocks

    output = b""
    for inblock in inblocks:  # for each block
        tweak = struct.pack("<I", (flash_address & ~0x7F)) + (b"\x00" * 12)
        flash_address += 0x80   # for next block

        if len(tweak) != 16:
            raise esptool.FatalError("Length of tweak must be 16, was {}".format(len(tweak)))

        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak), backend=backend)
        encryptor = cipher.decryptor() if do_decrypt else cipher.encryptor()

        inblock = inblock[::-1]               # reverse input
        outblock = encryptor.update(inblock)  # standard algo
        output += outblock[::-1]              # reverse output

    # undo any padding we applied to the input
    if pad_right != 0:
        output = output[:-pad_right]
    if pad_left != 0:
        output = output[pad_left:]

    # output length matches original input
    if len(output) != len(indata) - pad_left - pad_right:
        raise esptool.FatalError("Length of input data ({}) should match the output data ({})".format(len(indata) - pad_left - pad_right, len(output)))

    output_file.write(output)


def _split_blocks(text, block_len=16):
    """ Take a bitstring, split it into chunks of "block_len" each """
    assert len(text) % block_len == 0
    while len(text) > 0:
        yield text[0:block_len]
        text = text[block_len:]


def decrypt_flash_data(args):
    _check_output_is_not_input(args.keyfile, args.output)
    _check_output_is_not_input(args.encrypted_file, args.output)
    if args.aes_xts:
        return _flash_encryption_operation_aes_xts(args.output, args.encrypted_file, args.address, args.keyfile, True)
    else:
        return _flash_encryption_operation_esp32(args.output, args.encrypted_file, args.address, args.keyfile, args.flash_crypt_conf, True)


def encrypt_flash_data(args):
    _check_output_is_not_input(args.keyfile, args.output)
    _check_output_is_not_input(args.plaintext_file, args.output)
    if args.aes_xts:
        return _flash_encryption_operation_aes_xts(args.output, args.plaintext_file, args.address, args.keyfile, False)
    else:
        return _flash_encryption_operation_esp32(args.output, args.plaintext_file, args.address, args.keyfile, args.flash_crypt_conf, False)


def _samefile(p1, p2):
    try:
        return os.path.samefile(p1, p2)
    except (OSError, AttributeError):
        # AttributeError - Python 2.7 on Windows doesn't know os.path.samefile()
        # OSError (FileNotFoundError under Python 3)
        return os.path.normcase(os.path.normpath(p1)) == os.path.normcase(os.path.normpath(p2))


def _check_output_is_not_input(input_file, output_file):
    i = getattr(input_file, 'name', input_file)
    o = getattr(output_file, 'name', output_file)
    # i & o should be string containing the path to files if espsecure was invoked from command line
    # i & o still can be something else when espsecure was imported and the functions used directly (e.g. io.BytesIO())
    check_f = _samefile if isinstance(i, _string_type) and isinstance(o, _string_type) else operator.eq
    if check_f(i, o):
        raise esptool.FatalError('The input "{}" and output "{}" should not be the same!'.format(i, o))


class OutFileType(object):
    """
    This class is a replacement of argparse.FileType('wb'). It doesn't create a file immediately but only during the
    first write. This allows us to do some checking before, e.g. that we are not overwriting the input.

    argparse.FileType('w')('-') returns STDOUT but argparse.FileType('wb') is not.

    The file object is not closed on failure just like in the case of argparse.FileType('w').
    """
    def __init__(self):
        self.path = None
        self.file_obj = None

    def __call__(self, path):
        self.path = path
        return self

    def __repr__(self):
        return '{}({})'.format(type(self).__name__, self.path)

    def write(self, payload):
        if len(payload) > 0:
            if not self.file_obj:
                self.file_obj = open(self.path, 'wb')
            self.file_obj.write(payload)

    def close(self):
        if self.file_obj:
            self.file_obj.close()
            self.file_obj = None

    @property
    def name(self):
        return self.path


def main(custom_commandline=None):
    """
    Main function for espsecure

    custom_commandline - Optional override for default arguments parsing (that uses sys.argv), can be a list of custom arguments
    as strings. Arguments and their values need to be added as individual items to the list e.g. "--port /dev/ttyUSB1" thus
    becomes ['--port', '/dev/ttyUSB1'].
    """
    parser = argparse.ArgumentParser(description='espsecure.py v%s - ESP32 Secure Boot & Flash Encryption tool' % esptool.__version__, prog='espsecure')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run espsecure.py {command} -h for additional help')

    p = subparsers.add_parser('digest_secure_bootloader',
                              help='Take a bootloader binary image and a secure boot key, and output a combined digest+binary '
                              'suitable for flashing along with the precalculated secure boot key.')
    p.add_argument('--keyfile', '-k', help="256 bit key for secure boot digest.", type=argparse.FileType('rb'), required=True)
    p.add_argument('--output', '-o', help="Output file for signed digest image.")
    p.add_argument('--iv', help="128 byte IV file. Supply a file for testing purposes only, if not supplied an IV will be randomly generated.",
                   type=argparse.FileType('rb'))
    p.add_argument('image', help="Bootloader image file to calculate digest from", type=argparse.FileType('rb'))

    p = subparsers.add_parser('generate_signing_key',
                              help='Generate a private key for signing secure boot images as per the secure boot version. '
                              'Key file is generated in PEM format, '
                              'Secure Boot V1 - ECDSA NIST256p private key, Secure Boot V2 - RSA 3072 private key .')
    p.add_argument('--version', '-v', help="Version of the secure boot signing scheme to use.", choices=["1", "2"], default="1")
    p.add_argument('keyfile', help="Filename for private key file (embedded public key)")

    p = subparsers.add_parser('sign_data',
                              help='Sign a data file for use with secure boot. Signing algorithm is deterministic ECDSA w/ SHA-512 (V1) '
                              'or RSA-PSS w/ SHA-256 (V2).')
    p.add_argument('--version', '-v', help="Version of the secure boot signing scheme to use.", choices=["1", "2"], required=True)
    p.add_argument('--keyfile', '-k', help="Private key file for signing. Key is in PEM format.", type=argparse.FileType('rb'), required=True, nargs='+')
    p.add_argument('--append_signatures', '-a', help="Append signature block(s) to already signed image"
                   "Valid only for ESP32-S2.", action='store_true')
    p.add_argument('--output', '-o', help="Output file for signed digest image. Default is to sign the input file.")
    p.add_argument('datafile', help="File to sign. For version 1, this can be any file. For version 2, this must be a valid app image.",
                   type=argparse.FileType('rb'))

    p = subparsers.add_parser('verify_signature',
                              help='Verify a data file previously signed by "sign_data", using the public key.')
    p.add_argument('--version', '-v', help="Version of the secure boot scheme to use.", choices=["1", "2"], required=True)
    p.add_argument('--keyfile', '-k', help="Public key file for verification. Can be private or public key in PEM format.",
                   type=argparse.FileType('rb'), required=True)
    p.add_argument('datafile', help="Signed data file to verify signature.", type=argparse.FileType('rb'))

    p = subparsers.add_parser('extract_public_key',
                              help='Extract the public verification key for signatures, save it as a raw binary file.')
    p.add_argument('--version', '-v', help="Version of the secure boot signing scheme to use.", choices=["1", "2"], default="1")
    p.add_argument('--keyfile', '-k', help="Private key file (PEM format) to extract the public verification key from.", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('public_keyfile', help="File to save new public key into", type=OutFileType())

    p = subparsers.add_parser('digest_rsa_public_key', help='Generate an SHA-256 digest of the public key. '
                              'This digest is burned into the eFuse and asserts the legitimacy of the public key for Secure boot v2.')
    p.add_argument('--keyfile', '-k', help="Public key file for verification. Can be private or public key in PEM format.", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('--output', '-o', help="Output file for the digest.", required=True)

    p = subparsers.add_parser('signature_info_v2', help='Reads the signature block and provides the signature block information.')
    p.add_argument('datafile', help="Secure boot v2 signed data file.", type=argparse.FileType('rb'))

    p = subparsers.add_parser('digest_private_key', help='Generate an SHA-256 digest of the private signing key. '
                              'This can be used as a reproducible secure bootloader or flash encryption key.')
    p.add_argument('--keyfile', '-k', help="Private key file (PEM format) to generate a digest from.", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('--keylen', '-l', help="Length of private key digest file to generate (in bits). 3/4 Coding Scheme requires 192 bit key.",
                   choices=[192, 256], default=256, type=int)
    p.add_argument('digest_file', help="File to write 32 byte digest into", type=OutFileType())

    p = subparsers.add_parser('generate_flash_encryption_key', help='Generate a development-use 32 byte flash encryption key with random data.')
    p.add_argument('--keylen', '-l', help="Length of private key digest file to generate (in bits). 3/4 Coding Scheme requires 192 bit key.",
                   choices=[192, 256], default=256, type=int)
    p.add_argument('key_file', help="File to write 24 or 32 byte digest into", type=OutFileType())

    p = subparsers.add_parser('decrypt_flash_data', help='Decrypt some data read from encrypted flash (using known key)')
    p.add_argument('encrypted_file', help="File with encrypted flash contents", type=argparse.FileType('rb'))
    p.add_argument('--aes_xts', '-x', help="Decrypt data using AES-XTS as used on ESP32-S2 and ESP32-C3", action='store_true')
    p.add_argument('--keyfile', '-k', help="File with flash encryption key", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('--output', '-o', help="Output file for plaintext data.", type=OutFileType(),
                   required=True)
    p.add_argument('--address', '-a', help="Address offset in flash that file was read from.", required=True, type=esptool.arg_auto_int)
    p.add_argument('--flash_crypt_conf', help="Override FLASH_CRYPT_CONF efuse value (default is 0XF).", required=False, default=0xF, type=esptool.arg_auto_int)

    p = subparsers.add_parser('encrypt_flash_data', help='Encrypt some data suitable for encrypted flash (using known key)')
    p.add_argument('--aes_xts', '-x', help="Encrypt data using AES-XTS as used on ESP32-S2 and ESP32-C3", action='store_true')
    p.add_argument('--keyfile', '-k', help="File with flash encryption key", type=argparse.FileType('rb'),
                   required=True)
    p.add_argument('--output', '-o', help="Output file for encrypted data.", type=OutFileType(),
                   required=True)
    p.add_argument('--address', '-a', help="Address offset in flash where file will be flashed.", required=True, type=esptool.arg_auto_int)
    p.add_argument('--flash_crypt_conf', help="Override FLASH_CRYPT_CONF efuse value (default is 0XF).", required=False, default=0xF, type=esptool.arg_auto_int)
    p.add_argument('plaintext_file', help="File with plaintext content for encrypting", type=argparse.FileType('rb'))

    args = parser.parse_args(custom_commandline)
    print('espsecure.py v%s' % esptool.__version__)
    if args.operation is None:
        parser.print_help()
        parser.exit(1)

    try:
        # each 'operation' is a module-level function of the same name
        operation_func = globals()[args.operation]
        operation_func(args)
    finally:
        for arg_name in vars(args):
            obj = getattr(args, arg_name)
            if isinstance(obj, OutFileType):
                obj.close()


def _main():
    try:
        main()
    except esptool.FatalError as e:
        print('\nA fatal error occurred: %s' % e)
        sys.exit(2)


if __name__ == '__main__':
    _main()
