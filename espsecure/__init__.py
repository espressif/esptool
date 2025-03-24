# SPDX-FileCopyrightText: 2016-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later
import configparser
from dataclasses import dataclass
import rich_click as click
import hashlib
import operator
import os
import struct
import sys
import tempfile
import zlib
from typing import IO

from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import int_to_bytes

from esptool.logger import log

import esptool

SIG_BLOCK_MAGIC = 0xE7

# Scheme used in Secure Boot V2
SIG_BLOCK_VERSION_RSA = 0x02
SIG_BLOCK_VERSION_ECDSA = 0x03

# SHA scheme used in Secure Boot V2 ECDSA signature blocks
ECDSA_SHA_256 = 0x0
ECDSA_SHA_384 = 0x1

# Curve IDs used in Secure Boot V2 ECDSA signature blocks
CURVE_ID_P192 = 1
CURVE_ID_P256 = 2
CURVE_ID_P384 = 3

SECTOR_SIZE = 4096
SIG_BLOCK_SIZE = (
    1216  # Refer to secure boot v2 signature block format for more details.
)


def get_chunks(source: bytes, chunk_len: int):
    """Returns an iterator over 'chunk_len' chunks of 'source'"""
    return (source[i : i + chunk_len] for i in range(0, len(source), chunk_len))


def endian_swap_words(source: bytes) -> bytes:
    """Endian-swap each word in 'source' bitstring"""
    assert len(source) % 4 == 0
    words = "I" * (len(source) // 4)
    return struct.pack("<" + words, *struct.unpack(">" + words, source))


def swap_word_order(source: bytes) -> bytes:
    """Swap the order of the words in 'source' bitstring"""
    assert len(source) % 4 == 0
    words = "I" * (len(source) // 4)
    return struct.pack(words, *reversed(struct.unpack(words, source)))


def _load_hardware_key(
    keyfile: IO, is_flash_encryption_key: bool, aes_xts: bool = False
):
    """Load a 128/256/512-bit key, similar to stored in efuse, from a file

    128-bit keys will be extended to 256-bit using the SHA256 of the key
    192-bit keys will be extended to 256-bit using the same algorithm used
    by hardware if 3/4 Coding Scheme is set.
    """
    key = keyfile.read()
    if len(key) not in [16, 24, 32, 64]:
        raise esptool.FatalError(
            "Key file contains wrong length (%d bytes), 16, 24, 32 or 64 expected."
            % len(key)
        )
    if is_flash_encryption_key:
        if aes_xts:
            if len(key) not in [16, 32, 64]:
                raise esptool.FatalError(
                    "AES_XTS supports only 128, 256, and 512-bit keys. "
                    f"Provided key is {len(key) * 8} bits."
                )
        else:
            if len(key) not in [24, 32]:
                raise esptool.FatalError(
                    "ESP32 supports only 192 and 256-bit keys. Provided key is "
                    f"{len(key) * 8} bits. Use --aes_xts for other chips."
                )
    if len(key) == 16:
        key = _sha256_digest(key)
        print("Using 128-bit key (extended)")
    elif len(key) == 24:
        key = key + key[8:16]
        assert len(key) == 32
        print("Using 192-bit key (extended)")
    elif len(key) == 32:
        print("Using 256-bit key")
    else:
        print("Using 512-bit key")
    return key


def digest_secure_bootloader(
    keyfile: IO, output: str | None, iv_file: IO | None, image: IO
):
    """Calculate the digest of a bootloader image, in the same way the hardware
    secure boot engine would do so. Can be used with a pre-loaded key to update a
    secure bootloader."""
    _check_output_is_not_input(keyfile, output)
    _check_output_is_not_input(image, output)
    _check_output_is_not_input(iv_file, output)
    if iv_file is not None:
        print("WARNING: --iv argument is for TESTING PURPOSES ONLY")
        iv = iv_file.read(128)
    else:
        iv = os.urandom(128)
    plaintext_image = image.read()
    image.seek(0)

    # secure boot engine reads in 128 byte blocks (ie SHA512 block
    # size), but also doesn't look for any appended SHA-256 digest
    fw_image = esptool.bin_image.ESP32FirmwareImage(image)
    if fw_image.append_digest:
        if len(plaintext_image) % 128 <= 32:
            # ROM bootloader will read to the end of the 128 byte block, but not
            # to the end of the SHA-256 digest at the end
            new_len = len(plaintext_image) - (len(plaintext_image) % 128)
            plaintext_image = plaintext_image[:new_len]

    # if image isn't 128 byte multiple then pad with 0xFF (ie unwritten flash)
    # as this is what the secure boot engine will see
    if len(plaintext_image) % 128 != 0:
        plaintext_image += b"\xff" * (128 - (len(plaintext_image) % 128))

    plaintext = iv + plaintext_image

    # Secure Boot digest algorithm in hardware uses AES256 ECB to
    # produce a ciphertext, then feeds output through SHA-512 to
    # produce the digest. Each block in/out of ECB is reordered
    # (due to hardware quirks not for security.)

    key = _load_hardware_key(keyfile, False)
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

    if output is None:
        output = os.path.splitext(image.name)[0] + "-digest-0x0000.bin"
    with open(output, "wb") as f:
        f.write(iv)
        for word in get_chunks(digest.digest(), 4):
            f.write(word[::-1])  # swap word order in the result
        f.write(b"\xff" * (0x1000 - f.tell()))  # pad to 0x1000
        f.write(plaintext_image)
    print("digest+image written to %s" % output)


def _generate_ecdsa_signing_key(curve_id: ec.EllipticCurve, keyfile: str):
    if curve_id not in [ec.SECP192R1, ec.SECP256R1, ec.SECP384R1]:
        raise ValueError(
            f"Unsupported curve: {curve_id}, "
            "only NIST192p, NIST256p, NIST384p are supported."
        )

    private_key = ec.generate_private_key(curve_id())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(keyfile, "wb") as f:
        f.write(pem)


def generate_signing_key(version: int, scheme: str | None, keyfile: str):
    if os.path.exists(keyfile):
        raise esptool.FatalError(f"ERROR: Key file {keyfile} already exists")
    if version == "1":
        if scheme is not None:
            if scheme != "ecdsa256" and scheme is not None:
                raise esptool.FatalError("ERROR: V1 only supports ECDSA256")
        """
        Generate an ECDSA signing key for signing secure boot images (post-bootloader)
        """
        _generate_ecdsa_signing_key(ec.SECP256R1, keyfile)
        print(f"ECDSA NIST256p private key in PEM format written to {keyfile}")
    elif version == "2":
        if scheme == "rsa3072" or scheme is None:
            """Generate a RSA 3072 signing key for signing secure boot images"""
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=3072, backend=default_backend()
            ).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(keyfile, "wb") as f:
                f.write(private_key)
            print(f"RSA 3072 private key in PEM format written to {keyfile}")
        elif scheme == "ecdsa192":
            """Generate a ECDSA 192 signing key for signing secure boot images"""
            _generate_ecdsa_signing_key(ec.SECP192R1, keyfile)
            print(f"ECDSA NIST192p private key in PEM format written to {keyfile}")
        elif scheme == "ecdsa256":
            """Generate a ECDSA 256 signing key for signing secure boot images"""
            _generate_ecdsa_signing_key(ec.SECP256R1, keyfile)
            print(f"ECDSA NIST256p private key in PEM format written to {keyfile}")
        elif scheme == "ecdsa384":
            """Generate a ECDSA 384 signing key for signing secure boot images"""
            _generate_ecdsa_signing_key(ec.SECP384R1, keyfile)
            print(f"ECDSA NIST384p private key in PEM format written to {keyfile}")
        else:
            raise esptool.FatalError(f"ERROR: Unsupported signing scheme {scheme}")


def load_ecdsa_signing_key(keyfile: IO) -> ec.EllipticCurvePrivateKey:
    """Load ECDSA signing key"""
    try:
        sk = serialization.load_pem_private_key(
            keyfile.read(), password=None, backend=default_backend()
        )
    except ValueError:
        raise esptool.FatalError(
            "Incorrect ECDSA private key specified. "
            "Please check algorithm and/or format."
        )
    if not isinstance(sk.curve, (ec.SECP192R1, ec.SECP256R1)):
        raise esptool.FatalError("Supports NIST192p and NIST256p keys only")
    return sk


def _load_ecdsa_signing_key(keyfile: IO) -> ec.EllipticCurvePrivateKey:
    """Load ECDSA signing key for Secure Boot V1 only"""
    sk = load_ecdsa_signing_key(keyfile)
    if not isinstance(sk.curve, ec.SECP256R1):
        raise esptool.FatalError(
            "Signing key uses incorrect curve. ESP32 Secure Boot only supports "
            "NIST256p (openssl calls this curve 'prime256v1')"
        )
    return sk


def _load_ecdsa_verifying_key(keyfile: IO) -> ec.EllipticCurvePublicKey:
    """Load ECDSA verifying key for Secure Boot V1 only"""
    try:
        vk = serialization.load_pem_public_key(
            keyfile.read(), backend=default_backend()
        )
    except ValueError:
        raise esptool.FatalError(
            "Incorrect ECDSA public key specified. "
            "Please check algorithm and/or format."
        )
    if not isinstance(vk.curve, ec.SECP256R1):
        raise esptool.FatalError(
            "Signing key uses incorrect curve. ESP32 Secure Boot only supports "
            "NIST256p (openssl calls this curve 'prime256v1')"
        )
    return vk


def _load_sbv2_signing_key(
    keydata: bytes,
) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    """
    Load Secure Boot V2 signing key

    can be rsa.RSAPrivateKey or ec.EllipticCurvePrivateKey
    """
    sk = serialization.load_pem_private_key(
        keydata, password=None, backend=default_backend()
    )
    if isinstance(sk, rsa.RSAPrivateKey):
        if sk.key_size != 3072:
            raise esptool.FatalError(
                "Key file has length %d bits. Secure boot v2 only supports RSA-3072."
                % sk.key_size
            )
        return sk
    if isinstance(sk, ec.EllipticCurvePrivateKey):
        if not isinstance(sk.curve, (ec.SECP192R1, ec.SECP256R1, ec.SECP384R1)):
            raise esptool.FatalError(
                "Key file uses incorrect curve. Secure Boot V2 + ECDSA only supports "
                "NIST192p, NIST256p, NIST384p (aka prime192v1 / secp192r1, "
                "prime256v1 / secp256r1, secp384r1)"
            )
        return sk

    raise esptool.FatalError("Unsupported signing key for Secure Boot V2")


def _load_sbv2_pub_key(keydata: bytes) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
    """
    Load Secure Boot V2 public key, can be rsa.RSAPublicKey or ec.EllipticCurvePublicKey
    """
    vk = serialization.load_pem_public_key(keydata, backend=default_backend())
    if isinstance(vk, rsa.RSAPublicKey):
        if vk.key_size != 3072:
            raise esptool.FatalError(
                "Key file has length %d bits. Secure boot v2 only supports RSA-3072."
                % vk.key_size
            )
        return vk
    if isinstance(vk, ec.EllipticCurvePublicKey):
        if not isinstance(vk.curve, (ec.SECP192R1, ec.SECP256R1, ec.SECP384R1)):
            raise esptool.FatalError(
                "Key file uses incorrect curve. Secure Boot V2 + ECDSA only supports "
                "NIST192p, NIST256p, NIST384p (aka prime192v1 / secp192r1, "
                "prime256v1 / secp256r1, secp384r1)"
            )
        return vk

    raise esptool.FatalError("Unsupported public key for Secure Boot V2")


def _get_sbv2_pub_key(keyfile: IO) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
    key_data = keyfile.read()
    if (
        b"-BEGIN RSA PRIVATE KEY" in key_data
        or b"-BEGIN EC PRIVATE KEY" in key_data
        or b"-BEGIN PRIVATE KEY" in key_data
    ):
        return _load_sbv2_signing_key(key_data).public_key()
    elif b"-BEGIN PUBLIC KEY" in key_data:
        vk = _load_sbv2_pub_key(key_data)
    else:
        raise esptool.FatalError(
            "Verification key does not appear to be an RSA Private or "
            "Public key in PEM format. Unsupported"
        )
    return vk


@dataclass
class Primitives:
    n: int
    e: int
    m: int
    rinv: int


def _get_sbv2_rsa_primitives(public_key: rsa.RSAPublicKey) -> Primitives:
    primitives = Primitives(0, 0, 0, 0)
    numbers = public_key.public_numbers()
    primitives.n = numbers.n
    primitives.e = numbers.e  # two public key components

    # Note: this cheats and calls a private 'rsa' method to get the modular
    # inverse calculation.
    primitives.m = -rsa._modinv(primitives.n, 1 << 32)

    rr = 1 << (public_key.key_size * 2)
    primitives.rinv = rr % primitives.n
    return primitives


def _microecc_format(a: int, b: int, curve_len: int) -> bytes:
    """
    Given two numbers (curve coordinates or (r,s) signature), write them out as a
    little-endian byte sequence suitable for micro-ecc
    "native little endian" mode
    """
    byte_len = int(curve_len / 8)
    ab: bytes = int_to_bytes(a, byte_len)[::-1] + int_to_bytes(b, byte_len)[::-1]
    assert len(ab) in [48, 64, 96]
    return ab


def sign_data(
    version: int,
    keyfile: list[IO],
    output: str | None,
    append_signatures: bool,
    hsm: bool,
    hsm_config: IO | None,
    pub_key: list[IO],
    signature: list[IO],
    datafile: IO,
):
    if keyfile:
        for file in keyfile:
            _check_output_is_not_input(file, output)
    _check_output_is_not_input(datafile, output)
    if version == "1":
        return sign_secure_boot_v1(keyfile, output, hsm, pub_key, signature, datafile)
    elif version == "2":
        return sign_secure_boot_v2(
            keyfile,
            output,
            append_signatures,
            hsm,
            hsm_config,
            pub_key,
            signature,
            datafile,
        )


def sign_secure_boot_v1(
    keyfile: list[IO],
    output: str | None,
    hsm: bool,
    pub_key: list[IO],
    signatures: list[IO],
    datafile: IO,
):
    """
    Sign a data file with a ECDSA private key, append binary signature to file contents
    """
    binary_content = datafile.read()

    if hsm:
        raise esptool.FatalError(
            "Secure Boot V1 does not support signing using an "
            "external Hardware Security Module (HSM)"
        )

    if signatures:
        print("Pre-calculated signatures found")
        if len(pub_key) > 1:
            raise esptool.FatalError("Secure Boot V1 only supports one signing key")
        raw_signature = signatures[0].read()
        # Signature needs to be DER-encoded for verification
        r = int.from_bytes(raw_signature[:32], "big")
        s = int.from_bytes(raw_signature[32:], "big")
        signature = utils.encode_dss_signature(r, s)
        # get verifying/public key
        vk = _load_ecdsa_verifying_key(pub_key[0])
    else:
        if len(keyfile) > 1:
            raise esptool.FatalError("Secure Boot V1 only supports one signing key")
        sk = _load_ecdsa_signing_key(keyfile[0])

        # calculate signature of binary data, returns DER-encoded signature
        signature = sk.sign(
            binary_content, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        )
        # get verifying/public key
        vk = sk.public_key()

    # back-verify signature
    vk.verify(
        signature, binary_content, ec.ECDSA(hashes.SHA256())
    )  # throws exception on failure

    # Secure boot signature block stores raw signature bytes, create raw signature
    r, s = utils.decode_dss_signature(signature)
    r_bytes = r.to_bytes(32, byteorder="big")
    s_bytes = s.to_bytes(32, byteorder="big")
    signature = r_bytes + s_bytes

    if output is None or os.path.abspath(output) == os.path.abspath(
        datafile.name
    ):  # append signature to input file
        datafile.close()
        outfile = open(datafile.name, "ab")
    else:  # write file & signature to new file
        outfile = open(output, "wb")
        outfile.write(binary_content)
    outfile.write(
        struct.pack("I", 0)
    )  # Version indicator, allow for different curves/formats later
    outfile.write(signature)
    outfile.close()
    print("Signed %d bytes of data from %s" % (len(binary_content), datafile.name))


def sign_secure_boot_v2(
    keyfile: list[IO],
    output: str | None,
    append_signatures: bool,
    hsm: bool,
    hsm_config: IO | None,
    pub_key: list[IO],
    signature: list[IO],
    datafile: IO,
):
    """
    Sign a firmware app image with an RSA private key using RSA-PSS,
    or ECDSA private key using P192 or P256 or P384.

    Write output file with a Secure Boot V2 header appended.
    """
    SIG_BLOCK_MAX_COUNT = 3
    contents = datafile.read()
    sig_block_num = 0
    signature_sector = b""

    if len(contents) % SECTOR_SIZE != 0:
        if signature:
            raise esptool.FatalError(
                "Secure Boot V2 requires the signature block to start "
                "from a 4KB aligned sector "
                "but the datafile supplied is not sector aligned."
            )
        else:
            pad_by = SECTOR_SIZE - (len(contents) % SECTOR_SIZE)
            print(
                f"Padding data contents by {pad_by} bytes "
                "so signature sector aligns at sector boundary"
            )
            contents += b"\xff" * pad_by

    elif append_signatures:
        while sig_block_num < SIG_BLOCK_MAX_COUNT:
            sig_block = validate_signature_block(contents, sig_block_num)
            if sig_block is None:
                break
            signature_sector += (
                sig_block  # Signature sector is populated with already valid blocks
            )
            sig_block_num += 1

        if len(signature_sector) % SIG_BLOCK_SIZE != 0:
            raise esptool.FatalError("Incorrect signature sector size")

        if sig_block_num == 0:
            print(
                "No valid signature blocks found. "
                "Discarding --append-signature and proceeding to sign the image afresh."
            )
        else:
            print(
                f"{sig_block_num} valid signature block(s) already present "
                "in the signature sector."
            )
            if sig_block_num == SIG_BLOCK_MAX_COUNT:
                raise esptool.FatalError(
                    f"Upto {SIG_BLOCK_MAX_COUNT} signature blocks are supported. "
                    "(For ESP32-ECO3 only 1 signature block is supported)"
                )

            # Signature stripped off the content
            # (the legitimate blocks are included in signature_sector)
            contents = contents[: len(contents) - SECTOR_SIZE]

    if hsm:
        if hsm_config is None:
            raise esptool.FatalError(
                "Config file is required to generate signature using an external HSM."
            )
        import espsecure.esp_hsm_sign as hsm_sign

        try:
            config = hsm_sign.read_hsm_config(hsm_config)
        except Exception as e:
            raise esptool.FatalError(f"Incorrect HSM config file format ({e})")
        if len(pub_key) == 0:
            pub_key = extract_pubkey_from_hsm(config)
        signature = generate_signature_using_hsm(config, contents)

    if signature:
        print("Pre-calculated signatures found")
        key_count = len(pub_key)
        if len(signature) != key_count:
            raise esptool.FatalError(
                f"Number of public keys ({key_count}) not equal to "
                f"the number of signatures {len(signature)}."
            )
    else:
        key_count = len(keyfile)

    empty_signature_blocks = SIG_BLOCK_MAX_COUNT - sig_block_num
    if key_count > empty_signature_blocks:
        raise esptool.FatalError(
            f"Number of keys({key_count}) more than the empty signature blocks."
            f"({empty_signature_blocks})"
        )

    print(f"{key_count} signing key(s) found.")

    # Generate signature block using pre-calculated signatures
    if signature:
        signature_block = generate_signature_block_using_pre_calculated_signature(
            signature, pub_key, contents
        )
    # Generate signature block by signing using private keys
    else:
        signature_block = generate_signature_block_using_private_key(keyfile, contents)

    if signature_block is None or len(signature_block) == 0:
        raise esptool.FatalError("Signature Block generation failed")

    signature_sector += signature_block

    if (
        len(signature_sector) < 0
        and len(signature_sector) > SIG_BLOCK_SIZE * 3
        and len(signature_sector) % SIG_BLOCK_SIZE != 0
    ):
        raise esptool.FatalError("Incorrect signature sector generation")

    total_sig_blocks = len(signature_sector) // SIG_BLOCK_SIZE

    # Pad signature_sector to sector
    signature_sector = signature_sector + (
        b"\xff" * (SECTOR_SIZE - len(signature_sector))
    )
    if len(signature_sector) != SECTOR_SIZE:
        raise esptool.FatalError("Incorrect signature sector size")

    # Write to output file, or append to existing file
    if output is None:
        datafile.close()
        output = datafile.name
    with open(output, "wb") as f:
        f.write(contents + signature_sector)
    print(
        f"Signed {len(contents)} bytes of data from {datafile.name}. "
        f"Signature sector now has {total_sig_blocks} signature blocks."
    )


def generate_signature_using_hsm(
    config: configparser.SectionProxy, contents: bytes
) -> list[IO]:
    import espsecure.esp_hsm_sign as hsm

    session = hsm.establish_session(config)
    # get the private key
    private_key = hsm.get_privkey_info(session, config)
    # Sign payload
    signature = hsm.sign_payload(private_key, contents)
    hsm.close_connection(session)
    temp_signature_file = tempfile.TemporaryFile()
    temp_signature_file.write(signature)
    temp_signature_file.seek(0)
    return [temp_signature_file]


def generate_signature_block_using_pre_calculated_signature(
    signature: list[IO], pub_key: list[IO], contents: bytes
) -> bytes:
    signature_blocks = b""
    for sig, pk in zip(signature, pub_key):
        try:
            public_key = _get_sbv2_pub_key(pk)
            sig_bytes = sig.read()
            if isinstance(public_key, rsa.RSAPublicKey):
                # Calculate digest of data file
                digest = _sha256_digest(contents)
                # RSA signature
                rsa_primitives = _get_sbv2_rsa_primitives(public_key)
                # Verify the signature
                public_key.verify(
                    sig_bytes,
                    digest,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                    utils.Prehashed(hashes.SHA256()),
                )

                signature_block = generate_rsa_signature_block(
                    digest, rsa_primitives, sig_bytes
                )
            else:
                # ECDSA signature
                numbers = public_key.public_numbers()
                if isinstance(numbers.curve, ec.SECP192R1):
                    curve_len = 192
                    curve_id = CURVE_ID_P192
                    hash_type = hashes.SHA256()
                    digest = _sha256_digest(contents)
                elif isinstance(numbers.curve, ec.SECP256R1):
                    curve_len = 256
                    curve_id = CURVE_ID_P256
                    hash_type = hashes.SHA256()
                    digest = _sha256_digest(contents)
                elif isinstance(numbers.curve, ec.SECP384R1):
                    curve_len = 384
                    curve_id = CURVE_ID_P384
                    hash_type = hashes.SHA384()
                    digest = _sha384_digest(contents)
                else:
                    raise esptool.FatalError("Invalid ECDSA curve instance.")

                # Verify the signature
                public_key.verify(
                    sig_bytes, digest, ec.ECDSA(utils.Prehashed(hash_type))
                )

                pubkey_point = _microecc_format(numbers.x, numbers.y, curve_len)
                r, s = utils.decode_dss_signature(sig_bytes)
                signature_rs = _microecc_format(r, s, curve_len)
                signature_block = generate_ecdsa_signature_block(
                    digest, curve_id, pubkey_point, signature_rs
                )
        except exceptions.InvalidSignature:
            raise esptool.FatalError(
                "Signature verification failed: Invalid Signature\n"
                "The pre-calculated signature has not been signed "
                "using the given public key"
            )
        signature_block += struct.pack("<I", zlib.crc32(signature_block) & 0xFFFFFFFF)
        signature_block += b"\x00" * 16  # padding

        if len(signature_block) != SIG_BLOCK_SIZE:
            raise esptool.FatalError("Incorrect signature block size")

        signature_blocks += signature_block
    return signature_blocks


def generate_signature_block_using_private_key(
    keyfiles: list[IO], contents: bytes
) -> bytes:
    signature_blocks = b""
    for keyfile in keyfiles:
        private_key = _load_sbv2_signing_key(keyfile.read())

        # Sign
        if isinstance(private_key, rsa.RSAPrivateKey):
            digest = _sha256_digest(contents)
            # RSA signature
            signature = private_key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
            rsa_primitives = _get_sbv2_rsa_primitives(private_key.public_key())
            signature_block = generate_rsa_signature_block(
                digest, rsa_primitives, signature
            )
        else:
            numbers = private_key.public_key().public_numbers()
            if isinstance(private_key.curve, ec.SECP192R1):
                curve_len = 192
                curve_id = CURVE_ID_P192
                hash_type = hashes.SHA256()
                digest = _sha256_digest(contents)
            elif isinstance(numbers.curve, ec.SECP256R1):
                curve_len = 256
                curve_id = CURVE_ID_P256
                hash_type = hashes.SHA256()
                digest = _sha256_digest(contents)
            elif isinstance(numbers.curve, ec.SECP384R1):
                curve_len = 384
                curve_id = CURVE_ID_P384
                hash_type = hashes.SHA384()
                digest = _sha384_digest(contents)
            else:
                raise esptool.FatalError("Invalid ECDSA curve instance.")

            # ECDSA signatures
            signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hash_type)))

            pubkey_point = _microecc_format(numbers.x, numbers.y, curve_len)

            r, s = utils.decode_dss_signature(signature)
            signature_rs = _microecc_format(r, s, curve_len)
            signature_block = generate_ecdsa_signature_block(
                digest, curve_id, pubkey_point, signature_rs
            )

        signature_block += struct.pack("<I", zlib.crc32(signature_block) & 0xFFFFFFFF)
        signature_block += b"\x00" * 16  # padding

        if len(signature_block) != SIG_BLOCK_SIZE:
            raise esptool.FatalError("Incorrect signature block size")

        signature_blocks += signature_block
    return signature_blocks


def generate_rsa_signature_block(
    digest: bytes, rsa_primitives: Primitives, signature: bytes
) -> bytes:
    """
    Encode in rsa signature block format

    Note: the [::-1] is to byte swap all of the bignum
    values (signatures, coefficients) to little endian
    for use with the RSA peripheral, rather than big endian
    which is conventionally used for RSA.
    """
    signature_block = struct.pack(
        "<BBxx32s384sI384sI384s",
        SIG_BLOCK_MAGIC,
        SIG_BLOCK_VERSION_RSA,
        digest,
        int_to_bytes(rsa_primitives.n)[::-1],
        rsa_primitives.e,
        int_to_bytes(rsa_primitives.rinv)[::-1],
        rsa_primitives.m & 0xFFFFFFFF,
        signature[::-1],
    )
    return signature_block


def generate_ecdsa_signature_block(
    digest: bytes, curve_id: int, pubkey_point: bytes, signature_rs: bytes
) -> bytes:
    """
    Encode in rsa signature block format

    # block is padded out to the much larger size
    # of the RSA version of this structure
    """

    if curve_id in [CURVE_ID_P192, CURVE_ID_P256]:
        signature_block = struct.pack(
            "<BBBx32sB64s64s1031x",
            SIG_BLOCK_MAGIC,
            SIG_BLOCK_VERSION_ECDSA,
            ECDSA_SHA_256,
            digest,
            curve_id,
            pubkey_point,
            signature_rs,
        )
    elif curve_id == CURVE_ID_P384:
        signature_block = struct.pack(
            "<BBBx48sB96s96s951x",
            SIG_BLOCK_MAGIC,
            SIG_BLOCK_VERSION_ECDSA,
            ECDSA_SHA_384,
            digest,
            curve_id,
            pubkey_point,
            signature_rs,
        )
    else:
        raise esptool.FatalError(
            "Invalid ECDSA curve ID detected while generating ECDSA signature block."
        )

    return signature_block


def verify_signature(
    version: int,
    hsm: bool,
    hsm_config: IO | None,
    keyfile: IO,
    datafile: IO,
):
    if version == "1":
        return verify_signature_v1(keyfile, datafile)
    elif version == "2":
        return verify_signature_v2(hsm, hsm_config, keyfile, datafile)


def verify_signature_v1(keyfile: IO, datafile: IO):
    """Verify a previously signed binary image, using the ECDSA public key"""
    key_data = keyfile.read()
    if b"-BEGIN EC PRIVATE KEY" in key_data:
        sk = serialization.load_pem_private_key(
            key_data, password=None, backend=default_backend()
        )
        vk = sk.public_key()
    elif b"-BEGIN PUBLIC KEY" in key_data:
        vk = serialization.load_pem_public_key(key_data, backend=default_backend())
    elif len(key_data) == 64:  # Raw public key bytes
        x = int.from_bytes(key_data[:32], byteorder="big")  # x coordinates
        y = int.from_bytes(key_data[32:], byteorder="big")  # y coordinates
        numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        vk = numbers.public_key(backend=default_backend())
    else:
        raise esptool.FatalError(
            "Verification key does not appear to be an EC key in PEM format "
            "or binary EC public key data. Unsupported"
        )

    if not isinstance(vk.curve, ec.SECP256R1):
        raise esptool.FatalError(
            "Public key uses incorrect curve. ESP32 Secure Boot only supports "
            "NIST256p (openssl calls this curve 'prime256v1')"
        )

    binary_content = datafile.read()
    data = binary_content[0:-68]
    sig_version, signature = struct.unpack("I64s", binary_content[-68:])
    if sig_version != 0:
        raise esptool.FatalError(
            "Signature block has version %d. This version of espsecure "
            "only supports version 0." % sig_version
        )
    print("Verifying %d bytes of data" % len(data))
    try:
        # Convert raw signature to DER format
        r = int.from_bytes(signature[:32], byteorder="big")
        s = int.from_bytes(signature[32:], byteorder="big")
        der_signature = utils.encode_dss_signature(r, s)

        vk.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        print("Signature is valid.")
    except exceptions.InvalidSignature:
        raise esptool.FatalError("Signature is not valid.")


def validate_signature_block(image_content: bytes, sig_blk_num: int) -> bytes | None:
    offset = -SECTOR_SIZE + sig_blk_num * SIG_BLOCK_SIZE
    sig_blk = image_content[offset : offset + SIG_BLOCK_SIZE]
    assert len(sig_blk) == SIG_BLOCK_SIZE

    # note: in case of ECDSA key, the exact fields in the middle are wrong
    # (but unused here)
    magic, version, _, _, _, _, _, _, blk_crc = struct.unpack(
        "<BBxx32s384sI384sI384sI16x", sig_blk
    )

    # The signature block(1216 bytes) consists of the data part(1196 bytes)
    # followed by a crc32(4 byte) and a 16 byte pad.
    calc_crc = zlib.crc32(sig_blk[:1196])

    is_invalid_block = magic != SIG_BLOCK_MAGIC
    is_invalid_block |= version not in [SIG_BLOCK_VERSION_RSA, SIG_BLOCK_VERSION_ECDSA]

    if is_invalid_block or blk_crc != calc_crc & 0xFFFFFFFF:  # Signature block invalid
        return None
    key_type = "RSA" if version == SIG_BLOCK_VERSION_RSA else "ECDSA"
    print(f"Signature block {sig_blk_num} is valid ({key_type}).")
    return sig_blk


def verify_signature_v2(hsm: bool, hsm_config: IO | None, keyfile: IO, datafile: IO):
    """Verify a previously signed binary image, using the RSA or ECDSA public key"""

    if hsm:
        if hsm_config is None:
            raise esptool.FatalError(
                "Config file is required to extract public key from an external HSM."
            )
        import espsecure.esp_hsm_sign as hsm_sign

        try:
            config = hsm_sign.read_hsm_config(hsm_config)
        except Exception as e:
            raise esptool.FatalError(f"Incorrect HSM config file format ({e})")
        # get public key from HSM
        keyfile = extract_pubkey_from_hsm(config)[0]

    vk = _get_sbv2_pub_key(keyfile)

    if isinstance(vk, rsa.RSAPublicKey):
        SIG_BLOCK_MAX_COUNT = 3
    elif isinstance(vk, ec.EllipticCurvePublicKey):
        SIG_BLOCK_MAX_COUNT = 1

    image_content = datafile.read()
    if len(image_content) < SECTOR_SIZE or len(image_content) % SECTOR_SIZE != 0:
        raise esptool.FatalError(
            "Invalid datafile. Data size should be non-zero & a multiple of 4096."
        )

    valid = False

    for sig_blk_num in range(SIG_BLOCK_MAX_COUNT):
        sig_blk = validate_signature_block(image_content, sig_blk_num)
        if sig_blk is None:
            print(f"Signature block {sig_blk_num} invalid. Skipping.")
            continue
        _, version, ecdsa_sha_version = struct.unpack("<BBBx", sig_blk[:4])

        if version == SIG_BLOCK_VERSION_ECDSA and ecdsa_sha_version == ECDSA_SHA_384:
            blk_digest = struct.unpack("<48s", sig_blk[4:52])[0]
            digest = _sha384_digest(image_content[:-SECTOR_SIZE])
        else:
            blk_digest = struct.unpack("<32s", sig_blk[4:36])[0]
            digest = _sha256_digest(image_content[:-SECTOR_SIZE])

        if blk_digest != digest:
            raise esptool.FatalError(
                "Signature block image digest does not match "
                f"the actual image digest {digest}. Expected {blk_digest}."
            )

        try:
            if isinstance(vk, rsa.RSAPublicKey):
                _, _, _, _, signature, _ = struct.unpack(
                    "<384sI384sI384sI16x", sig_blk[36:]
                )
                vk.verify(
                    signature[::-1],
                    digest,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                    utils.Prehashed(hashes.SHA256()),
                )
            else:
                if ecdsa_sha_version == ECDSA_SHA_256:
                    curve_id, _pubkey, encoded_rs = struct.unpack(
                        "B64s64s1031x4x16x", sig_blk[36:]
                    )
                elif ecdsa_sha_version == ECDSA_SHA_384:
                    curve_id, _pubkey, encoded_rs = struct.unpack(
                        "B96s96s951x4x16x", sig_blk[52:]
                    )

                assert curve_id in (CURVE_ID_P192, CURVE_ID_P256, CURVE_ID_P384)

                # length of each number in the keypair
                if curve_id == CURVE_ID_P192:
                    keylen = 24
                    hash_type = hashes.SHA256()
                elif curve_id == CURVE_ID_P256:
                    keylen = 32
                    hash_type = hashes.SHA256()
                elif curve_id == CURVE_ID_P384:
                    keylen = 48
                    hash_type = hashes.SHA384()

                r = int.from_bytes(encoded_rs[:keylen], "little")
                s = int.from_bytes(encoded_rs[keylen : keylen * 2], "little")

                signature = utils.encode_dss_signature(r, s)

                vk.verify(signature, digest, ec.ECDSA(utils.Prehashed(hash_type)))

            key_type = "RSA" if isinstance(vk, rsa.RSAPublicKey) else "ECDSA"

            print(
                f"Signature block {sig_blk_num} verification successful using "
                f"the supplied key ({key_type})."
            )
            valid = True

        except exceptions.InvalidSignature:
            print(
                f"Signature block {sig_blk_num} is not signed by the supplied key. "
                "Checking the next block"
            )
            continue

    if not valid:
        raise esptool.FatalError(
            "Checked all blocks. Signature could not be verified with the provided key."
        )


def extract_public_key(version: int, keyfile: IO, public_keyfile: IO):
    _check_output_is_not_input(keyfile, public_keyfile)
    if version == "1":
        """
        Load an ECDSA private key and extract the embedded public key
        as raw binary data.
        """
        sk = _load_ecdsa_signing_key(keyfile)
    elif version == "2":
        """
        Load an RSA or an ECDSA private key and extract the public key
        as raw binary data.
        """
        sk = _load_sbv2_signing_key(keyfile.read())
    vk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_keyfile.write(vk)
    print(f"{keyfile.name} public key extracted to {public_keyfile.name}")


def extract_pubkey_from_hsm(config: configparser.SectionProxy) -> list[IO]:
    import espsecure.esp_hsm_sign as hsm

    session = hsm.establish_session(config)
    # get public key from HSM
    public_key = hsm.get_pubkey(session, config)
    hsm.close_connection(session)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    temp_pub_key_file = tempfile.TemporaryFile()
    temp_pub_key_file.write(pem)
    temp_pub_key_file.seek(0)
    return [temp_pub_key_file]


def _sha256_digest(data):
    digest = hashlib.sha256()
    digest.update(data)
    return digest.digest()


def _sha384_digest(contents):
    # Calculate digest of data file
    digest = hashlib.sha384()
    digest.update(contents)
    return digest.digest()


def signature_info_v2(datafile: IO):
    """
    Validates the signature block and prints the RSA/ECDSA public key
    digest for valid blocks
    """
    SIG_BLOCK_MAX_COUNT = 3

    image_content = datafile.read()
    if len(image_content) < SECTOR_SIZE or len(image_content) % SECTOR_SIZE != 0:
        raise esptool.FatalError(
            "Invalid datafile. Data size should be non-zero & a multiple of 4096."
        )

    for sig_blk_num in range(SIG_BLOCK_MAX_COUNT):
        sig_blk = validate_signature_block(image_content, sig_blk_num)
        if sig_blk is None:
            print(
                "Signature block %d absent/invalid. Skipping checking next blocks."
                % sig_blk_num
            )
            return

        _, version, ecdsa_sha_version = struct.unpack("<BBBx", sig_blk[:4])

        if version == SIG_BLOCK_VERSION_ECDSA and ecdsa_sha_version == ECDSA_SHA_384:
            sig_data = struct.unpack("<BBxx48s1164x", sig_blk)
            digest = _sha384_digest(image_content[:-SECTOR_SIZE])
        else:
            sig_data = struct.unpack("<BBxx32s1180x", sig_blk)
            digest = _sha256_digest(image_content[:-SECTOR_SIZE])

        if sig_data[2] != digest:
            raise esptool.FatalError(
                "Digest in signature block %d doesn't match the image digest."
                % (sig_blk_num)
            )

        offset = -SECTOR_SIZE + sig_blk_num * SIG_BLOCK_SIZE
        sig_block = image_content[offset : offset + SIG_BLOCK_SIZE]
        if sig_data[1] == SIG_BLOCK_VERSION_RSA:
            key_digest = _sha256_digest(sig_block[36:812])
        elif sig_data[1] == SIG_BLOCK_VERSION_ECDSA:
            if ecdsa_sha_version == ECDSA_SHA_384:
                key_digest = _sha256_digest(sig_block[52:149])
            else:
                key_digest = _sha256_digest(sig_block[36:101])
        else:
            raise esptool.FatalError(
                "Unsupported scheme in signature block %d" % (sig_blk_num)
            )

        print(
            "Public key digest for block %d: %s"
            % (sig_blk_num, " ".join("{:02x}".format(c) for c in bytearray(key_digest)))
        )


def _digest_sbv2_public_key(keyfile: IO) -> bytes:
    public_key = _get_sbv2_pub_key(keyfile)

    if isinstance(public_key, rsa.RSAPublicKey):
        rsa_primitives = _get_sbv2_rsa_primitives(public_key)

        # Encode in the same way it is represented in the signature block
        #
        # Note: the [::-1] is to byte swap all of the bignum
        # values (signatures, coefficients) to little endian
        # for use with the RSA peripheral, rather than big endian
        # which is conventionally used for RSA.
        binary_format = struct.pack(
            "<384sI384sI",
            int_to_bytes(rsa_primitives.n)[::-1],
            rsa_primitives.e,
            int_to_bytes(rsa_primitives.rinv)[::-1],
            rsa_primitives.m & 0xFFFFFFFF,
        )
    else:  # ECC public key
        numbers = public_key.public_numbers()
        if isinstance(public_key.curve, ec.SECP192R1):
            curve_len = 192
            curve_id = CURVE_ID_P192
        elif isinstance(public_key.curve, ec.SECP256R1):
            curve_len = 256
            curve_id = CURVE_ID_P256
        elif isinstance(public_key.curve, ec.SECP384R1):
            curve_len = 384
            curve_id = CURVE_ID_P384

        pubkey_point = _microecc_format(numbers.x, numbers.y, curve_len)

        if curve_id == CURVE_ID_P384:
            binary_format = struct.pack(
                "<B96s",
                curve_id,
                pubkey_point,
            )
        else:
            binary_format = struct.pack(
                "<B64s",
                curve_id,
                pubkey_point,
            )

    return hashlib.sha256(binary_format).digest()


def digest_sbv2_public_key(keyfile: IO, output: str):
    _check_output_is_not_input(keyfile, output)
    public_key_digest = _digest_sbv2_public_key(keyfile)
    with open(output, "wb") as f:
        print(f"Writing the public key digest of {keyfile.name} to {output}.")
        f.write(public_key_digest)


def get_ecdsa_signing_key_raw_bytes(sk):
    return sk.private_numbers().private_value.to_bytes(
        length=(sk.key_size + 7) // 8, byteorder="big"
    )


def digest_private_key(keyfile: IO, keylen: int, digest_file: IO):
    _check_output_is_not_input(keyfile, digest_file)
    sk = _load_ecdsa_signing_key(keyfile)
    private_bytes = get_ecdsa_signing_key_raw_bytes(sk)
    result = hashlib.sha256(private_bytes).digest()
    if keylen == 192:
        result = result[0:24]
    digest_file.write(result)
    print(
        "SHA-256 digest of private key %s%s written to %s"
        % (
            keyfile.name,
            "" if keylen == 256 else " (truncated to 192 bits)",
            digest_file.name,
        )
    )


# flash encryption key tweaking pattern: the nth bit of the key is
# flipped if the kth bit in the flash offset is set, where mapping
# from n to k is provided by this list of 'n' bit offsets (range k)
# fmt: off
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
# fmt: on


def _flash_encryption_tweak_range_bits(flash_crypt_config: int = 0xF) -> int:
    """Return bits (in reverse order) that the "key tweak" applies to,
    as determined by the FLASH_CRYPT_CONFIG 4 bit efuse value.
    """
    tweak_range = 0
    if (flash_crypt_config & 1) != 0:
        tweak_range |= (
            0xFFFFFFFFFFFFFFFFE00000000000000000000000000000000000000000000000
        )
    if (flash_crypt_config & 2) != 0:
        tweak_range |= (
            0x00000000000000001FFFFFFFFFFFFFFFF0000000000000000000000000000000
        )
    if (flash_crypt_config & 4) != 0:
        tweak_range |= (
            0x000000000000000000000000000000000FFFFFFFFFFFFFFFE000000000000000
        )
    if (flash_crypt_config & 8) != 0:
        tweak_range |= (
            0x0000000000000000000000000000000000000000000000001FFFFFFFFFFFFFFF
        )
    return tweak_range


# Forward bit order masks
mul1 = 0x0000200004000080000004000080001000000200004000080000040000800010
mul2 = 0x0000000000000000200000000000000010000000000000002000000000000001

mul1_mask = 0xFFFFFFFFFFFFFF801FFFFFFFFFFFFFF00FFFFFFFFFFFFFF81FFFFFFFFFFFFFF0
mul2_mask = 0x000000000000007FE00000000000000FF000000000000007E00000000000000F


def _flash_encryption_tweak_key(key: int, offset: int, tweak_range: int) -> bytes:
    """Apply XOR "tweak" values to the key, derived from flash offset
    'offset'. This matches the ESP32 hardware flash encryption.

    tweak_range is a list of bit indexes to apply the tweak to, as
    generated by _flash_encryption_tweak_range() from the
    FLASH_CRYPT_CONFIG efuse value.

    Return tweaked key
    """
    addr = offset >> 5
    key ^= ((mul1 * addr) | ((mul2 * addr) & mul2_mask)) & tweak_range
    return int.to_bytes(key, length=32, byteorder="big", signed=False)


def _flash_encryption_operation_esp32(
    output_file: IO,
    input_file: IO,
    flash_address: int,
    keyfile: IO,
    flash_crypt_conf: int,
    do_decrypt: bool,
):
    """
    Perform flash encryption or decryption operation for ESP32.

    This function handles the encryption or decryption of flash data for ESP32 chip.
    It reads data from the input file, processes it in 16-byte blocks, and writes the
    processed data to the output file. The function ensures that the key length is
    either 192 or 256 bits, as required by the ESP32 chip. It also checks that the flash
    address is a multiple of 16.

    Note: This function is specific to the ESP32 chip. For other chips, use the
    --aes_xts flag to call the correct function.
    """
    key = _load_hardware_key(keyfile, True, aes_xts=False)

    if flash_address % 16 != 0:
        raise esptool.FatalError(
            "Starting flash address 0x%x must be a multiple of 16" % flash_address
        )

    if flash_crypt_conf == 0:
        print("WARNING: Setting FLASH_CRYPT_CONF to zero is not recommended")

    tweak_range = _flash_encryption_tweak_range_bits(flash_crypt_conf)
    key = int.from_bytes(key, byteorder="big", signed=False)

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
            print(
                "Note: Padding with %d bytes of random data "
                "(encrypted data must be multiple of 16 bytes long)" % pad
            )

        if block_offs % 32 == 0 or cipher is None:
            # each bit of the flash encryption key is XORed with tweak bits
            # derived from the offset of 32 byte block of flash
            block_key = _flash_encryption_tweak_key(key, block_offs, tweak_range)

            if cipher is None:  # first pass
                cipher = Cipher(algorithms.AES(block_key), modes.ECB(), backend=backend)

                # note AES is used inverted for flash encryption, so
                # "decrypting" flash uses AES encrypt algorithm and vice
                # versa. (This does not weaken AES.)
                actor = cipher.encryptor() if do_decrypt else cipher.decryptor()
            else:
                # performance hack: changing the key using pyca-cryptography API
                # requires recreating'actor'.
                # With openssl backend, this re-initializes the openssl cipher context.
                # To save some time, manually call EVP_CipherInit_ex() in the openssl
                # backend to update the key.
                # If it fails, fall back to recreating the entire context via public API
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
                    # backend is not an openssl backend, or implementation has changed:
                    # fall back to the slow safe version
                    cipher.algorithm.key = block_key
                    actor = cipher.encryptor() if do_decrypt else cipher.decryptor()

        block = block[::-1]  # reverse input block byte order
        block = actor.update(block)

        output_file.write(block[::-1])  # reverse output block byte order
        block_offs += 16


def _flash_encryption_operation_aes_xts(
    output_file: IO, input_file: IO, flash_address: int, keyfile: IO, do_decrypt: bool
):
    """
    Apply the AES-XTS algorithm with the hardware addressing scheme used by Espressif

    key = AES-XTS key (32 or 64 bytes)
    flash_address = address in flash to encrypt at. Must be multiple of 16 bytes.
    indata = Data to encrypt/decrypt. Must be multiple of 16 bytes.
    encrypt = True to Encrypt indata, False to decrypt indata.

    Returns a bitstring of the ciphertext or plaintext result.
    """

    backend = default_backend()
    key = _load_hardware_key(keyfile, True, aes_xts=True)
    indata = input_file.read()

    if flash_address % 16 != 0:
        raise esptool.FatalError(
            "Starting flash address 0x%x must be a multiple of 16" % flash_address
        )

    if len(indata) % 16 != 0:
        raise esptool.FatalError(
            "Input data length (%d) must be a multiple of 16" % len(indata)
        )

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

    output_list = []
    for inblock in inblocks:  # for each block
        tweak = struct.pack("<I", (flash_address & ~0x7F)) + (b"\x00" * 12)
        flash_address += 0x80  # for next block

        if len(tweak) != 16:
            raise esptool.FatalError(
                "Length of tweak must be 16, was {}".format(len(tweak))
            )

        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak), backend=backend)
        encryptor = cipher.decryptor() if do_decrypt else cipher.encryptor()

        inblock = inblock[::-1]  # reverse input
        outblock = encryptor.update(inblock)  # standard algo
        output_list.append(outblock[::-1])  # reverse output

    output = b"".join(output_list)

    # undo any padding we applied to the input
    if pad_right != 0:
        output = output[:-pad_right]
    if pad_left != 0:
        output = output[pad_left:]

    # output length matches original input
    if len(output) != len(indata) - pad_left - pad_right:
        raise esptool.FatalError(
            "Length of input data ({}) should match the output data ({})".format(
                len(indata) - pad_left - pad_right, len(output)
            )
        )

    output_file.write(output)


def _split_blocks(text: bytes, block_len: int = 16):
    """Take bytes, split it into chunks of "block_len" each"""
    assert len(text) % block_len == 0
    pos = 0
    while pos < len(text):
        yield text[pos : pos + block_len]
        pos = pos + block_len


def decrypt_flash_data(
    keyfile: IO,
    output: IO,
    address: int,
    flash_crypt_conf: int,
    aes_xts: bool,
    encrypted_file: IO,
):
    _check_output_is_not_input(keyfile, output)
    _check_output_is_not_input(encrypted_file, output)
    if aes_xts:
        return _flash_encryption_operation_aes_xts(
            output, encrypted_file, address, keyfile, True
        )
    else:
        return _flash_encryption_operation_esp32(
            output,
            encrypted_file,
            address,
            keyfile,
            flash_crypt_conf,
            True,
        )


def encrypt_flash_data(
    keyfile: IO,
    output: IO,
    address: int,
    flash_crypt_conf: int,
    aes_xts: bool,
    plaintext_file: IO,
):
    _check_output_is_not_input(keyfile, output)
    _check_output_is_not_input(plaintext_file, output)
    if aes_xts:
        return _flash_encryption_operation_aes_xts(
            output, plaintext_file, address, keyfile, False
        )
    else:
        return _flash_encryption_operation_esp32(
            output,
            plaintext_file,
            address,
            keyfile,
            flash_crypt_conf,
            False,
        )


def _samefile(p1, p2):
    return os.path.normcase(os.path.normpath(p1)) == os.path.normcase(
        os.path.normpath(p2)
    )


def _check_output_is_not_input(
    input_file: IO | str | None, output_file: IO | str | None
):
    i = getattr(input_file, "name", input_file)
    o = getattr(output_file, "name", output_file)
    # i & o should be string containing the path to files if espsecure
    # was invoked from command line
    # i & o still can be something else when espsecure was imported
    # and the functions used directly (e.g. io.BytesIO())
    check_f = _samefile if isinstance(i, str) and isinstance(o, str) else operator.eq
    if check_f(i, o):
        raise esptool.FatalError(
            f'The input "{i}" and output "{o}" should not be the same!'
        )


class Group(esptool.cli_util.Group):
    DEPRECATED_OPTIONS = {
        "--aes_xts": "--aes-xts",
        "--flash_crypt_conf": "--flash-crypt-conf",
        "--append_signatures": "--append-signatures",
    }


@click.group(
    cls=Group,
    no_args_is_help=True,
    context_settings=dict(help_option_names=["-h", "--help"], max_content_width=120),
    help=f"espsecure.py v{esptool.__version__} - ESP32 Secure Boot & Flash Encryption "
    "tool",
)
def cli():
    print(f"espsecure.py v{esptool.__version__}")


@cli.command("digest-secure-bootloader")
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    required=True,
    help="256 bit key for secure boot digest.",
)
@click.option(
    "--output", "-o", type=click.Path(), help="Output file for signed digest image."
)
@click.option(
    "--iv",
    type=click.File("rb"),
    help="128 byte IV file. Supply a file for testing purposes only, if not supplied an"
    " IV will be randomly generated.",
)
@click.argument("image", type=click.File("rb"))
def digest_secure_bootloader_cli(keyfile, output, iv, image):
    """Take a bootloader binary image and a secure boot key, and output a combined
    digest+binary suitable for flashing along with the precalculated secure boot key."""
    digest_secure_bootloader(keyfile, output, iv, image)


@cli.command("generate-signing-key")
@click.option(
    "--version",
    "-v",
    type=click.Choice(["1", "2"]),
    default="1",
    help="Version of the secure boot signing scheme to use.",
)
@click.option(
    "--scheme",
    "-s",
    type=click.Choice(["rsa3072", "ecdsa192", "ecdsa256", "ecdsa384"]),
    help="Scheme of secure boot signing.",
    required=False,
)
@click.argument("keyfile", type=click.Path())
def generate_signing_key_cli(version, scheme, keyfile):
    """Generate a private key for signing secure boot images as per the secure boot
    version."""
    generate_signing_key(version, scheme, keyfile)


@cli.command("sign-data")
@click.option(
    "--version",
    "-v",
    type=click.Choice(["1", "2"]),
    required=True,
    help="Version of the secure boot signing scheme to use.",
)
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    multiple=True,
    help="Private key file for signing. Key is in PEM format.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for signed digest image. Default is to sign the input file.",
)
@click.option(
    "--append-signatures",
    "-a",
    is_flag=True,
    help="Append signature block(s) to already signed image. Not valid for ESP32 and "
    "ESP32-C2.",
)
@click.option(
    "--hsm",
    is_flag=True,
    help="Use an external Hardware Security Module to generate signature using PKCS#11 "
    "interface.",
)
@click.option(
    "--hsm-config",
    type=click.File("r"),
    default=None,
    help="Config file for the external Hardware Security Module to be used to generate "
    "signature.",
)
@click.option(
    "--pub-key",
    type=click.File("rb"),
    multiple=True,
    help="Public key files corresponding to the private key used to generate the "
    "pre-calculated signatures. Keys should be in PEM format.",
)
@click.option(
    "--signature",
    type=click.File("rb"),
    multiple=True,
    default=None,
    help="Pre-calculated signatures. Signatures generated using external private keys "
    "e.g. keys stored in HSM.",
)
@click.argument("datafile", type=click.File("rb"))
def sign_data_cli(
    version,
    keyfile,
    output,
    append_signatures,
    hsm,
    hsm_config,
    pub_key,
    signature,
    datafile,
):
    """Sign a data file for use with secure boot."""
    sign_data(
        version,
        keyfile,
        output,
        append_signatures,
        hsm,
        hsm_config,
        pub_key,
        signature,
        datafile,
    )


@cli.command("verify-signature")
@click.option(
    "--version",
    "-v",
    type=click.Choice(["1", "2"]),
    required=True,
    help="Version of the secure boot scheme to use.",
)
@click.option(
    "--hsm",
    is_flag=True,
    help="Use an external Hardware Security Module to verify signature using PKCS#11 "
    "interface.",
)
@click.option(
    "--hsm-config",
    default=None,
    type=click.File("r"),
    help="Config file for the external Hardware Security Module to be used to verify "
    "signature.",
)
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    help="Public key file for verification. Can be private or public key in PEM format",
)
@click.argument("datafile", type=click.File("rb"))
def verify_signature_cli(version, hsm, hsm_config, keyfile, datafile):
    """Verify a data file previously signed by "sign_data", using the public key."""
    verify_signature(version, hsm, hsm_config, keyfile, datafile)


@cli.command("extract-public-key")
@click.option(
    "--version",
    "-v",
    type=click.Choice(["1", "2"]),
    default="1",
    help="Version of the secure boot signing scheme to use.",
)
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    required=True,
    help="Private key file (PEM format) to extract the public verification key from.",
)
@click.argument("public-keyfile", type=click.File("wb", lazy=True))
def extract_public_key_cli(version, keyfile, public_keyfile):
    """Extract the public verification key for signatures, save it as a raw binary
    file"""
    extract_public_key(version, keyfile, public_keyfile)


@cli.command("digest-rsa-public-key", deprecated=True)
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    required=True,
    help="Public key file for verification. Can be private or public key in PEM format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    required=True,
    help="Output file for the digest.",
)
def digest_rsa_public_key(keyfile, output):
    """Generate an SHA-256 digest of the RSA public key."""
    digest_sbv2_public_key(keyfile, output)


@cli.command("digest-sbv2-public-key")
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    required=True,
    help="Public key file for verification. Can be private or public key in PEM format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    required=True,
    help="Output file for the digest.",
)
def digest_sbv2_public_key_cli(keyfile, output):
    """Generate an SHA-256 digest of the public key."""
    digest_sbv2_public_key(keyfile, output)


@cli.command("signature-info-v2")
@click.argument("datafile", type=click.File("rb"))
def signature_info_v2_cli(datafile):
    """Reads the signature block and provides the signature block information."""
    signature_info_v2(datafile)


@cli.command("digest-private-key")
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    required=True,
    help="Private key file (PEM format) to generate a digest from.",
)
@click.option(
    "--keylen",
    "-l",
    type=int,
    default=256,
    help="Length of private key digest file to generate (in bits). 3/4 Coding Scheme "
    "requires 192 bit key.",
)
@click.argument("digest-file", type=click.File("wb", lazy=True))
def digest_private_key_cli(keyfile, keylen, digest_file):
    """Generate a SHA-256 digest of the private signing key."""
    digest_private_key(keyfile, keylen, digest_file)


@cli.command("generate-flash-encryption-key")
@click.option(
    "--keylen",
    "-l",
    type=int,
    default=256,
    help="Length of private key digest file to generate (in bits). 3/4 Coding Scheme "
    "requires 192 bit key.",
)
@click.argument("key-file", type=click.File("wb", lazy=True))
def generate_flash_encryption_key(keylen: int, key_file: IO):
    """Generate a development-use flash encryption key with random data."""
    print(f"Writing {keylen} random bits to key file {key_file.name}")
    key_file.write(os.urandom(keylen // 8))


@cli.command("decrypt-flash-data")
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    required=True,
    help="File with flash encryption key",
)
@click.option(
    "--output",
    "-o",
    type=click.File("wb", lazy=True),
    required=True,
    help="Output file for plaintext data.",
)
@click.option(
    "--address",
    "-a",
    type=esptool.cli_util.AnyIntType(),
    required=True,
    help="Address offset in flash that file was read from.",
)
@click.option(
    "--flash-crypt-conf",
    type=esptool.cli_util.AnyIntType(),
    default=0xF,
    help="Override FLASH_CRYPT_CONF efuse value (default is 0XF) (applicable only for "
    "ESP32).",
)
@click.option(
    "--aes-xts",
    "-x",
    is_flag=True,
    help="Decrypt data using AES-XTS (not applicable for ESP32)",
)
@click.argument("encrypted-file", type=click.File("rb"))
def decrypt_flash_data_cli(
    keyfile, output, address, flash_crypt_conf, aes_xts, encrypted_file
):
    """Decrypt some data read from encrypted flash (using known key)."""
    decrypt_flash_data(
        keyfile, output, address, flash_crypt_conf, aes_xts, encrypted_file
    )


@cli.command("encrypt-flash-data")
@click.option(
    "--keyfile",
    "-k",
    type=click.File("rb"),
    required=True,
    help="File with flash encryption key",
)
@click.option(
    "--output",
    "-o",
    type=click.File("wb", lazy=True),
    required=True,
    help="Output file for encrypted data.",
)
@click.option(
    "--address",
    "-a",
    type=esptool.cli_util.AnyIntType(),
    help="Address offset in flash where file will be flashed.",
    required=True,
)
@click.option(
    "--flash-crypt-conf",
    type=esptool.cli_util.AnyIntType(),
    default=0xF,
    help="Override FLASH_CRYPT_CONF efuse value (default is 0XF) (applicable only for "
    "ESP32)",
)
@click.option(
    "--aes-xts",
    "-x",
    is_flag=True,
    help="Encrypt data using AES-XTS (not applicable for ESP32)",
)
@click.argument("plaintext-file", type=click.File("rb"))
def encrypt_flash_data_cli(
    keyfile, output, address, flash_crypt_conf, aes_xts, plaintext_file
):
    """Encrypt some data suitable for encrypted flash (using known key)."""
    encrypt_flash_data(
        keyfile, output, address, flash_crypt_conf, aes_xts, plaintext_file
    )


def main(argv: list[str] | None = None):
    """
    Main function for espsecure

    argv - Optional override for default arguments parsing
    (that uses sys.argv), can be a list of custom arguments as strings.
    Arguments and their values need to be added as individual items to the list
    e.g. "--port /dev/ttyUSB1" thus becomes ['--port', '/dev/ttyUSB1'].
    """
    cli(args=argv)


def _main():
    try:
        main()
    except esptool.FatalError as e:
        log.error(f"\nA fatal error occurred: {e}")
        sys.exit(2)
    except ValueError as e:
        try:
            if [arg for arg in e.args if "Could not deserialize key data." in arg]:
                log.error(
                    "Note: This error originates from the cryptography module. "
                    "It is likely not a problem with espsecure, "
                    "please make sure you are using a compatible OpenSSL backend."
                )
        finally:
            raise
    except KeyboardInterrupt:
        log.error("KeyboardInterrupt: Run cancelled by user.")
        sys.exit(2)


if __name__ == "__main__":
    _main()
