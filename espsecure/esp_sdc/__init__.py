# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later
# Secure Debug Controller Certificate Generation
import binascii
import configparser
import hashlib
import json
import os
import secrets
import struct
import zlib
from typing import IO

from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils

from esptool import FatalError
from esptool.logger import log

# SDC Certificate Generation Constants
USC_DATA_SIZE = 256  # USC (Unlock Security Configuration) data size in bytes
PUBLIC_KEY_SIZE = 64  # ECDSA P-256 public key size (32 bytes x + 32 bytes y)
SIGNATURE_SIZE = 32  # ECDSA signature component size (r or s)
CERT_HASH_SIZE = 32  # SHA-256 hash size
SDC_CERT_HEADER_SIZE = 20  # Certificate header size
SDC_CERT_BODY_SIZE = (
    USC_DATA_SIZE + PUBLIC_KEY_SIZE + SIGNATURE_SIZE + SIGNATURE_SIZE + CERT_HASH_SIZE
)  # 256 + 64 + 32 + 32 + 32 = 416 bytes
SDC_CERT_SIZE = SDC_CERT_HEADER_SIZE + SDC_CERT_BODY_SIZE  # Total: 436 bytes

# Certificate Header Constants
SDC_CERT_MAGIC = 0x524D4143  # "RMAC" magic number (little-endian: "CAMR")
SDC_CERT_VERSION_1 = 0x01  # Certificate format version 1

# SDC USC Configuration Bits (stored in first 4 bytes of USC data)
USC_BIT_JTAG = 0  # Bit 0: Enable JTAG debugging interface
USC_BIT_DOWNLOAD_REUSE = 1  # Bit 1: Enable download mode reuse
USC_BIT_FORCE_SPI_BOOT = 2  # Bit 2: Force SPI boot mode


class SDCCertificateGenerator:
    """SDC Certificate Generator using big-endian format"""

    def __init__(self) -> None:
        """Initialize generator with big-endian format"""
        self.verbose = False

    def generate_usc_data(
        self,
        enable_jtag: bool = False,
        enable_download_reuse: bool = False,
        enable_force_spi_boot: bool = False,
    ) -> bytes:
        """Generate USC data with configuration options"""
        # Create first word based on configuration bits
        first_word = 0
        if enable_jtag:
            first_word |= 1 << USC_BIT_JTAG
        if enable_download_reuse:
            first_word |= 1 << USC_BIT_DOWNLOAD_REUSE
        if enable_force_spi_boot:
            first_word |= 1 << USC_BIT_FORCE_SPI_BOOT

        # Convert first word to bytes (4 bytes)
        first_word_bytes = first_word.to_bytes(4, "big")

        # Fill remaining bytes with zeros (252 bytes for 256-byte USC)
        zero_bytes = bytes(USC_DATA_SIZE - 4)

        # Combine first word and zero padding
        usc_data = first_word_bytes + zero_bytes

        if self.verbose:
            log.print("USC data generated successfully")
            log.print(f"  JTAG: {'Enabled' if enable_jtag else 'Disabled'}")
            download_reuse_status = "Enabled" if enable_download_reuse else "Disabled"
            log.print(f"  Download reuse: {download_reuse_status}")
            force_spi_boot_status = "Enabled" if enable_force_spi_boot else "Disabled"
            log.print(f"  Force SPI boot: {force_spi_boot_status}")

        return usc_data

    def generate_public_key(
        self, private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    ) -> bytes:
        """Generate public key from private key with validation"""
        if isinstance(private_key, rsa.RSAPrivateKey):
            raise FatalError("SDC certificates only support ECDSA keys, not RSA keys.")

        public_key = private_key.public_key()

        # Extract and validate public key
        public_key_bytes = _get_sdc_public_key_bytes(public_key)

        if self.verbose:
            log.print("Public key extracted successfully")

        return public_key_bytes

    def create_message(self, usc_data: bytes, chip_info: bytes) -> bytes:
        """Create message = {USC, CHIP_INFO} with validation"""
        if not usc_data:
            raise FatalError("USC data is empty")

        if not chip_info:
            raise FatalError("Chip info is empty")

        message = usc_data + chip_info

        if self.verbose:
            log.print("Certificate message prepared successfully")

        return message

    def generate_signature(
        self,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        message: bytes,
    ) -> tuple[int, int]:
        """Generate ECDSA signature {r, s} with comprehensive validation"""
        if not message:
            raise FatalError("Message is empty")

        if isinstance(private_key, rsa.RSAPrivateKey):
            raise FatalError(
                "SDC certificates only support ECDSA signatures, not RSA signatures."
            )

        # Direct ECDSA signing
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

        # Extract r, s from signature
        r, s = utils.decode_dss_signature(signature)

        # Validate r and s are non-zero
        if r == 0 or s == 0:
            raise FatalError("Invalid signature")

        if self.verbose:
            log.print("ECDSA signature generated successfully")

        return r, s

    def calculate_cert_hash(
        self, usc_data: bytes, public_key: bytes, r: int, s: int
    ) -> bytes:
        """Calculate certificate hash using SHA-256 with validation"""
        if not usc_data:
            raise FatalError("USC data is empty")

        if not public_key or len(public_key) != PUBLIC_KEY_SIZE:
            raise FatalError(
                f"Invalid public key length: {len(public_key) if public_key else 0}"
            )

        if r <= 0 or s <= 0:
            raise FatalError("Invalid signature values for hash calculation")

        # Create certificate plain format (all data except cert hash)
        r_bytes = r.to_bytes(SIGNATURE_SIZE, "big")
        s_bytes = s.to_bytes(SIGNATURE_SIZE, "big")
        cert_plain = usc_data + public_key + r_bytes + s_bytes

        # Calculate SHA-256 hash
        cert_hash = hashlib.sha256(cert_plain).digest()

        if self.verbose:
            log.print("Certificate integrity hash calculated successfully")

        return cert_hash

    def calculate_public_key_hash(self, public_key: bytes) -> bytes:
        """Calculate SHA-256 hash of the public key"""
        if not public_key or len(public_key) != PUBLIC_KEY_SIZE:
            raise FatalError(
                f"Invalid public key length: {len(public_key) if public_key else 0}"
            )

        # Calculate SHA-256 hash of the public key
        pub_key_hash = hashlib.sha256(public_key).digest()

        if self.verbose:
            log.print("Public key hash calculated successfully")

        return pub_key_hash

    def create_certificate_header(self, cert_body: bytes) -> bytes:
        """Create SDC certificate header with magic, version, lengths, and CRC32"""
        if len(cert_body) != SDC_CERT_BODY_SIZE:
            raise FatalError(
                f"Invalid certificate body length: {len(cert_body)}, "
                f"expected {SDC_CERT_BODY_SIZE}"
            )

        # Calculate CRC32 of certificate body
        # (initial value UINT32_MAX, same as ROM crc32_le)
        crc32 = zlib.crc32(cert_body, 0xFFFFFFFF) & 0xFFFFFFFF

        # Header format: magic(4) + version(1) + reserved(1) + usc_len(2)
        # + length(2) + reserved(2) + crc32(4) + reserved(4) = 20 bytes
        return struct.pack(
            "<IBBHHHII",
            SDC_CERT_MAGIC,  # magic (4 bytes)
            SDC_CERT_VERSION_1,  # version (1 byte)
            0,  # reserved_1 (1 byte)
            USC_DATA_SIZE,  # usc_len (2 bytes)
            SDC_CERT_SIZE,  # length (2 bytes)
            0,  # reserved_2 (2 bytes)
            crc32,  # crc32 (4 bytes)
            0,  # reserved_3 (4 bytes)
        )

    def create_sdc_certificate(
        self, usc_data: bytes, public_key: bytes, r: int, s: int, cert_hash: bytes
    ) -> bytes:
        """Create SDC certificate content with header and validation"""
        if not usc_data:
            raise FatalError("USC data is empty")

        if len(usc_data) != USC_DATA_SIZE:
            raise FatalError(
                f"Invalid USC data length: {len(usc_data)}, expected {USC_DATA_SIZE}"
            )

        if not public_key or len(public_key) != PUBLIC_KEY_SIZE:
            raise FatalError(
                f"Invalid public key length: {len(public_key) if public_key else 0}"
            )

        if r <= 0 or s <= 0:
            raise FatalError("Invalid signature values")

        if not cert_hash or len(cert_hash) != CERT_HASH_SIZE:
            raise FatalError(
                f"Invalid certificate hash length: {len(cert_hash) if cert_hash else 0}"
            )

        # Create certificate body: USC data, public key,
        # signature r, signature s, cert_hash
        r_bytes = r.to_bytes(SIGNATURE_SIZE, "big")
        s_bytes = s.to_bytes(SIGNATURE_SIZE, "big")
        cert_body = usc_data + public_key + r_bytes + s_bytes + cert_hash

        # Create certificate header
        cert_header = self.create_certificate_header(cert_body)

        # Combine header + body
        sdc_cert = cert_header + cert_body

        return sdc_cert


# SDC Utility Functions


def _get_sdc_public_key_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Extract 64-byte (32x + 32y) public key for SDC"""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise FatalError("SDC certificates only support ECDSA keys")

    if not isinstance(public_key.curve, ec.SECP256R1):
        raise FatalError(
            f"Unsupported curve: {public_key.curve.name}. "
            "Only SECP256R1 (P-256) is supported"
        )

    public_numbers = public_key.public_numbers()
    x_bytes: bytes = public_numbers.x.to_bytes(32, "big")
    y_bytes: bytes = public_numbers.y.to_bytes(32, "big")
    return x_bytes + y_bytes


def _normalize_hex_string(hex_str: str) -> str:
    """Normalize hex string by removing whitespace and separators,
    converting to uppercase"""
    return (
        hex_str.replace(" ", "")
        .replace("\n", "")
        .replace("\t", "")
        .replace(":", "")
        .replace("-", "")
        .upper()
    )


def _parse_input_data(
    input_str: str, expected_len: int, param_name: str, verbose: bool = False
) -> bytes:
    """Parse input data - can be hex string, binary file path, or hex file path

    Supports:
    - Hex strings directly (e.g., "3A7FB2C1...")
    - Binary files (.bin)
    - Hex text files (.hex containing hex strings)

    Args:
        input_str: Input as hex string or file path
        expected_len: Expected length in bytes
        param_name: Name of parameter for error messages
        verbose: Enable verbose output

    Returns:
        bytes: Parsed data as bytes
    """
    # Normalize input string to lowercase for case-insensitive extension checks
    input_lower = input_str.lower()

    # Check if it looks like a file path
    is_file_path = (
        os.path.sep in input_str
        or (os.path.altsep and os.path.altsep in input_str)
        or input_lower.endswith(".bin")
        or input_lower.endswith(".hex")
    )

    if is_file_path and os.path.exists(input_str):
        # Try as file path
        if input_lower.endswith(".bin"):
            # Binary file
            if verbose:
                log.print(f"Reading {param_name} from binary file: {input_str}")
            with open(input_str, "rb") as f:
                data = f.read()
            if len(data) != expected_len:
                raise FatalError(
                    f"Invalid {param_name} file size: '{input_str}' "
                    f"contains {len(data)} bytes, "
                    f"expected {expected_len} bytes"
                )
            return data
        elif input_lower.endswith(".hex"):
            # Hex text file (.hex)
            if verbose:
                log.print(f"Reading {param_name} from hex file: {input_str}")
            with open(input_str) as f:
                hex_content = f.read().strip()
            # Normalize hex string (remove separators, convert to uppercase)
            hex_content = _normalize_hex_string(hex_content)

            if len(hex_content) != expected_len * 2:
                raise FatalError(
                    f"{param_name} hex file '{input_str}' contains "
                    f"{len(hex_content)} hex characters, "
                    f"expected {expected_len * 2} hex characters"
                )
            try:
                return bytes.fromhex(hex_content)
            except ValueError:
                raise FatalError(
                    f"Invalid hex format in file '{input_str}': "
                    f"{param_name} must contain valid hex characters"
                )
        else:
            # File exists but not .bin or .hex, treat as hex string
            if verbose:
                log.print(
                    f"File '{input_str}' exists but is not .bin or .hex, "
                    "treating as hex string"
                )
            hex_str = _normalize_hex_string(input_str)
            if len(hex_str) != expected_len * 2:
                raise FatalError(
                    f"{param_name} hex string has {len(hex_str)} hex characters, "
                    f"expected {expected_len * 2} hex characters"
                )
            try:
                return bytes.fromhex(hex_str)
            except ValueError:
                raise FatalError(
                    f"Invalid {param_name} hex format: "
                    "must contain valid hex characters"
                )
    else:
        # Treat as hex string
        if verbose:
            log.print(f"Parsing {param_name} from hex string")
        # Normalize hex string (remove separators, convert to uppercase)
        hex_str = _normalize_hex_string(input_str)

        if len(hex_str) != expected_len * 2:
            raise FatalError(
                f"{param_name} hex string has {len(hex_str)} hex characters, "
                f"expected {expected_len * 2} hex characters"
            )
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            raise FatalError(
                f"Invalid {param_name} hex format: must contain valid hex characters"
            )


def _calculate_chip_info(
    mac: str,
    sdc_session_counter: int | bytes,
    nonce: str | bytes,
    verbose: bool = False,
) -> bytes:
    """Calculate chip info using SHA256(SHA256(MAC) + nonce + sdc_session_counter)

    First generates UNIQ_id from MAC address using SHA256(MAC), then calculates
    chip info using SHA256(UNIQ_id + nonce + sdc_session_counter).

    Args:
        mac: MAC address as hex string (6 bytes, 12 hex chars) or file path (.bin/.hex).
             Supports formats: "00:00:00:00:00:00", "00-00-00-00-00-00",
             "000000000000", or binary file.
        sdc_session_counter: SDC session counter as integer (0-255, default: 0) or
            bytes (1 byte). Must match the value burned in the device eFuse.
        nonce: Nonce as hex string (32 bytes) or file path (.bin/.hex)
        verbose: Enable verbose output

    Returns:
        bytes: 32-byte chip info (SHA-256 digest)
    """
    # Validate inputs
    if not mac:
        raise FatalError("MAC address is required")
    if not nonce:
        raise FatalError("Nonce is required")

    # Parse MAC - must be 6 bytes (standard MAC address length)
    if isinstance(mac, bytes):
        mac_bytes = mac
        if len(mac_bytes) != 6:
            raise FatalError(
                "Invalid MAC address length: expected 6 bytes, "
                f"got {len(mac_bytes)} bytes."
            )
    else:
        mac_bytes = _parse_input_data(mac, 6, "MAC", verbose)

    # Generate unique device identifier from MAC address using SHA256.
    # The MAC is supplied in the human-readable order shown by `espefuse summary`
    # (e.g. "30:ed:a0:ed:78:9c"), but the device ROM derives UNIQ_id from the MAC
    # in eFuse byte order, which is the reverse. Reverse the bytes here so the
    # offline computation matches the device: SHA256(reverse(MAC)) -> UNIQ_id.
    if verbose:
        log.print("Deriving device unique identifier from MAC address")
    sha256_mac = hashlib.sha256()
    sha256_mac.update(mac_bytes[::-1])
    uniq_id = sha256_mac.digest()  # 32-byte unique identifier

    # Parse sdc_session_counter - must be 1 byte
    if isinstance(sdc_session_counter, bytes):
        session_counter_bytes = sdc_session_counter
        if len(session_counter_bytes) != 1:
            raise FatalError(
                "Invalid SDC session counter length: expected 1 byte, "
                f"got {len(session_counter_bytes)} bytes"
            )
    elif isinstance(sdc_session_counter, int):
        # Convert integer to 1-byte bytes
        if sdc_session_counter < 0 or sdc_session_counter > 255:
            raise FatalError(
                "Invalid SDC session counter value: expected 0-255, "
                f"got {sdc_session_counter}"
            )
        session_counter_bytes = sdc_session_counter.to_bytes(1, "big")
        if verbose:
            log.print(f"SDC session counter: {sdc_session_counter}")
    else:
        raise FatalError(
            "Invalid SDC session counter type: expected int or bytes, "
            f"got {type(sdc_session_counter).__name__}"
        )

    # Parse nonce - must be 32 bytes (nonce is always required)
    if isinstance(nonce, bytes):
        nonce_bytes = nonce
        if len(nonce_bytes) != 32:
            raise FatalError(f"Nonce must be 32 bytes, got {len(nonce_bytes)} bytes")
    else:
        nonce_bytes = _parse_input_data(nonce, 32, "nonce", verbose)

    # Calculate chip info: SHA256(unique_id + nonce + sdc_session_counter)
    if verbose:
        log.print("Calculating chip info")
    sha256 = hashlib.sha256()
    sha256.update(uniq_id)
    sha256.update(nonce_bytes)
    sha256.update(session_counter_bytes)

    # Calculate SHA256 hash
    return sha256.digest()


def _load_usc_config_from_json(json_file: str, verbose: bool = False) -> dict:
    """Load USC configuration from JSON file

    Expected JSON format:
    {
        "config_flags": {
            "enable_jtag": true/false,
            "enable_download_reuse": true/false,
            "enable_force_spi_boot": true/false
        },
        "pma_config": { ... },  # Future use
        "pmp_config": { ... }   # Future use
    }
    """
    try:
        with open(json_file) as f:
            config = json.load(f)
    except FileNotFoundError:
        raise FatalError(f"USC JSON file not found: {json_file}")
    except json.JSONDecodeError as e:
        raise FatalError(f"Invalid JSON in USC config file: {e}")

    # Validate that config is a dictionary
    if not isinstance(config, dict):
        raise FatalError(
            f"USC JSON file must contain a JSON object, got {type(config).__name__}"
        )

    # Handle nested "config_flags" structure (preferred)
    if "config_flags" in config:
        config_flags = config["config_flags"]
        if not isinstance(config_flags, dict):
            raise FatalError(
                "'config_flags' must be a JSON object, "
                f"got {type(config_flags).__name__}"
            )
        active_config = config_flags
    else:
        # Fallback: assume flat structure for backward compatibility
        active_config = config

    # Validate boolean values if present
    for key in ["enable_jtag", "enable_download_reuse", "enable_force_spi_boot"]:
        if key in active_config and not isinstance(active_config[key], bool):
            raise FatalError(
                f"Invalid value for '{key}' in USC JSON: expected boolean, "
                f"got {type(active_config[key]).__name__}"
            )

    if verbose:
        log.print(f"Loaded USC configuration from {json_file}")
        log.print(f"Configuration: {active_config}")

    return active_config


def _generate_sdc_certificate_data(
    generator: SDCCertificateGenerator,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None,
    usc_data: bytes,
    chip_info: bytes,
    verbose: bool,
    hsm_config: configparser.SectionProxy | None = None,
    pub_key_file: IO | None = None,
) -> tuple[bytes, bytes, int, int, bytes, bytes]:
    """Generate all SDC certificate data components"""
    if hsm_config is not None:
        # Import HSM functions only when needed (requires optional pkcs11 dependency)
        from .. import extract_pubkey_from_hsm, generate_signature_using_hsm

        # HSM signing path
        if private_key is not None:
            raise FatalError("Cannot specify both private key and HSM config")

        # Extract public key from HSM
        if pub_key_file is None:
            try:
                pub_key_files = extract_pubkey_from_hsm(hsm_config)
                pub_key_file = pub_key_files[0]
            except Exception as e:
                raise FatalError(f"Failed to extract public key from HSM: {e}")

        # Load the public key and validate it's ECDSA P-256
        try:
            pub_key_data = pub_key_file.read()
            pub_key_file.seek(0)  # Reset for potential reuse
            public_key_obj = serialization.load_pem_public_key(
                pub_key_data, backend=default_backend()
            )
        except Exception as e:
            raise FatalError(f"Failed to load public key from HSM: {e}")

        # Extract and validate public key
        public_key = _get_sdc_public_key_bytes(public_key_obj)

        # Calculate public key hash
        pub_key_hash = generator.calculate_public_key_hash(public_key)

        # Create message for signing
        message = generator.create_message(usc_data, chip_info)

        # Sign using HSM
        try:
            signature_files = generate_signature_using_hsm(hsm_config, message)
            try:
                signature = signature_files[0].read()
            finally:
                for f in signature_files:
                    f.close()
        except Exception as e:
            raise FatalError(f"HSM signing failed: {e}")

        try:
            r, s = utils.decode_dss_signature(signature)
        except ValueError as e:
            raise FatalError(
                f"Failed to decode HSM signature: {e}. "
                f"Signature length: {len(signature)} bytes. "
                "Expected DER-encoded ECDSA signature."
            )

        # Verify signature can be verified with the public key
        try:
            der_signature = utils.encode_dss_signature(r, s)
            public_key_obj.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
            if verbose:
                log.print("Signature verified successfully with public key")
        except exceptions.InvalidSignature as e:
            raise FatalError(
                f"HSM signature verification failed: {e}. "
                "The signature from HSM cannot be verified with the "
                "extracted public key. Check that the HSM key pair is correct."
            )

        if verbose:
            log.print("ECDSA signature generated successfully using HSM")

        # Calculate certificate hash
        cert_hash = generator.calculate_cert_hash(usc_data, public_key, r, s)

        # Create SDC certificate
        sdc_cert = generator.create_sdc_certificate(
            usc_data, public_key, r, s, cert_hash
        )

        return public_key, pub_key_hash, r, s, cert_hash, sdc_cert
    else:
        # Regular private key signing path
        if private_key is None:
            raise FatalError("Private key is required when not using HSM")

        public_key = generator.generate_public_key(private_key)

        pub_key_hash = generator.calculate_public_key_hash(public_key)
        message = generator.create_message(usc_data, chip_info)

        r, s = generator.generate_signature(private_key, message)

        # Verify signature can be verified with the public key
        try:
            # Get public key object from private key for verification
            public_key_obj = private_key.public_key()
            der_signature = utils.encode_dss_signature(r, s)
            public_key_obj.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
            if verbose:
                log.print("Signature verified successfully with public key")
        except exceptions.InvalidSignature:
            raise FatalError(
                "Generated signature cannot be verified with the public key - "
                "signing may have failed"
            )

        cert_hash = generator.calculate_cert_hash(usc_data, public_key, r, s)
        sdc_cert = generator.create_sdc_certificate(
            usc_data, public_key, r, s, cert_hash
        )

        return public_key, pub_key_hash, r, s, cert_hash, sdc_cert


def generate_sdc_certificate(
    private_key_file: str | None = None,
    output_file: str = "sdc_cert.bin",
    usc: str | None = None,
    enable_jtag: bool = False,
    enable_download_reuse: bool = False,
    enable_force_spi_boot: bool = False,
    chip_info_file: str | None = None,
    mac: str | None = None,
    sdc_session_counter: int = 0,
    verbose: bool = False,
    hsm: bool = False,
    hsm_config_file: str | None = None,
    pub_key_file: str | None = None,
) -> None:
    """Generate SDC certificate using ECDSA signatures

    Args:
        private_key_file: Path to ECDSA private key file in PEM format
            (not required if using HSM)
        output_file: Output file for SDC certificate (default: sdc_cert.bin)
        usc: Optional JSON file containing USC configuration options
        enable_jtag: Enable JTAG access
        enable_download_reuse: Enable download reuse
        enable_force_spi_boot: Enable force SPI boot
        chip_info_file: Path to 64-byte chip_info file.
            If provided, mac and sdc_session_counter are not required.
        mac: MAC address as hex string (6 bytes, 12 hex chars) or file path (.bin/.hex).
             Supports formats: "00:00:00:00:00:00", "00-00-00-00-00-00",
             "000000000000", or binary file. Required if chip_info_file is not provided.
        sdc_session_counter: SDC session counter as integer (0-255, default: 0).
            Must match the value burned in the device eFuse.
        verbose: Enable verbose output
        hsm: Use Hardware Security Module for signing
        hsm_config_file: HSM configuration file (required if hsm=True)
        pub_key_file: Public key file (optional if hsm=True, will extract from HSM
            if not provided)
    """
    # Import here to avoid circular imports
    from .. import _load_private_key_unified

    # Load USC configuration from JSON if provided
    if usc:
        if verbose:
            log.print(f"Loading USC configuration from: {usc}")
        json_config = _load_usc_config_from_json(usc, verbose)
        # JSON config overrides command line options
        enable_jtag = json_config.get("enable_jtag", enable_jtag)
        enable_download_reuse = json_config.get(
            "enable_download_reuse", enable_download_reuse
        )
        enable_force_spi_boot = json_config.get(
            "enable_force_spi_boot", enable_force_spi_boot
        )

    # Handle chip_info and nonce based on input method
    if chip_info_file:
        # If chip_info_file is provided, read it directly
        if verbose:
            log.print(f"Reading chip_info from file: {chip_info_file}")

        if not os.path.exists(chip_info_file):
            raise FatalError(f"Chip info file not found: {chip_info_file}")

        with open(chip_info_file, "rb") as f:
            chip_info_data = f.read()

        # chip_info.bin must contain chip_info (32 bytes) + nonce (32 bytes) =
        # 64 bytes total
        if len(chip_info_data) != 64:
            raise FatalError(
                "Invalid chip_info file size: expected 64 bytes "
                "(32 bytes chip_info + 32 bytes nonce), "
                f"got {len(chip_info_data)} bytes."
            )
        # Extract chip_info (first 32 bytes) and nonce (last 32 bytes)
        chip_info = chip_info_data[:32]
        nonce_bytes = chip_info_data[32:]
        if verbose:
            log.print("Extracted chip_info and nonce from chip_info.bin file")
            log.print(f"  Chip info (32 bytes): {binascii.hexlify(chip_info).decode()}")
            log.print(f"  Nonce (32 bytes): {binascii.hexlify(nonce_bytes).decode()}")
    else:
        # If chip_info_file is not provided, calculate chip_info from MAC,
        # nonce, sdc_session_counter
        if not mac:
            raise FatalError(
                "MAC address is required when chip_info_file is not provided"
            )

        # Generate nonce automatically
        nonce_bytes = secrets.token_bytes(32)
        if verbose:
            log.print("Auto-generated 32-byte nonce")
            log.print(f"  Nonce (32 bytes): {binascii.hexlify(nonce_bytes).decode()}")

        # Calculate chip info (pass nonce as bytes to avoid re-parsing)
        chip_info = _calculate_chip_info(mac, sdc_session_counter, nonce_bytes, verbose)
        if verbose:
            log.print(f"  Chip info (32 bytes): {binascii.hexlify(chip_info).decode()}")

    # Initialize generator
    generator = SDCCertificateGenerator()
    generator.verbose = verbose

    # Generate USC data
    usc_data = generator.generate_usc_data(
        enable_jtag=enable_jtag,
        enable_download_reuse=enable_download_reuse,
        enable_force_spi_boot=enable_force_spi_boot,
    )

    # Handle HSM vs private key signing
    if hsm:
        # Import HSM module only when needed (requires optional pkcs11 dependency)
        from .. import esp_hsm_sign as hsm_sign

        if not hsm_config_file:
            raise FatalError("HSM config file is required when using HSM")

        # Load HSM config
        try:
            with open(hsm_config_file) as f:
                hsm_config = hsm_sign.read_hsm_config(f)
        except FileNotFoundError:
            raise FatalError(f"HSM config file not found: {hsm_config_file}")
        except (KeyError, configparser.Error) as e:
            raise FatalError(f"Invalid HSM config file format: {e}")

        # Handle public key file if provided
        pub_key_io: IO | None = None
        if pub_key_file:
            if not os.path.exists(pub_key_file):
                raise FatalError(f"Public key file not found: {pub_key_file}")
            pub_key_io = open(pub_key_file, "rb")

        try:
            # Generate certificate data using HSM
            public_key, pub_key_hash, r, s, cert_hash, sdc_cert = (
                _generate_sdc_certificate_data(
                    generator,
                    None,
                    usc_data,
                    chip_info,
                    verbose,
                    hsm_config,
                    pub_key_io,
                )
            )
        finally:
            if pub_key_io:
                pub_key_io.close()

    else:
        if not private_key_file:
            raise FatalError("Private key file is required when not using HSM")

        if not os.path.exists(private_key_file):
            raise FatalError(f"Private key file not found: {private_key_file}")

        # Read private key
        with open(private_key_file, "rb") as f:
            private_key = _load_private_key_unified(f.read(), key_type_hint="sdc")

        # Generate certificate data
        public_key, pub_key_hash, r, s, cert_hash, sdc_cert = (
            _generate_sdc_certificate_data(
                generator, private_key, usc_data, chip_info, verbose
            )
        )

    # Append nonce to certificate
    sdc_cert = sdc_cert + nonce_bytes

    # Write SDC certificate file
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "wb") as f:
        f.write(sdc_cert)

    # Print detailed results (verbose mode only)
    if verbose:
        log.print(f"SDC certificate written to {output_file}")
        log.print("\nSDC Certificate Details")
        log.print("=" * 60)
        log.print(f"Certificate size: {len(sdc_cert)} bytes")
        log.print(f"  - Certificate body: {len(sdc_cert) - 32} bytes")
        log.print(f"  - Nonce: {len(nonce_bytes)} bytes")
        log.print("\nUSC Configuration:")
        log.print(f"  - JTAG access: {'Enabled' if enable_jtag else 'Disabled'}")
        download_reuse_status = "Enabled" if enable_download_reuse else "Disabled"
        log.print(f"  - Download reuse: {download_reuse_status}")
        force_spi_boot_status = "Enabled" if enable_force_spi_boot else "Disabled"
        log.print(f"  - Force SPI boot: {force_spi_boot_status}")
        log.print("\nCryptographic Details:")
        log.print(f"  - Public key hash: {binascii.hexlify(pub_key_hash).decode()}")
        log.print(f"  - Certificate hash: {binascii.hexlify(cert_hash).decode()}")
        log.print("=" * 60)

    # Professional success message
    log.print(f'\nSDC certificate generated successfully: "{output_file}"')
    log.print(f"Certificate size: {len(sdc_cert)} bytes")

    # Summary of configuration (always shown, but concise)
    config_summary = []
    if enable_jtag:
        config_summary.append("JTAG")
    if enable_download_reuse:
        config_summary.append("Download Reuse")
    if enable_force_spi_boot:
        config_summary.append("Force SPI Boot")

    if config_summary:
        log.print(f"Enabled features: {', '.join(config_summary)}")
    else:
        log.print("No additional features enabled (default security configuration)")


def generate_sdc_public_key_digest(
    private_key_file: str | None = None,
    public_key_file: str | None = None,
    output_file: str | None = None,
    hsm: bool = False,
    hsm_config_file: str | None = None,
    verbose: bool = False,
) -> None:
    """Generate SDC public key digest for eFuse burning

    This function calculates the SHA-256 hash of the SDC public key and outputs
    the reversed digest that must be burned to the device eFuse.

    Args:
        private_key_file: Path to ECDSA private key file in PEM format
            (not required if using HSM or public_key_file)
        public_key_file: Path to ECDSA public key file in PEM format
            (not required if using HSM or private_key_file)
        output_file: Output file for SDC public key digest (required)
        hsm: Use Hardware Security Module for extracting public key
        hsm_config_file: HSM configuration file (required if hsm=True)
        verbose: Enable verbose output

    Raises:
        FatalError: If key loading fails or public key is invalid
    """
    # Import here to avoid circular imports
    from .. import _load_private_key_unified

    if not output_file:
        raise FatalError("Output file is required. Please specify --output/-o option.")

    # Determine source of public key
    if hsm:
        # Import HSM module only when needed (requires optional pkcs11 dependency)
        from ..esp_hsm_sign import (
            close_connection,
            establish_session,
            get_pubkey,
            read_hsm_config,
        )

        if not hsm_config_file:
            raise FatalError("--hsm-config is required when using --hsm")

        if verbose:
            log.print("Extracting public key from HSM...")

        # Read HSM config
        try:
            with open(hsm_config_file) as f:
                hsm_config = read_hsm_config(f)
        except FileNotFoundError:
            raise FatalError(f"HSM config file not found: {hsm_config_file}")
        except (KeyError, configparser.Error) as e:
            raise FatalError(f"Invalid HSM config file format: {e}")

        # Establish HSM session and get public key
        session = establish_session(hsm_config)
        try:
            public_key_obj = get_pubkey(session, hsm_config)
        finally:
            close_connection(session)

    elif public_key_file:
        if not os.path.exists(public_key_file):
            raise FatalError(f"Public key file not found: {public_key_file}")

        if verbose:
            log.print(f"Loading public key from {public_key_file}...")

        with open(public_key_file, "rb") as f:
            key_data = f.read()

        # Load public key
        if b"-BEGIN PUBLIC KEY" in key_data or b"-BEGIN EC PUBLIC KEY" in key_data:
            public_key_obj = serialization.load_pem_public_key(
                key_data, backend=default_backend()
            )
        else:
            raise FatalError("Unsupported public key format. Expected PEM format.")

    elif private_key_file:
        if not os.path.exists(private_key_file):
            raise FatalError(f"Private key file not found: {private_key_file}")

        if verbose:
            log.print(
                f"Extracting public key from private key file {private_key_file}..."
            )

        with open(private_key_file, "rb") as f:
            private_key = _load_private_key_unified(f.read(), key_type_hint="sdc")

        public_key_obj = private_key.public_key()

    else:
        raise FatalError(
            "One of --keyfile, --pub-key, or --hsm with --hsm-config must be provided"
        )

    # Extract public key bytes in SDC format (64 bytes: 32x + 32y)
    # _get_sdc_public_key_bytes validates key type and curve
    public_key_bytes = _get_sdc_public_key_bytes(public_key_obj)

    if verbose:
        log.print(
            "Public key bytes (64 bytes): "
            f"{binascii.hexlify(public_key_bytes).decode()}"
        )

    # Calculate SHA-256 hash
    pub_key_hash = hashlib.sha256(public_key_bytes).digest()

    if verbose:
        log.print(f"Public key hash: {binascii.hexlify(pub_key_hash).decode()}")

    # Reverse the hash for eFuse burning (digest format)
    # The digest is reversed so it can be written using burn-block-data
    # which writes in normal byte order
    pub_key_digest = pub_key_hash[::-1]

    if verbose:
        log.print(
            f"Public key digest (reversed): {binascii.hexlify(pub_key_digest).decode()}"
        )

    # Write digest to file
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "wb") as f:
        f.write(pub_key_digest)

    if verbose:
        log.print(f"Public key digest written to {output_file}")

    # Success message
    log.print(f'\nSDC public key digest generated successfully: "{output_file}"')
    log.print(f"Digest size: {len(pub_key_digest)} bytes")
    log.print(
        "This digest must be burned to the device eFuse using "
        "'espefuse burn-key <BLOCK> <digest_file> SDC_KEY_DIGEST'."
    )
