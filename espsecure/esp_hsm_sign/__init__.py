# SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import binascii
import configparser
import hashlib
import os
import sys
from esptool.logger import log
from getpass import getpass
from typing import IO

try:
    import pkcs11
    from .exceptions import handle_exceptions
except ImportError:
    raise ImportError(
        "python-pkcs11 package is not installed. "
        "Please install it using the required packages with command: "
        "pip install 'esptool[hsm]'"
    )

import cryptography.hazmat.primitives.asymmetric.ec as EC
import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import cryptography.hazmat.primitives.asymmetric.utils as utils


def read_hsm_config(configfile: IO) -> configparser.SectionProxy:
    config = configparser.ConfigParser()
    config.read_file(configfile)

    section = "hsm_config"
    if not config.has_section(section):
        raise configparser.NoSectionError(section)

    section_options = ["pkcs11_lib", "slot", "label"]
    for option in section_options:
        if not config.has_option(section, option):
            raise configparser.NoOptionError(option, section)

    # If the config file does not contain the "credentials" option,
    # prompt the user for the HSM PIN
    if not config.has_option(section, "credentials"):
        hsm_pin = getpass("Please enter the PIN of your HSM:\n")
        config.set(section, "credentials", hsm_pin)

    return config[section]


def establish_session(config: configparser.SectionProxy) -> pkcs11.Session:
    log.print("Trying to establish a session with the HSM...")
    try:
        if os.path.exists(config["pkcs11_lib"]):
            lib = pkcs11.lib(config["pkcs11_lib"])
        else:
            log.error(f'LIB file does not exist at "{config["pkcs11_lib"]}".')
            sys.exit(1)
        for slot in lib.get_slots(token_present=True):
            if slot.slot_id == int(config["slot"]):
                break

        token = slot.get_token()
        session = token.open(rw=True, user_pin=config["credentials"])
        log.print(f"Session creation successful with HSM slot {int(config['slot'])}.")
        return session

    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e)
        log.error("Session establishment failed.")
        sys.exit(1)


def get_privkey_info(
    session: pkcs11.Session, config: configparser.SectionProxy
) -> pkcs11.Key:
    try:
        private_key = session.get_key(
            object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=config["label"]
        )
        log.print(f"Got private key metadata with label {config['label']}.")
        return private_key

    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e)
        log.error("Failed to get the private key.")
        sys.exit(1)


def get_pubkey(
    session: pkcs11.Session, config: configparser.SectionProxy
) -> EC.EllipticCurvePublicKey | RSA.RSAPublicKey:
    log.print("Trying to extract public key from the HSM...")
    try:
        if "label_pubkey" in config:
            public_key_label = config["label_pubkey"]
        else:
            log.print(
                "Config option 'label_pubkey' not found, "
                "using config option 'label' for public key."
            )
            public_key_label = config["label"]

        public_key = session.get_key(
            object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY,
            label=public_key_label,
        )
        if public_key.key_type == pkcs11.mechanisms.KeyType.RSA:
            exponent = public_key[pkcs11.Attribute.PUBLIC_EXPONENT]
            modulus = public_key[pkcs11.Attribute.MODULUS]
            e = int.from_bytes(exponent, byteorder="big")
            n = int.from_bytes(modulus, byteorder="big")
            public_key = RSA.RSAPublicNumbers(e, n).public_key()

        elif public_key.key_type == pkcs11.mechanisms.KeyType.EC:
            # EC_POINT is encoded as an octet string
            # First byte is "0x04" indicating uncompressed point format
            # followed by length bytes
            ec_point_der = public_key[pkcs11.Attribute.EC_POINT]
            if ec_point_der[0] != 0x04:  # octet string tag
                raise ValueError(
                    "Invalid EC_POINT encoding. "
                    f"Wanted type 'octetstring' (0x04), got {ec_point_der[0]:#02x}."
                )
            length = ec_point_der[1]
            ecpoints = ec_point_der[2 : 2 + length]
            public_key = EC.EllipticCurvePublicKey.from_encoded_point(
                EC.SECP256R1(), ecpoints
            )

        else:
            log.error("Incorrect public key algorithm.")
            sys.exit(1)

        log.print(f"Got public key with label {public_key_label}.")
        return public_key

    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e)
        log.error("Failed to extract the public key.")
        sys.exit(1)


def sign_payload(private_key: pkcs11.Key, payload: bytes) -> bytes:
    try:
        log.print("Signing payload using the HSM...")
        key_type = private_key.key_type
        mechanism, mechanism_params = get_mechanism(key_type)
        hashed_payload = hashlib.sha256(payload).digest()
        signature: bytes = private_key.sign(
            data=hashed_payload, mechanism=mechanism, mechanism_param=mechanism_params
        )

        if len(signature) != 0:
            log.print("Signature generation successful.")

        if key_type == pkcs11.mechanisms.KeyType.EC:
            r = int(binascii.hexlify(signature[:32]), 16)
            s = int(binascii.hexlify(signature[32:]), 16)

            # ECDSA signature is encoded as a DER sequence
            signature = utils.encode_dss_signature(r, s)

        return signature

    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e, mechanism)
        log.error("Payload signing failed.")
        sys.exit(1)


def get_mechanism(
    key_type: pkcs11.mechanisms.KeyType,
) -> tuple[pkcs11.mechanisms.Mechanism, tuple | None]:
    if key_type == pkcs11.mechanisms.KeyType.RSA:
        return pkcs11.mechanisms.Mechanism.RSA_PKCS_PSS, (
            pkcs11.mechanisms.Mechanism.SHA256,
            pkcs11.MGF.SHA256,
            32,
        )
    elif key_type == pkcs11.mechanisms.KeyType.EC:
        return pkcs11.mechanisms.Mechanism.ECDSA, None
    else:
        log.error("Invalid signing key mechanism.")
        sys.exit(1)


def close_connection(session: pkcs11.Session):
    try:
        session.close()
        log.print("Connection closed successfully.")
    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e)
        log.error("Failed to close the HSM session.")
        sys.exit(1)
