# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import binascii
import configparser
import os
import sys

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

import ecdsa


def read_hsm_config(configfile):
    config = configparser.ConfigParser()
    config.read(configfile)

    section = "hsm_config"
    if not config.has_section(section):
        raise configparser.NoSectionError(section)

    section_options = ["pkcs11_lib", "credentials", "slot", "label"]
    for option in section_options:
        if not config.has_option(section, option):
            raise configparser.NoOptionError(option, section)

    return config[section]


def establish_session(config):
    print("Trying to establish a session with the HSM.")
    try:
        if os.path.exists(config["pkcs11_lib"]):
            lib = pkcs11.lib(config["pkcs11_lib"])
        else:
            print(f'LIB file does not exist at {config["pkcs11_lib"]}')
            sys.exit(1)
        for slot in lib.get_slots(token_present=True):
            if slot.slot_id == int(config["slot"]):
                break

        token = slot.get_token()
        session = token.open(rw=True, user_pin=config["credentials"])
        print(f'Session creation successful with HSM slot {int(config["slot"])}.')
        return session

    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e)
        print("Session establishment failed")
        sys.exit(1)


def get_privkey_info(session, config):
    try:
        private_key = session.get_key(
            object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY, label=config["label"]
        )
        print(f'Got private key metadata with label {config["label"]}.')
        return private_key

    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e)
        print("Failed to get the private key")
        sys.exit(1)


def get_pubkey(session, config):
    print("Trying to extract public key from the HSM.")
    try:
        if "label_pubkey" in config:
            public_key_label = config["label_pubkey"]
        else:
            print(
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
            ecpoints, _ = ecdsa.der.remove_octet_string(
                public_key[pkcs11.Attribute.EC_POINT]
            )
            public_key = EC.EllipticCurvePublicKey.from_encoded_point(
                EC.SECP256R1(), ecpoints
            )

        else:
            print("Incorrect public key algorithm")
            sys.exit(1)

        print(f"Got public key with label {public_key_label}.")
        return public_key

    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e)
        print("Failed to extract the public key")
        sys.exit(1)


def sign_payload(private_key, payload):
    try:
        print("Signing payload using the HSM.")
        key_type = private_key.key_type
        mechanism, mechanism_params = get_mechanism(key_type)
        signature = private_key.sign(
            data=payload, mechanism=mechanism, mechanism_param=mechanism_params
        )

        if len(signature) != 0:
            print("Signature generation successful.")

        if key_type == pkcs11.mechanisms.KeyType.EC:
            r = int(binascii.hexlify(signature[:32]), 16)
            s = int(binascii.hexlify(signature[32:]), 16)

            # der encoding in case of ecdsa signatures
            signature = ecdsa.der.encode_sequence(
                ecdsa.der.encode_integer(r), ecdsa.der.encode_integer(s)
            )

        return signature

    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e, mechanism)
        print("Payload Signing Failed")
        sys.exit(1)


def get_mechanism(key_type):
    if key_type == pkcs11.mechanisms.KeyType.RSA:
        return pkcs11.mechanisms.Mechanism.SHA256_RSA_PKCS_PSS, (
            pkcs11.mechanisms.Mechanism.SHA256,
            pkcs11.MGF.SHA256,
            32,
        )
    elif key_type == pkcs11.mechanisms.KeyType.EC:
        return pkcs11.mechanisms.Mechanism.ECDSA_SHA256, None
    else:
        print("Invalid signing key mechanism")
        sys.exit(1)


def close_connection(session):
    try:
        session.close()
        print("Connection closed successfully")
    except pkcs11.exceptions.PKCS11Error as e:
        handle_exceptions(e)
        print("Failed to close the HSM session")
        sys.exit(1)
