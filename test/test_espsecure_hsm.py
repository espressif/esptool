# Tests for espsecure.py (esp_hsm_sign.py) using the pytest framework
#
# Assumes openssl binary is in the PATH

import configparser
import os
import os.path
import sys
import tempfile
from collections import namedtuple

from conftest import need_to_install_package_err

try:
    import espsecure
    import pkcs11
except ImportError:
    need_to_install_package_err()

TEST_DIR = os.path.abspath(os.path.dirname(__file__))

TOKEN_PIN = "1234"
TOKEN_PIN_SO = "123456"


class EspSecureHSMTestCase:
    @classmethod
    def setup_class(self):
        self.cleanup_files = []  # keep a list of files _open()ed by each test case

    @classmethod
    def teardown_class(self):
        for f in self.cleanup_files:
            f.close()

    def _open(self, image_file):
        f = open(os.path.join(TEST_DIR, "secure_images", image_file), "rb")
        self.cleanup_files.append(f)
        return f

    def get_pkcs11lib(self):
        if sys.maxsize > 2**32:
            # 64-bits
            WINDOWS_SOFTHSM = "c:/SoftHSM2/lib/softhsm2-x64.dll"
        else:
            # 32-bits
            WINDOWS_SOFTHSM = "c:/SoftHSM2/lib/softhsm2.dll"
        # use SoftHSM2
        LIBS = [
            "/usr/local/lib/softhsm/libsofthsm2.so",  # macOS or local build
            "/usr/lib/softhsm/libsofthsm2.so",  # Debian
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",  # Ubuntu 16.04
            WINDOWS_SOFTHSM,  # Windows
        ]

        for lib in LIBS:
            if os.path.isfile(lib):
                print("Using lib:", lib)
                return lib

        return None

    # RSA-PSS token
    def softhsm_setup_token(self, filename, token_label):
        self.pkcs11_lib = self.get_pkcs11lib()
        if self.pkcs11_lib is None:
            print("PKCS11 lib does not exist")
            sys.exit(-1)
        lib = pkcs11.lib(self.pkcs11_lib)
        token = lib.get_token(token_label=token_label)
        slot = token.slot.slot_id
        session = token.open(rw=True, user_pin=TOKEN_PIN)

        keyID = (0x0,)
        label = "Private Key for Digital Signature"
        label_pubkey = "Public Key for Digital Signature"
        pubTemplate = [
            (pkcs11.Attribute.CLASS, pkcs11.constants.ObjectClass.PUBLIC_KEY),
            (pkcs11.Attribute.TOKEN, True),
            (pkcs11.Attribute.PRIVATE, False),
            (pkcs11.Attribute.MODULUS_BITS, 0x0C00),
            (pkcs11.Attribute.PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (pkcs11.Attribute.ENCRYPT, True),
            (pkcs11.Attribute.VERIFY, True),
            (pkcs11.Attribute.VERIFY_RECOVER, True),
            (pkcs11.Attribute.WRAP, True),
            (pkcs11.Attribute.LABEL, label_pubkey),
            (pkcs11.Attribute.ID, keyID),
        ]

        privTemplate = [
            (pkcs11.Attribute.CLASS, pkcs11.constants.ObjectClass.PRIVATE_KEY),
            (pkcs11.Attribute.TOKEN, True),
            (pkcs11.Attribute.PRIVATE, True),
            (pkcs11.Attribute.DECRYPT, True),
            (pkcs11.Attribute.SIGN, True),
            (pkcs11.Attribute.SENSITIVE, True),
            (pkcs11.Attribute.SIGN_RECOVER, True),
            (pkcs11.Attribute.LABEL, label),
            (pkcs11.Attribute.UNWRAP, True),
            (pkcs11.Attribute.ID, keyID),
        ]
        session.generate_keypair(
            pkcs11.KeyType.RSA,
            3072,
            private_template=privTemplate,
            public_template=pubTemplate,
        )

        # Generate HSM config file
        configfile = os.path.join(TEST_DIR, "secure_images", filename)
        config = configparser.ConfigParser()

        section = "hsm_config"
        config.add_section(section)

        config.set(section, "pkcs11_lib", self.pkcs11_lib)
        config.set(section, "credentials", TOKEN_PIN)
        config.set(section, "slot", str(slot))
        config.set(section, "label", label)
        config.set(section, "label_pubkey", label_pubkey)

        with open(configfile, "w") as c:
            config.write(c)

        session.close()


class TestSigning(EspSecureHSMTestCase):
    VerifyArgs = namedtuple(
        "verify_signature_args", ["version", "hsm", "hsm_config", "keyfile", "datafile"]
    )

    SignArgs = namedtuple(
        "sign_data_args",
        [
            "version",
            "keyfile",
            "output",
            "append_signatures",
            "hsm",
            "hsm_config",
            "pub_key",
            "signature",
            "datafile",
        ],
    )

    def test_sign_v2_hsm(self):
        # Sign using SoftHSMv2 + Verify
        self.softhsm_setup_token("softhsm_v2.ini", "softhsm-test-token")
        with tempfile.NamedTemporaryFile() as output_file:
            args = self.SignArgs(
                "2",
                None,
                output_file.name,
                False,
                True,
                os.path.join(TEST_DIR, "secure_images", "softhsm_v2.ini"),
                None,
                None,
                self._open("bootloader_unsigned_v2.bin"),
            )
            espsecure.sign_data(args)

            args = self.VerifyArgs(
                "2",
                True,
                os.path.join(TEST_DIR, "secure_images", "softhsm_v2.ini"),
                None,
                output_file,
            )
            espsecure.verify_signature(args)

    def test_sign_v2_hsm_append_signatures_multiple_steps(self):
        # Append signatures using HSM + Verify with an appended key
        self.softhsm_setup_token("softhsm_v2_1.ini", "softhsm-test-token-1")
        with tempfile.NamedTemporaryFile() as output_file1:
            args = self.SignArgs(
                "2",
                None,
                output_file1.name,
                True,
                True,
                os.path.join(TEST_DIR, "secure_images", "softhsm_v2_1.ini"),
                None,
                None,
                self._open("bootloader_unsigned_v2.bin"),
            )
            espsecure.sign_data(args)

            self.softhsm_setup_token("softhsm_v2_2.ini", "softhsm-test-token-2")
            with tempfile.NamedTemporaryFile() as output_file2:
                args = self.SignArgs(
                    "2",
                    None,
                    output_file2.name,
                    True,
                    True,
                    os.path.join(TEST_DIR, "secure_images", "softhsm_v2_2.ini"),
                    None,
                    None,
                    self._open(output_file1.name),
                )
                espsecure.sign_data(args)

                self.softhsm_setup_token("softhsm_v2_3.ini", "softhsm-test-token-3")
                with tempfile.NamedTemporaryFile() as output_file3:
                    args = self.SignArgs(
                        "2",
                        None,
                        output_file3.name,
                        True,
                        True,
                        os.path.join(TEST_DIR, "secure_images", "softhsm_v2_3.ini"),
                        None,
                        None,
                        self._open(output_file2.name),
                    )
                    espsecure.sign_data(args)

                    args = self.VerifyArgs(
                        "2",
                        True,
                        os.path.join(TEST_DIR, "secure_images", "softhsm_v2_1.ini"),
                        None,
                        output_file3,
                    )
                    espsecure.verify_signature(args)
                    output_file3.seek(0)

                    args = self.VerifyArgs(
                        "2",
                        True,
                        os.path.join(TEST_DIR, "secure_images", "softhsm_v2_2.ini"),
                        None,
                        output_file3,
                    )
                    espsecure.verify_signature(args)
                    output_file3.seek(0)

                    args = self.VerifyArgs(
                        "2",
                        True,
                        os.path.join(TEST_DIR, "secure_images", "softhsm_v2_3.ini"),
                        None,
                        output_file3,
                    )
                    espsecure.verify_signature(args)
