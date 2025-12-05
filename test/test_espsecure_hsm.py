# Tests for espsecure (esp_hsm_sign.py) using the pytest framework
#
# Assumes openssl binary is in the PATH

import configparser
import os
import os.path
import sys
import tempfile

import pytest

pytestmark = [pytest.mark.host_test, pytest.mark.linux_host_test]

pkcs11 = pytest.importorskip("pkcs11")

import espsecure

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

    # ECDSA P-256 token
    def softhsm_setup_ecdsa_token(self, filename, token_label):
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

        # Delete existing keys with the same ID to avoid duplicates
        try:
            # Try to find and delete existing private key
            try:
                priv_key = session.get_key(
                    object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY,
                    id=keyID,
                )
                priv_key.destroy()
            except pkcs11.exceptions.NoSuchKey:
                pass

            # Try to find and delete existing public key
            try:
                pub_key = session.get_key(
                    object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY,
                    id=keyID,
                )
                pub_key.destroy()
            except pkcs11.exceptions.NoSuchKey:
                pass
        except pkcs11.exceptions.MultipleObjectsReturned:
            # If multiple keys exist, delete all of them
            for obj in session.get_objects({pkcs11.Attribute.ID: keyID}):
                try:
                    obj.destroy()
                except Exception:
                    pass

        # OID for secp256r1 (1.2.840.10045.3.1.7)
        ec_params = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"

        pubTemplate = [
            (pkcs11.Attribute.TOKEN, True),
            (pkcs11.Attribute.PRIVATE, False),
            (pkcs11.Attribute.EC_PARAMS, ec_params),
            (pkcs11.Attribute.VERIFY, True),
            (pkcs11.Attribute.LABEL, label_pubkey),
            (pkcs11.Attribute.ID, keyID),
        ]

        privTemplate = [
            (pkcs11.Attribute.TOKEN, True),
            (pkcs11.Attribute.PRIVATE, True),
            (pkcs11.Attribute.SIGN, True),
            (pkcs11.Attribute.SENSITIVE, True),
            (pkcs11.Attribute.LABEL, label),
            (pkcs11.Attribute.ID, keyID),
        ]
        session.generate_keypair(
            pkcs11.KeyType.EC,
            256,
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
    def test_sign_v2_hsm(self):
        # Sign using SoftHSMv2 + Verify
        self.softhsm_setup_token("softhsm_v2.ini", "softhsm-test-token")
        with (
            tempfile.NamedTemporaryFile() as output_file,
            open(
                os.path.join(TEST_DIR, "secure_images", "softhsm_v2.ini")
            ) as config_file,
        ):
            espsecure.sign_data(
                version="2",
                keyfile=None,
                output=output_file.name,
                append_signatures=False,
                hsm=True,
                hsm_config=config_file,
                pub_key=[],
                signature=[],
                datafile=self._open("bootloader_unsigned_v2.bin"),
            )
            config_file.seek(0)
            espsecure.verify_signature(
                "2",
                True,
                config_file,
                None,
                output_file,
            )

    def test_sign_v2_hsm_append_signatures_multiple_steps(self):
        # Append signatures using HSM + Verify with an appended key
        self.softhsm_setup_token("softhsm_v2_1.ini", "softhsm-test-token-1")
        with (
            tempfile.NamedTemporaryFile() as output_file1,
            open(
                os.path.join(TEST_DIR, "secure_images", "softhsm_v2_1.ini")
            ) as config_file1,
        ):
            espsecure.sign_data(
                version="2",
                keyfile=None,
                output=output_file1.name,
                append_signatures=True,
                hsm=True,
                hsm_config=config_file1,
                pub_key=[],
                signature=[],
                datafile=self._open("bootloader_unsigned_v2.bin"),
            )

            self.softhsm_setup_token("softhsm_v2_2.ini", "softhsm-test-token-2")
            with (
                tempfile.NamedTemporaryFile() as output_file2,
                open(
                    os.path.join(TEST_DIR, "secure_images", "softhsm_v2_2.ini")
                ) as config_file2,
            ):
                espsecure.sign_data(
                    version="2",
                    keyfile=None,
                    output=output_file2.name,
                    append_signatures=True,
                    hsm=True,
                    hsm_config=config_file2,
                    pub_key=[],
                    signature=[],
                    datafile=self._open(output_file1.name),
                )

                self.softhsm_setup_token("softhsm_v2_3.ini", "softhsm-test-token-3")
                with (
                    tempfile.NamedTemporaryFile() as output_file3,
                    open(
                        os.path.join(TEST_DIR, "secure_images", "softhsm_v2_3.ini"),
                    ) as config_file3,
                ):
                    espsecure.sign_data(
                        version="2",
                        keyfile=None,
                        output=output_file3.name,
                        append_signatures=True,
                        hsm=True,
                        hsm_config=config_file3,
                        pub_key=[],
                        signature=[],
                        datafile=self._open(output_file2.name),
                    )

                    config_file1.seek(0)
                    config_file2.seek(0)
                    config_file3.seek(0)

                    espsecure.verify_signature(
                        "2",
                        True,
                        config_file1,
                        None,
                        output_file3,
                    )
                    output_file3.seek(0)

                    espsecure.verify_signature(
                        "2",
                        True,
                        config_file2,
                        None,
                        output_file3,
                    )
                    output_file3.seek(0)

                    espsecure.verify_signature(
                        "2",
                        True,
                        config_file3,
                        None,
                        output_file3,
                    )


class TestSDCSigning(EspSecureHSMTestCase):
    def test_generate_sdc_cert_hsm(self):
        self.softhsm_setup_ecdsa_token("softhsm_v2_sdc.ini", "softhsm-sdc-token")
        with (
            tempfile.NamedTemporaryFile() as output_file,
            open(
                os.path.join(TEST_DIR, "secure_images", "softhsm_v2_sdc.ini")
            ) as config_file,
        ):
            from espsecure.esp_sdc import generate_sdc_certificate

            generate_sdc_certificate(
                private_key_file=None,
                output_file=output_file.name,
                mac="00:00:00:00:00:00",
                sdc_session_counter=0,
                hsm=True,
                hsm_config_file=config_file.name,
                enable_jtag=True,
                enable_download_reuse=True,
            )

            assert os.path.exists(output_file.name)
            assert os.path.getsize(output_file.name) == 468

    def test_digest_sdc_public_key_hsm(self):
        self.softhsm_setup_ecdsa_token("softhsm_v2_sdc.ini", "softhsm-sdc-token")
        with (
            tempfile.NamedTemporaryFile() as digest_file,
            open(
                os.path.join(TEST_DIR, "secure_images", "softhsm_v2_sdc.ini")
            ) as config_file,
        ):
            from espsecure.esp_sdc import digest_sdc_public_key

            digest_sdc_public_key(
                private_key_file=None,
                public_key_file=None,
                output_file=digest_file.name,
                hsm=True,
                hsm_config_file=config_file.name,
            )

            assert os.path.exists(digest_file.name)
            assert os.path.getsize(digest_file.name) == 32
