# Tests for espsecure.py using the pytest framework
#
# Assumes openssl binary is in the PATH

import binascii
import io
import os
import os.path
import subprocess
import sys
import tempfile

from conftest import need_to_install_package_err

import pytest

try:
    import esptool
    import espsecure
except ImportError:
    need_to_install_package_err()

TEST_DIR = os.path.abspath(os.path.dirname(__file__))


@pytest.mark.host_test
class EspSecureTestCase:
    def run_espsecure(self, args):
        """
        Run espsecure.py with the specified arguments

        Returns output as a string if there is any,
        raises an exception if espsecure.py fails
        """
        cmd = [sys.executable, "-m", "espsecure"] + args.split(" ")
        print("\nExecuting {}...".format(" ".join(cmd)))

        try:
            output = subprocess.check_output(
                [str(s) for s in cmd], cwd=TEST_DIR, stderr=subprocess.STDOUT
            )
            output = output.decode("utf-8")
            print(output)
            return output
        except subprocess.CalledProcessError as e:
            print(e.output.decode("utf-8"))
            raise e

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


class TestESP32SecureBootloader(EspSecureTestCase):
    def test_digest_bootloader(self):
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            espsecure.digest_secure_bootloader(
                self._open("256bit_key.bin"),
                output_file.name,
                self._open("256bit_iv.bin"),
                self._open("bootloader.bin"),
            )

            with open(output_file.name, "rb") as of:
                with self._open("bootloader_digested.bin") as ef:
                    assert ef.read() == of.read()
        finally:
            os.unlink(output_file.name)

    def test_digest_rsa_public_key(self):
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            out = self.run_espsecure(
                "digest-rsa-public-key --keyfile "
                "secure_images/rsa_secure_boot_signing_key.pem "
                f"-o {output_file.name}"
            )
            assert (
                "DeprecationWarning: The command 'digest-rsa-public-key' is deprecated."
                in out
            )

            with open(output_file.name, "rb") as of:
                with self._open("rsa_public_key_digest.bin") as ef:
                    assert ef.read() == of.read()
        finally:
            os.unlink(output_file.name)


class TestSigning(EspSecureTestCase):
    def test_key_generation_v1(self):
        with tempfile.TemporaryDirectory() as keydir:
            # keyfile cannot exist before generation -> tempfile.NamedTemporaryFile()
            # cannot be used for keyfile
            keyfile_name = os.path.join(keydir, "key.pem")
            self.run_espsecure(f"generate-signing-key --version 1 {keyfile_name}")

    def test_key_generation_v2(self):
        with tempfile.TemporaryDirectory() as keydir:
            # keyfile cannot exist before generation -> tempfile.NamedTemporaryFile()
            # cannot be used for keyfile
            keyfile_name = os.path.join(keydir, "key.pem")
            self.run_espsecure(f"generate-signing-key --version 2 {keyfile_name}")

    def _test_sign_v1_data(self, key_name):
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            # Note: signing bootloader is not actually needed
            # for ESP32, it's just a handy file to sign
            espsecure.sign_data(
                "1",
                [self._open(key_name)],
                output_file.name,
                False,
                False,
                None,
                None,
                None,
                self._open("bootloader.bin"),
            )

            with open(output_file.name, "rb") as of:
                with self._open("bootloader_signed.bin") as ef:
                    assert ef.read() == of.read()

        finally:
            os.unlink(output_file.name)

    def test_sign_v1_data(self):
        self._test_sign_v1_data("ecdsa256_secure_boot_signing_key.pem")

    def test_sign_v1_data_pkcs8(self):
        self._test_sign_v1_data("ecdsa256_secure_boot_signing_key_pkcs8.pem")

    def test_sign_v1_with_pre_calculated_signature(self):
        # Sign using pre-calculated signature + Verify
        signing_pubkey = "ecdsa256_secure_boot_signing_pubkey.pem"
        pre_calculated_signature = "pre_calculated_bootloader_signature.bin"

        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            espsecure.sign_data(
                "1",
                None,
                output_file.name,
                False,
                False,
                None,
                [self._open(signing_pubkey)],
                [self._open(pre_calculated_signature)],
                self._open("bootloader.bin"),
            )

            espsecure.verify_signature(
                "1", False, None, self._open(signing_pubkey), output_file
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_data(self, scheme):
        key = f"{scheme}_secure_boot_signing_key.pem"
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            espsecure.sign_data(
                "2",
                [self._open(key)],
                output_file.name,
                False,
                False,
                None,
                None,
                None,
                self._open("bootloader_unsigned_v2.bin"),
            )

            espsecure.verify_signature("2", False, None, self._open(key), output_file)
        finally:
            output_file.close()
            os.unlink(output_file.name)

    def test_sign_v2_multiple_keys(self):
        # 3 keys + Verify with 3rd key
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            espsecure.sign_data(
                "2",
                [
                    self._open("rsa_secure_boot_signing_key.pem"),
                    self._open("rsa_secure_boot_signing_key2.pem"),
                    self._open("rsa_secure_boot_signing_key3.pem"),
                ],
                output_file.name,
                False,
                False,
                None,
                None,
                None,
                self._open("bootloader_unsigned_v2.bin"),
            )

            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key3.pem"),
                output_file,
            )

            output_file.seek(0)
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key2.pem"),
                output_file,
            )

            output_file.seek(0)
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key.pem"),
                output_file,
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    def test_sign_v2_append_signatures(self):
        # Append signatures + Verify with an appended key
        # (bootloader_signed_v2_rsa.bin already signed with
        # rsa_secure_boot_signing_key.pem)
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            espsecure.sign_data(
                "2",
                [
                    self._open("rsa_secure_boot_signing_key2.pem"),
                    self._open("rsa_secure_boot_signing_key3.pem"),
                ],
                output_file.name,
                True,
                False,
                None,
                None,
                None,
                self._open("bootloader_signed_v2_rsa.bin"),
            )

            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key.pem"),
                output_file,
            )

            output_file.seek(0)
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key2.pem"),
                output_file,
            )

            output_file.seek(0)
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key3.pem"),
                output_file,
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    def test_sign_v2_append_signatures_multiple_steps(self):
        # similar to previous test, but sign in two invocations
        try:
            output_file1 = tempfile.NamedTemporaryFile(delete=False)
            output_file2 = tempfile.NamedTemporaryFile(delete=False)
            espsecure.sign_data(
                "2",
                [self._open("rsa_secure_boot_signing_key2.pem")],
                output_file1.name,
                True,
                False,
                None,
                None,
                None,
                self._open("bootloader_signed_v2_rsa.bin"),
            )

            espsecure.sign_data(
                "2",
                [self._open("rsa_secure_boot_signing_key3.pem")],
                output_file2.name,
                True,
                False,
                None,
                None,
                None,
                output_file1,
            )

            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key.pem"),
                output_file2,
            )

            output_file2.seek(0)
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key2.pem"),
                output_file2,
            )

            output_file2.seek(0)
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key3.pem"),
                output_file2,
            )
        finally:
            output_file1.close()
            os.unlink(output_file1.name)
            output_file2.close()
            os.unlink(output_file2.name)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_with_pre_calculated_signature(self, scheme):
        # Sign using pre-calculated signature + Verify
        pub_key = f"{scheme}_secure_boot_signing_pubkey.pem"
        signature = f"pre_calculated_bootloader_signature_{scheme}.bin"
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            espsecure.sign_data(
                "2",
                None,
                output_file.name,
                False,
                False,
                None,
                [self._open(pub_key)],
                [self._open(signature)],
                self._open("bootloader_unsigned_v2.bin"),
            )

            espsecure.verify_signature(
                "2", False, None, self._open(pub_key), output_file
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    def test_sign_v2_with_multiple_pre_calculated_signatures(self):
        # Sign using multiple pre-calculated signatures + Verify
        signing_pubkeys = [
            "rsa_secure_boot_signing_pubkey.pem",
            "rsa_secure_boot_signing_pubkey.pem",
            "rsa_secure_boot_signing_pubkey.pem",
        ]
        pre_calculated_signatures = [
            "pre_calculated_bootloader_signature_rsa.bin",
            "pre_calculated_bootloader_signature_rsa.bin",
            "pre_calculated_bootloader_signature_rsa.bin",
        ]
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            espsecure.sign_data(
                "2",
                None,
                output_file.name,
                False,
                False,
                None,
                [self._open(pub_key) for pub_key in signing_pubkeys],
                [self._open(signature) for signature in pre_calculated_signatures],
                self._open("bootloader_unsigned_v2.bin"),
            )

            espsecure.verify_signature(
                "2", False, None, self._open(signing_pubkeys[0]), output_file
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    @pytest.mark.parametrize(
        "version, keyfile, datafile",
        [
            ("1", "ecdsa256_secure_boot_signing_key.pem", "bootloader_signed.bin"),
            ("2", "rsa_secure_boot_signing_key.pem", "bootloader_signed_v2_rsa.bin"),
            (
                "2",
                "ecdsa384_secure_boot_signing_key.pem",
                "bootloader_signed_v2_ecdsa384.bin",
            ),
            (
                "2",
                "ecdsa256_secure_boot_signing_key.pem",
                "bootloader_signed_v2_ecdsa256.bin",
            ),
            (
                "2",
                "ecdsa192_secure_boot_signing_key.pem",
                "bootloader_signed_v2_ecdsa192.bin",
            ),
        ],
        ids=["v1", "v2_rsa", "v2_ecdsa384", "v2_ecdsa256", "v2_ecdsa192"],
    )
    def test_verify_signature_correct_key(self, version, keyfile, datafile):
        espsecure.verify_signature(
            version,
            False,
            None,
            self._open(keyfile),
            self._open(datafile),
        )

    def test_verify_signature_wrong_key_v1(self):
        with pytest.raises(esptool.FatalError) as cm:
            espsecure.verify_signature(
                "1",
                False,
                None,
                self._open("ecdsa256_secure_boot_signing_key2.pem"),
                self._open("bootloader_signed.bin"),
            )
        assert "Signature is not valid" in str(cm.value)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_verify_signature_wrong_key_v2(self, scheme):
        with pytest.raises(esptool.FatalError) as cm:
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open(f"{scheme}_secure_boot_signing_key2.pem"),
                self._open(f"bootloader_signed_v2_{scheme}.bin"),
            )
        assert "Signature could not be verified with the provided key." in str(cm.value)

    def test_verify_signature_wrong_scheme(self):
        with pytest.raises(esptool.FatalError) as cm:
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("ecdsa256_secure_boot_signing_key.pem"),
                self._open("bootloader_signed.bin"),
            )
        assert "Invalid datafile" in str(cm.value)

    def test_verify_signature_multi_signed_wrong_key(self):
        with pytest.raises(esptool.FatalError) as cm:
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_key4.pem"),
                self._open("bootloader_multi_signed_v2.bin"),
            )
        assert "Signature could not be verified with the provided key." in str(cm.value)

    @pytest.mark.parametrize(
        "version, keyfile, datafile",
        [
            ("1", "ecdsa256_secure_boot_signing_pubkey.pem", "bootloader_signed.bin"),
            ("2", "rsa_secure_boot_signing_pubkey.pem", "bootloader_signed_v2_rsa.bin"),
            (
                "2",
                "ecdsa384_secure_boot_signing_pubkey.pem",
                "bootloader_signed_v2_ecdsa384.bin",
            ),
            (
                "2",
                "ecdsa256_secure_boot_signing_pubkey.pem",
                "bootloader_signed_v2_ecdsa256.bin",
            ),
            (
                "2",
                "ecdsa192_secure_boot_signing_pubkey.pem",
                "bootloader_signed_v2_ecdsa192.bin",
            ),
        ],
        ids=["v1", "v2_rsa", "v2_ecdsa384", "v2_ecdsa256", "v2_ecdsa192"],
    )
    def test_verify_signature_correct_pubkey(self, version, keyfile, datafile):
        espsecure.verify_signature(
            version,
            False,
            None,
            self._open(keyfile),
            self._open(datafile),
        )

    def test_verify_signature_wrong_pubkey_v1(self):
        with pytest.raises(esptool.FatalError) as cm:
            espsecure.verify_signature(
                "1",
                False,
                None,
                self._open("ecdsa256_secure_boot_signing_pubkey2.pem"),
                self._open("bootloader_signed.bin"),
            )
        assert "Signature is not valid" in str(cm.value)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_verify_signature_wrong_pubkey_v2(self, scheme):
        with pytest.raises(esptool.FatalError) as cm:
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open(f"{scheme}_secure_boot_signing_pubkey2.pem"),
                self._open(f"bootloader_signed_v2_{scheme}.bin"),
            )
        assert "Signature could not be verified with the provided key." in str(cm.value)

    def test_verify_signature_multi_signed_wrong_pubkey(self):
        with pytest.raises(esptool.FatalError) as cm:
            espsecure.verify_signature(
                "2",
                False,
                None,
                self._open("rsa_secure_boot_signing_pubkey4.pem"),
                self._open("bootloader_multi_signed_v2.bin"),
            )
        assert "Signature could not be verified with the provided key." in str(cm.value)

    def test_extract_binary_public_key(self):
        with (
            tempfile.NamedTemporaryFile() as pub_keyfile,
            tempfile.NamedTemporaryFile() as pub_keyfile2,
        ):
            espsecure.extract_public_key(
                "1", self._open("ecdsa256_secure_boot_signing_key.pem"), pub_keyfile
            )

            espsecure.extract_public_key(
                "1", self._open("ecdsa256_secure_boot_signing_key2.pem"), pub_keyfile2
            )

            pub_keyfile.seek(0)
            pub_keyfile2.seek(0)

            # use correct extracted public key to verify
            espsecure.verify_signature(
                "1", False, None, pub_keyfile, self._open("bootloader_signed.bin")
            )

            # use wrong extracted public key to try and verify
            with pytest.raises(esptool.FatalError) as cm:
                espsecure.verify_signature(
                    "1", False, None, pub_keyfile2, self._open("bootloader_signed.bin")
                )
            assert "Signature is not valid" in str(cm.value)

    @pytest.mark.parametrize("scheme", ["rsa3072", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_generate_and_extract_key_v2(self, scheme):
        with tempfile.TemporaryDirectory() as keydir:
            # keyfile cannot exist before generation -> tempfile.NamedTemporaryFile()
            # cannot be used for keyfile
            keyfile_name = os.path.join(keydir, "key.pem")

            espsecure.generate_signing_key("2", scheme, keyfile_name)

            with (
                tempfile.NamedTemporaryFile() as pub_keyfile,
                open(keyfile_name, "rb") as keyfile,
            ):
                espsecure.extract_public_key("2", keyfile, pub_keyfile)


class TestFlashEncryption(EspSecureTestCase):
    def _test_encrypt_decrypt(
        self,
        input_plaintext,
        expected_ciphertext,
        key_path,
        offset,
        flash_crypt_conf=0xF,
        aes_xts=None,
    ):
        original_plaintext = self._open(input_plaintext)
        keyfile = self._open(key_path)
        ciphertext = io.BytesIO()

        espsecure.encrypt_flash_data(
            keyfile, ciphertext, offset, flash_crypt_conf, aes_xts, original_plaintext
        )

        original_plaintext.seek(0)
        assert original_plaintext.read() != ciphertext.getvalue()
        with self._open(expected_ciphertext) as f:
            assert f.read() == ciphertext.getvalue()

        ciphertext.seek(0)
        keyfile.seek(0)
        plaintext = io.BytesIO()
        espsecure.decrypt_flash_data(
            keyfile, plaintext, offset, flash_crypt_conf, aes_xts, ciphertext
        )

        original_plaintext.seek(0)
        assert original_plaintext.read() == plaintext.getvalue()


class TestESP32FlashEncryption(TestFlashEncryption):
    def test_encrypt_decrypt_bootloader(self):
        self._test_encrypt_decrypt(
            "bootloader.bin", "bootloader-encrypted.bin", "256bit_key.bin", 0x1000, 0xF
        )

    def test_encrypt_decrypt_app(self):
        self._test_encrypt_decrypt(
            "hello-world-signed.bin",
            "hello-world-signed-encrypted.bin",
            "ef-flashencryption-key.bin",
            0x20000,
            0xF,
        )

    def test_encrypt_decrypt_non_default_conf(self):
        """Try some non-default (non-recommended) flash_crypt_conf settings"""
        for conf in [0x0, 0x3, 0x9, 0xC]:
            self._test_encrypt_decrypt(
                "bootloader.bin",
                f"bootloader-encrypted-conf{conf:x}.bin",
                "256bit_key.bin",
                0x1000,
                conf,
            )


class TestAesXtsFlashEncryption(TestFlashEncryption):
    def test_encrypt_decrypt_bootloader(self):
        self._test_encrypt_decrypt(
            "bootloader.bin",
            "bootloader-encrypted-aes-xts.bin",
            "256bit_key.bin",
            0x1000,
            aes_xts=True,
        )

    def test_encrypt_decrypt_app(self):
        self._test_encrypt_decrypt(
            "hello-world-signed.bin",
            "hello-world-signed-encrypted-aes-xts.bin",
            "ef-flashencryption-key.bin",
            0x20000,
            aes_xts=True,
        )

    def test_encrypt_decrypt_app_512_bit_key(self):
        self._test_encrypt_decrypt(
            "hello-world-signed.bin",
            "hello-world-signed-encrypted-aes-xts-256.bin",
            "512bit_key.bin",
            0x10000,
            aes_xts=True,
        )

    def test_padding(self):
        # Random 2048 bits hex string
        plaintext = binascii.unhexlify(
            "c33b7c49f12a969a9bb45af5f660b73f"
            "3b372685012da570df1cf99d1a82eabb"
            "fdf6aa16b9675bd8a2f95e871513e175"
            "3bc89f57986ecfb2707a3d3b59a46968"
            "5e6609d2e9c21d4b2310571175e6e3de"
            "2656ee22243f557b925ef39ff782ab56"
            "f821e6859ee852000daae7c03a7c77ce"
            "58744f15fbdf0ad4ae6e964aedd6316a"
            "cf0e36935eef895cd14a60fe682fb971"
            "eb239eae38b770bdf969017c9decfd91"
            "b7c60329fb0c896684f0e7415f99dec1"
            "da0572fac360a3e6d7219973a7de07e5"
            "33b5abfdf5917ed5bfe54d660a6f5047"
            "32fdb8d07259bfcdc67da87293857c11"
            "427b2bae5f00da4a4b2b00b588ff5109"
            "4c41f07f02f680f8826841b43da3f25b"
        )

        plaintext_file = io.BytesIO(plaintext)
        ciphertext_full_block = io.BytesIO()

        keyfile = self._open("256bit_key.bin")
        address = 0x1000

        espsecure.encrypt_flash_data(
            keyfile, ciphertext_full_block, address, None, "aes_xts", plaintext_file
        )

        # Test with different number of bytes per encryption call
        # Final ciphertext should still be the same if padding is done correctly
        bytes_per_encrypt = [16, 32, 64, 128]

        for b in bytes_per_encrypt:
            ciphertext = io.BytesIO()
            num_enc_calls = len(plaintext) // b

            for i in range(0, num_enc_calls):
                keyfile.seek(0)
                offset = b * i

                # encrypt the whole plaintext a substring of b bytes at a time
                plaintext_sub = io.BytesIO(plaintext[offset : offset + b])

                espsecure.encrypt_flash_data(
                    keyfile,
                    ciphertext,
                    address + offset,
                    None,
                    "aes_xts",
                    plaintext_sub,
                )

            assert ciphertext_full_block.getvalue() == ciphertext.getvalue()


class TestDigest(EspSecureTestCase):
    def test_digest_private_key(self):
        with tempfile.NamedTemporaryFile() as f:
            outfile_name = f.name

        self.run_espsecure(
            "digest-private-key "
            "--keyfile secure_images/ecdsa256_secure_boot_signing_key.pem "
            f"{outfile_name}"
        )

        with open(outfile_name, "rb") as f:
            assert f.read() == binascii.unhexlify(
                "7b7b53708fc89d5e0b2df2571fb8f9d778f61a422ff1101a22159c4b34aad0aa"
            )

    def test_digest_private_key_with_invalid_output(self, capsys):
        fname = "secure_images/ecdsa256_secure_boot_signing_key.pem"

        with pytest.raises(subprocess.CalledProcessError):
            self.run_espsecure(f"digest-private-key --keyfile {fname} {fname}")
        output = capsys.readouterr().out
        assert "should not be the same!" in output
