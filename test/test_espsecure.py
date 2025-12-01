# Tests for espsecure using the pytest framework
#
# Assumes openssl binary is in the PATH

import binascii
import hashlib
import io
import json
import os
import os.path
import struct
import subprocess
import sys
import tempfile
import zlib

import pytest
from conftest import need_to_install_package_err

try:
    import espsecure
    from espsecure import SECTOR_SIZE
except ImportError:
    need_to_install_package_err()

TEST_DIR = os.path.abspath(os.path.dirname(__file__))


@pytest.mark.host_test
class EspSecureTestCase:
    def run_espsecure(self, args):
        """
        Run espsecure with the specified arguments

        Returns output as a string if there is any,
        raises an exception if espsecure fails
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

    def _get_imagepath(self, image_file):
        return os.path.join(TEST_DIR, "secure_images", image_file)

    def _open(self, image_file):
        f = open(self._get_imagepath(image_file), "rb")
        self.cleanup_files.append(f)
        return f


class TestESP32SecureBootloader(EspSecureTestCase):
    def test_digest_bootloader(self):
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            self.run_espsecure(
                f"digest-secure-bootloader "
                f"--keyfile {self._get_imagepath('256bit_key.bin')} "
                f"--output {output_file.name} "
                f"--iv {self._get_imagepath('256bit_iv.bin')} "
                f"{self._get_imagepath('bootloader.bin')}"
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
                "digest-rsa-public-key "
                f"--keyfile {self._get_imagepath('rsa_secure_boot_signing_key.pem')} "
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

    def test_extract_public_key_v1(self):
        """Test that extract-public-key CLI command produces raw output for version 1"""
        with tempfile.TemporaryDirectory() as keydir:
            # Generate a version 1 ECDSA256 key
            keyfile_name = os.path.join(keydir, "v1_key.pem")
            self.run_espsecure(
                f"generate-signing-key --version 1 --scheme ecdsa256 {keyfile_name}"
            )

            output_file = os.path.join(keydir, "v1_public_key.bin")
            output = self.run_espsecure(
                f"extract-public-key --version 1 --keyfile {keyfile_name} {output_file}"
            )

            # Check that the command succeeded
            assert "public key extracted" in output.lower()

            # Read the output file
            with open(output_file, "rb") as f:
                v1_output = f.read()

            # Version 1 should produce raw binary (64 bytes for ECDSA256)
            assert len(v1_output) == 64, (
                f"Expected 64 bytes for ECDSA256, got {len(v1_output)}"
            )

            # Raw binary should not contain PEM markers
            assert b"-----BEGIN PUBLIC KEY-----" not in v1_output
            assert b"-----END PUBLIC KEY-----" not in v1_output
            assert b"PUBLIC KEY" not in v1_output

            # Raw binary should contain only binary data (not text)
            printable_count = sum(1 for b in v1_output if 32 <= b <= 126)
            assert printable_count < len(v1_output), (
                "Raw binary should not be all printable ASCII"
            )

    def test_extract_public_key_v2(self):
        """Test that extract-public-key CLI command produces PEM output for version 2"""
        with tempfile.TemporaryDirectory() as keydir:
            # Generate a version 2 ECDSA256 key
            keyfile_name = os.path.join(keydir, "v2_key.pem")
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {keyfile_name}"
            )

            output_file = os.path.join(keydir, "v2_public_key.pem")
            output = self.run_espsecure(
                f"extract-public-key --version 2 --keyfile {keyfile_name} {output_file}"
            )

            # Check that the command succeeded
            assert "public key extracted" in output.lower()

            # Read the output file
            with open(output_file, "rb") as f:
                v2_output = f.read()

            # Version 2 should produce PEM format
            assert b"-----BEGIN PUBLIC KEY-----" in v2_output
            assert b"-----END PUBLIC KEY-----" in v2_output
            assert b"PUBLIC KEY" in v2_output

            # PEM format should be longer than raw binary
            assert len(v2_output) > 64, "PEM format should be longer than raw binary"

            # PEM format should be mostly printable ASCII
            printable_count = sum(1 for b in v2_output if 32 <= b <= 126)
            assert printable_count > len(v2_output) * 0.8, (
                "PEM format should be mostly printable ASCII"
            )


class TestSigning(EspSecureTestCase):
    def test_key_generation_v1(self):
        with tempfile.TemporaryDirectory() as keydir:
            # keyfile cannot exist before generation -> tempfile.NamedTemporaryFile()
            # cannot be used for keyfile
            keyfile_name = os.path.join(keydir, "key.pem")
            self.run_espsecure(f"generate-signing-key --version 1 {keyfile_name}")

    @pytest.mark.parametrize("scheme", ["rsa3072", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_key_generation_v2(self, scheme):
        with tempfile.TemporaryDirectory() as keydir:
            # keyfile cannot exist before generation -> tempfile.NamedTemporaryFile()
            # cannot be used for keyfile
            keyfile_name = os.path.join(keydir, "key.pem")
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme {scheme} {keyfile_name}"
            )

    def _test_sign_v1_data(self, key_name):
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            # Note: signing bootloader is not actually needed
            # for ESP32, it's just a handy file to sign
            self.run_espsecure(
                f"sign-data --version 1 --keyfile {self._get_imagepath(key_name)} "
                f"--output {output_file.name} {self._get_imagepath('bootloader.bin')}"
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
            self.run_espsecure(
                f"sign-data --version 1 "
                f"--pub-key {self._get_imagepath(signing_pubkey)} "
                f"--signature {self._get_imagepath(pre_calculated_signature)} "
                f"--output {output_file.name} "
                f"{self._get_imagepath('bootloader.bin')}"
            )

            self.run_espsecure(
                f"verify-signature --version 1 "
                f"--keyfile {self._get_imagepath(signing_pubkey)} "
                f"{output_file.name}"
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_data(self, scheme):
        key = f"{scheme}_secure_boot_signing_key.pem"
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            self.run_espsecure(
                f"sign-data --version 2 "
                f"--keyfile {self._get_imagepath(key)} "
                f"--output {output_file.name} "
                f"{self._get_imagepath('bootloader_unsigned_v2.bin')}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile {self._get_imagepath(key)} "
                f"{output_file.name}"
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_data_skip_padding(self, scheme):
        """Test signing with --skip-padding option"""
        key = f"{scheme}_secure_boot_signing_key.pem"
        data_length = 100

        # Create a test file that is NOT sector-aligned (e.g., 100 bytes)
        with tempfile.NamedTemporaryFile(delete=False) as non_aligned_file:
            non_aligned_file.write(
                b"\x00" * data_length
            )  # data_length bytes, not aligned to 4096
            non_aligned_file_path = non_aligned_file.name

        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            # Test with --skip-padding
            output = self.run_espsecure(
                "sign-data --version 2 --skip-padding "
                f"--keyfile {self._get_imagepath(key)} "
                f"--output {output_file.name} "
                f"{non_aligned_file_path}"
            )

            # Verify that padding was skipped (check output message)
            assert "Skipping sector padding" in output

            # Verify file size: should be original size + signature sector (4096)
            with open(output_file.name, "rb") as f:
                signed_data = f.read()
            expected_size = data_length + SECTOR_SIZE  # original + signature sector
            assert len(signed_data) == expected_size

            # Verify the signed file can still be verified with --skip-padding
            self.run_espsecure(
                "verify-signature --version 2 --skip-padding "
                f"--keyfile {self._get_imagepath(key)} "
                f"{output_file.name}"
            )

        finally:
            os.unlink(non_aligned_file_path)
            os.unlink(output_file.name)

    def test_verify_signature_v2_skip_padding_file_too_small(self):
        """Test verify-signature with --skip-padding fails for files < 4096 bytes"""
        key = "rsa_secure_boot_signing_key.pem"

        # Create a file smaller than 4096 bytes
        with tempfile.NamedTemporaryFile(delete=False) as small_file:
            small_file.write(b"\x00" * 100)  # Only 100 bytes
            small_file_path = small_file.name

        try:
            with pytest.raises(subprocess.CalledProcessError) as cm:
                self.run_espsecure(
                    "verify-signature --version 2 --skip-padding "
                    f"--keyfile {self._get_imagepath(key)} "
                    f"{small_file_path}"
                )
            assert (
                "Invalid datafile. File too small (must be at least 4096 bytes)"
                in cm.value.output.decode("utf-8")
            )
        finally:
            os.unlink(small_file_path)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_multiple_keys_cli(self, scheme):
        keydir = os.path.join(TEST_DIR, "secure_images")
        with tempfile.NamedTemporaryFile(delete=False) as output_file:
            keyfiles = [
                os.path.join(keydir, f"{scheme}_secure_boot_signing_key.pem"),
                os.path.join(keydir, f"{scheme}_secure_boot_signing_key2.pem"),
                os.path.join(keydir, f"{scheme}_secure_boot_signing_key3.pem"),
            ]

            self.run_espsecure(
                f"sign-data --version 2 --keyfile {' '.join(keyfiles)} "
                f"--output {output_file.name} "
                f"{os.path.join(keydir, 'bootloader_unsigned_v2.bin')}"
            )
            self.run_espsecure(
                "verify-signature --version 2 --keyfile "
                f"{os.path.join(keydir, f'{scheme}_secure_boot_signing_key.pem')} "
                f"{output_file.name}"
            )
            self.run_espsecure(
                "verify-signature --version 2 --keyfile "
                f"{os.path.join(keydir, f'{scheme}_secure_boot_signing_key2.pem')} "
                f"{output_file.name}"
            )
            self.run_espsecure(
                "verify-signature --version 2 --keyfile "
                f"{os.path.join(keydir, f'{scheme}_secure_boot_signing_key3.pem')} "
                f"{output_file.name}"
            )

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_multiple_keys(self, scheme):
        # 3 keys + Verify with 3rd key
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            keyfiles = [
                self._get_imagepath(f"{scheme}_secure_boot_signing_key.pem"),
                self._get_imagepath(f"{scheme}_secure_boot_signing_key2.pem"),
                self._get_imagepath(f"{scheme}_secure_boot_signing_key3.pem"),
            ]

            self.run_espsecure(
                f"sign-data --version 2 "
                f"--keyfile {' '.join(keyfiles)} "
                f"--output {output_file.name} "
                f"{self._get_imagepath('bootloader_unsigned_v2.bin')}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key3.pem')} "
                f"{output_file.name}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key2.pem')} "
                f"{output_file.name}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key.pem')} "
                f"{output_file.name}"
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_append_signatures(self, scheme):
        # Append signatures + Verify with an appended key
        # (bootloader_signed_v2_rsa.bin already signed with
        # rsa_secure_boot_signing_key.pem)
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            keyfiles = [
                self._get_imagepath(f"{scheme}_secure_boot_signing_key2.pem"),
                self._get_imagepath(f"{scheme}_secure_boot_signing_key3.pem"),
            ]

            self.run_espsecure(
                f"sign-data --version 2 --append-signatures "
                f"--keyfile {' '.join(keyfiles)} "
                f"--output {output_file.name} "
                f"{self._get_imagepath(f'bootloader_signed_v2_{scheme}.bin')}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key.pem')} "
                f"{output_file.name}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key2.pem')} "
                f"{output_file.name}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key3.pem')} "
                f"{output_file.name}"
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_append_signatures_multiple_steps(self, scheme):
        # similar to previous test, but sign in two invocations
        try:
            output_file1 = tempfile.NamedTemporaryFile(delete=False)
            output_file2 = tempfile.NamedTemporaryFile(delete=False)
            output_file1.close()
            output_file2.close()

            self.run_espsecure(
                f"sign-data --version 2 --append-signatures "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key2.pem')} "
                f"--output {output_file1.name} "
                f"{self._get_imagepath(f'bootloader_signed_v2_{scheme}.bin')}"
            )

            self.run_espsecure(
                f"sign-data --version 2 --append-signatures "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key3.pem')} "
                f"--output {output_file2.name} {output_file1.name}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key.pem')} "
                f"{output_file2.name}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key2.pem')} "
                f"{output_file2.name}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key3.pem')} "
                f"{output_file2.name}"
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
            output_file.close()

            self.run_espsecure(
                f"sign-data --version 2 "
                f"--pub-key {self._get_imagepath(pub_key)} "
                f"--signature {self._get_imagepath(signature)} "
                f"--output {output_file.name} "
                f"{self._get_imagepath('bootloader_unsigned_v2.bin')}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile {self._get_imagepath(pub_key)} "
                f"{output_file.name}"
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_sign_v2_with_multiple_pre_calculated_signatures(self, scheme):
        # Sign using multiple pre-calculated signatures + Verify
        signing_pubkeys = [
            f"{scheme}_secure_boot_signing_pubkey.pem",
            f"{scheme}_secure_boot_signing_pubkey.pem",
            f"{scheme}_secure_boot_signing_pubkey.pem",
        ]
        pre_calculated_signatures = [
            f"pre_calculated_bootloader_signature_{scheme}.bin",
            f"pre_calculated_bootloader_signature_{scheme}.bin",
            f"pre_calculated_bootloader_signature_{scheme}.bin",
        ]
        try:
            output_file = tempfile.NamedTemporaryFile(delete=False)
            output_file.close()

            pubkey_args = " ".join(
                f"--pub-key {self._get_imagepath(pub_key)}"
                for pub_key in signing_pubkeys
            )
            signature_args = " ".join(
                f"--signature {self._get_imagepath(signature)}"
                for signature in pre_calculated_signatures
            )

            self.run_espsecure(
                f"sign-data --version 2 {pubkey_args} {signature_args} "
                f"--output {output_file.name} "
                f"{self._get_imagepath('bootloader_unsigned_v2.bin')}"
            )

            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile {self._get_imagepath(signing_pubkeys[0])} "
                f"{output_file.name}"
            )
        finally:
            output_file.close()
            os.unlink(output_file.name)

    @pytest.mark.parametrize(
        "version, keyfile, datafile",
        [
            ("1", "ecdsa256_secure_boot_signing_key.pem", "bootloader_signed.bin"),
            (
                "1",
                "ecdsa256_secure_boot_signing_pubkey_raw.bin",
                "bootloader_signed.bin",
            ),
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
        ids=[
            "v1_pem",
            "v1_raw",
            "v2_rsa",
            "v2_ecdsa384",
            "v2_ecdsa256",
            "v2_ecdsa192",
        ],
    )
    def test_verify_signature_correct_key(self, version, keyfile, datafile):
        self.run_espsecure(
            f"verify-signature --version {version} "
            f"--keyfile {self._get_imagepath(keyfile)} "
            f"{self._get_imagepath(datafile)}"
        )

    def test_verify_signature_wrong_key_v1(self):
        with pytest.raises(subprocess.CalledProcessError) as cm:
            self.run_espsecure(
                f"verify-signature --version 1 "
                f"--keyfile "
                f"{self._get_imagepath('ecdsa256_secure_boot_signing_key2.pem')} "
                f"{self._get_imagepath('bootloader_signed.bin')}"
            )
        assert "Signature is not valid" in cm.value.output.decode("utf-8")

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_verify_signature_wrong_key_v2(self, scheme):
        with pytest.raises(subprocess.CalledProcessError) as cm:
            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key2.pem')} "
                f"{self._get_imagepath(f'bootloader_signed_v2_{scheme}.bin')}"
            )
        assert (
            "Signature could not be verified with the provided key."
            in cm.value.output.decode("utf-8")
        )

    def test_verify_signature_wrong_scheme(self):
        with pytest.raises(subprocess.CalledProcessError) as cm:
            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath('ecdsa256_secure_boot_signing_key.pem')} "
                f"{self._get_imagepath('bootloader_signed.bin')}"
            )
        assert "Invalid datafile" in cm.value.output.decode("utf-8")

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_verify_signature_multi_signed_wrong_key(self, scheme):
        with pytest.raises(subprocess.CalledProcessError) as cm:
            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_key4.pem')} "
                f"{self._get_imagepath(f'bootloader_multi_signed_v2_{scheme}.bin')}"
            )
        assert (
            "Signature could not be verified with the provided key."
            in cm.value.output.decode("utf-8")
        )

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
        self.run_espsecure(
            f"verify-signature --version {version} "
            f"--keyfile {self._get_imagepath(keyfile)} "
            f"{self._get_imagepath(datafile)}"
        )

    def test_verify_signature_wrong_pubkey_v1(self):
        with pytest.raises(subprocess.CalledProcessError) as cm:
            self.run_espsecure(
                f"verify-signature --version 1 "
                f"--keyfile "
                f"{self._get_imagepath('ecdsa256_secure_boot_signing_pubkey2.pem')} "
                f"{self._get_imagepath('bootloader_signed.bin')}"
            )
        assert "Signature is not valid" in cm.value.output.decode("utf-8")

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_verify_signature_wrong_pubkey_v2(self, scheme):
        with pytest.raises(subprocess.CalledProcessError) as cm:
            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_pubkey2.pem')} "
                f"{self._get_imagepath(f'bootloader_signed_v2_{scheme}.bin')}"
            )
        assert (
            "Signature could not be verified with the provided key."
            in cm.value.output.decode("utf-8")
        )

    @pytest.mark.parametrize("scheme", ["rsa", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_verify_signature_multi_signed_wrong_pubkey(self, scheme):
        with pytest.raises(subprocess.CalledProcessError) as cm:
            self.run_espsecure(
                f"verify-signature --version 2 "
                f"--keyfile "
                f"{self._get_imagepath(f'{scheme}_secure_boot_signing_pubkey4.pem')} "
                f"{self._get_imagepath(f'bootloader_multi_signed_v2_{scheme}.bin')}"
            )
        assert (
            "Signature could not be verified with the provided key."
            in cm.value.output.decode("utf-8")
        )

    def test_extract_binary_public_key(self):
        with tempfile.TemporaryDirectory() as keydir:
            pub_keyfile_path = os.path.join(keydir, "pubkey1.bin")
            pub_keyfile2_path = os.path.join(keydir, "pubkey2.bin")

            self.run_espsecure(
                f"extract-public-key --version 1 "
                f"--keyfile "
                f"{self._get_imagepath('ecdsa256_secure_boot_signing_key.pem')} "
                f"{pub_keyfile_path}"
            )

            self.run_espsecure(
                f"extract-public-key --version 1 "
                f"--keyfile "
                f"{self._get_imagepath('ecdsa256_secure_boot_signing_key2.pem')} "
                f"{pub_keyfile2_path}"
            )

            # use correct extracted public key to verify
            self.run_espsecure(
                f"verify-signature --version 1 --keyfile {pub_keyfile_path} "
                f"{self._get_imagepath('bootloader_signed.bin')}"
            )

            # use wrong extracted public key to try and verify
            with pytest.raises(subprocess.CalledProcessError) as cm:
                self.run_espsecure(
                    f"verify-signature --version 1 --keyfile {pub_keyfile2_path} "
                    f"{self._get_imagepath('bootloader_signed.bin')}"
                )
            assert "Signature is not valid" in cm.value.output.decode("utf-8")

    @pytest.mark.parametrize("scheme", ["rsa3072", "ecdsa192", "ecdsa256", "ecdsa384"])
    def test_generate_and_extract_key_v2(self, scheme):
        with tempfile.TemporaryDirectory() as keydir:
            # keyfile cannot exist before generation -> tempfile.NamedTemporaryFile()
            # cannot be used for keyfile
            keyfile_name = os.path.join(keydir, "key.pem")
            pub_keyfile_name = os.path.join(keydir, "pubkey.pem")

            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme {scheme} {keyfile_name}"
            )

            self.run_espsecure(
                f"extract-public-key --version 2 "
                f"--keyfile {keyfile_name} {pub_keyfile_name}"
            )


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
        with tempfile.TemporaryDirectory() as tmpdir:
            ciphertext_path = os.path.join(tmpdir, "ciphertext.bin")
            plaintext_path = os.path.join(tmpdir, "plaintext.bin")

            # Build encrypt command
            encrypt_cmd = (
                f"encrypt-flash-data --keyfile {self._get_imagepath(key_path)} "
                f"--output {ciphertext_path} --address {offset}"
            )
            if flash_crypt_conf is not None:
                encrypt_cmd += f" --flash-crypt-conf {flash_crypt_conf}"
            if aes_xts:
                encrypt_cmd += " --aes-xts"
            encrypt_cmd += f" {self._get_imagepath(input_plaintext)}"

            self.run_espsecure(encrypt_cmd)

            # Verify encrypted content differs from original and matches expected
            with open(self._get_imagepath(input_plaintext), "rb") as orig:
                original_data = orig.read()
            with open(ciphertext_path, "rb") as cipher:
                cipher_data = cipher.read()
            with self._open(expected_ciphertext) as expected:
                expected_data = expected.read()

            assert original_data != cipher_data
            assert cipher_data == expected_data

            # Build decrypt command
            decrypt_cmd = (
                f"decrypt-flash-data --keyfile {self._get_imagepath(key_path)} "
                f"--output {plaintext_path} --address {offset}"
            )
            if flash_crypt_conf is not None:
                decrypt_cmd += f" --flash-crypt-conf {flash_crypt_conf}"
            if aes_xts:
                decrypt_cmd += " --aes-xts"
            decrypt_cmd += f" {ciphertext_path}"

            self.run_espsecure(decrypt_cmd)

            # Verify decrypted content matches original
            with open(plaintext_path, "rb") as decrypted:
                decrypted_data = decrypted.read()
            assert original_data == decrypted_data


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
            f"--keyfile {self._get_imagepath('ecdsa256_secure_boot_signing_key.pem')} "
            f"{outfile_name}"
        )

        with open(outfile_name, "rb") as f:
            assert f.read() == binascii.unhexlify(
                "7b7b53708fc89d5e0b2df2571fb8f9d778f61a422ff1101a22159c4b34aad0aa"
            )

    def test_digest_private_key_with_invalid_output(self, capsys):
        fname = self._get_imagepath("ecdsa256_secure_boot_signing_key.pem")

        with pytest.raises(subprocess.CalledProcessError):
            self.run_espsecure(f"digest-private-key --keyfile {fname} {fname}")
        output = capsys.readouterr().out
        assert "should not be the same!" in output


class TestSDCCertificate(EspSecureTestCase):
    def test_generate_sdc_cert(self):
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            # Generate ECDSA P-256 key
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {keyfile_name}"
            )

            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} "
                f"--output {output_file} "
                "--mac 00:11:22:33:44:55 --enable-jtag"
            )

            assert os.path.exists(output_file)
            # Header (20) + Body (416) + Nonce (32) = 468 bytes
            assert os.path.getsize(output_file) == 468

    def test_generate_sdc_cert_missing_args(self):
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {keyfile_name}"
            )
            # Test missing required --mac argument (when --chip-info is not provided)
            with pytest.raises(subprocess.CalledProcessError):
                self.run_espsecure(
                    f"generate-sdc-certificate --keyfile {keyfile_name}"
                )  # Missing --mac (required when --chip-info is not provided)

    def test_digest_sdc_public_key_from_private_key(self):
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            digest_file = os.path.join(keydir, "sdc_pub_key_digest.bin")
            # Generate ECDSA P-256 key
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {keyfile_name}"
            )

            # Generate public key digest from private key
            self.run_espsecure(
                f"digest-sdc-public-key --keyfile {keyfile_name} -o {digest_file}"
            )

            assert os.path.exists(digest_file)
            # SDC public key digest should be 32 bytes (SHA-256 hash)
            assert os.path.getsize(digest_file) == 32

    def test_digest_sdc_public_key_from_public_key(self):
        with tempfile.TemporaryDirectory() as keydir:
            private_keyfile = os.path.join(keydir, "sdc_key.pem")
            public_keyfile = os.path.join(keydir, "sdc_pub_key.pem")
            digest_file = os.path.join(keydir, "sdc_pub_key_digest.bin")
            # Generate ECDSA P-256 key
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {private_keyfile}"
            )

            # Extract public key
            self.run_espsecure(
                f"extract-public-key --version 2 --keyfile {private_keyfile} "
                f"{public_keyfile}"
            )

            # Generate public key digest from public key
            self.run_espsecure(
                f"digest-sdc-public-key --pub-key {public_keyfile} -o {digest_file}"
            )

            assert os.path.exists(digest_file)
            # SDC public key digest should be 32 bytes (SHA-256 hash)
            assert os.path.getsize(digest_file) == 32

    def test_digest_sdc_public_key_default_output(self):
        # The digest is written to the default path (sdc_pub_key_digest.bin in the
        # working directory, which is TEST_DIR for run_espsecure) when -o is omitted.
        default_digest_file = os.path.join(TEST_DIR, "sdc_pub_key_digest.bin")
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            # Generate ECDSA P-256 key
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {keyfile_name}"
            )

            try:
                # Generate public key digest without -o to exercise the default path
                self.run_espsecure(f"digest-sdc-public-key --keyfile {keyfile_name}")

                assert os.path.exists(default_digest_file)
                assert os.path.getsize(default_digest_file) == 32
            finally:
                if os.path.exists(default_digest_file):
                    os.unlink(default_digest_file)

    def test_digest_sdc_public_key_consistency(self):
        """Test that generating digest multiple times from same key produces same
        result."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            digest_file1 = os.path.join(keydir, "digest1.bin")
            digest_file2 = os.path.join(keydir, "digest2.bin")
            # Generate ECDSA P-256 key
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {keyfile_name}"
            )

            # Generate digest twice from same key
            self.run_espsecure(
                f"digest-sdc-public-key --keyfile {keyfile_name} -o {digest_file1}"
            )
            self.run_espsecure(
                f"digest-sdc-public-key --keyfile {keyfile_name} -o {digest_file2}"
            )

            # Both digests should exist and be identical
            assert os.path.exists(digest_file1)
            assert os.path.exists(digest_file2)
            with open(digest_file1, "rb") as f1, open(digest_file2, "rb") as f2:
                assert f1.read() == f2.read()

    def test_digest_sdc_public_key_private_matches_public(self):
        """Digest from a private key must match the digest from its own public
        key - both paths hash the same public point."""
        with tempfile.TemporaryDirectory() as keydir:
            private_keyfile = os.path.join(keydir, "sdc_key.pem")
            public_keyfile = os.path.join(keydir, "sdc_pub_key.pem")
            digest_from_priv = os.path.join(keydir, "digest_priv.bin")
            digest_from_pub = os.path.join(keydir, "digest_pub.bin")
            # Generate ECDSA P-256 key and extract its public key
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {private_keyfile}"
            )
            self.run_espsecure(
                f"extract-public-key --version 2 --keyfile {private_keyfile} "
                f"{public_keyfile}"
            )

            self.run_espsecure(
                "digest-sdc-public-key "
                f"--keyfile {private_keyfile} "
                f"-o {digest_from_priv}"
            )
            self.run_espsecure(
                f"digest-sdc-public-key --pub-key {public_keyfile} -o {digest_from_pub}"
            )

            with open(digest_from_priv, "rb") as f1, open(digest_from_pub, "rb") as f2:
                assert f1.read() == f2.read()

    def test_generate_sdc_cert_download_reuse(self):
        """The --enable-download-reuse flag produces a valid 468-byte cert."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self.run_espsecure(
                f"generate-signing-key --version 2 --scheme ecdsa256 {keyfile_name}"
            )

            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} "
                f"--output {output_file} "
                "--mac 00:11:22:33:44:55 --enable-download-reuse"
            )

            assert os.path.exists(output_file)
            # Header (20) + Body (416) + Nonce (32) = 468 bytes
            assert os.path.getsize(output_file) == 468

    # --- Helpers -----------------------------------------------------------

    def _gen_key(self, path, scheme="ecdsa256"):
        self.run_espsecure(f"generate-signing-key --version 2 --scheme {scheme} {path}")

    @staticmethod
    def _parse_sdc_cert(cert_bytes):
        """Unpack the on-wire SDC cert into its fields for structural checks.

        Layout: header(20) + body[usc(256)+pubkey(64)+r(32)+s(32)+hash(32)=416]
        + nonce(32) = 468 bytes. Mirrors espsecure.esp_sdc constants exactly so a
        silent format/packing regression is caught.
        """
        assert len(cert_bytes) == 468
        header = cert_bytes[:20]
        body = cert_bytes[20:436]
        nonce = cert_bytes[436:468]
        magic, version, _r1, usc_len, length, _r2, crc32, _r3 = struct.unpack(
            "<IBBHHHII", header
        )
        return {
            "magic": magic,
            "version": version,
            "usc_len": usc_len,
            "length": length,
            "crc32": crc32,
            "body": body,
            "usc_first_word": int.from_bytes(body[0:4], "big"),
            "nonce": nonce,
        }

    # --- Structural / correctness corner cases -----------------------------

    def test_generate_sdc_cert_structure_and_crc(self):
        """Minutely validate the generated certificate's binary structure:
        magic, version, declared lengths, body CRC32, and that the requested USC
        config bits (and only those) are set."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            # Enable JTAG (bit 0) and force-spi-boot (bit 2); leave reuse (bit 1) off
            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} --output {output_file} "
                "--mac 00:11:22:33:44:55 --enable-jtag --enable-force-spi-boot"
            )
            with open(output_file, "rb") as f:
                cert = f.read()

            fields = self._parse_sdc_cert(cert)
            assert fields["magic"] == 0x524D4143  # "RMAC"
            assert fields["version"] == 0x01
            assert fields["usc_len"] == 256
            assert fields["length"] == 436  # header + body, excludes nonce
            # CRC32 in header must match a fresh CRC of the body (ROM crc32_le init)
            expected_crc = zlib.crc32(fields["body"], 0xFFFFFFFF) & 0xFFFFFFFF
            assert fields["crc32"] == expected_crc
            # USC config bits: JTAG=bit0, download_reuse=bit1, force_spi_boot=bit2
            assert fields["usc_first_word"] & (1 << 0)  # JTAG on
            assert not fields["usc_first_word"] & (1 << 1)  # reuse off
            assert fields["usc_first_word"] & (1 << 2)  # force SPI boot on

    def test_generate_sdc_cert_no_flags_has_zero_usc(self):
        """With no --enable-* flags the USC config word must be all zeros."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} --output {output_file} "
                "--mac 00:11:22:33:44:55"
            )
            with open(output_file, "rb") as f:
                fields = self._parse_sdc_cert(f.read())
            assert fields["usc_first_word"] == 0

    def test_generate_sdc_digest_value_is_reversed_sha256(self):
        """The digest must be the byte-reversed SHA-256 of the 64-byte (x||y)
        public key - this is what gets burned to eFuse, so the exact bytes and
        byte order matter, not just the length."""
        from cryptography.hazmat.primitives import serialization

        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            digest_file = os.path.join(keydir, "digest.bin")
            self._gen_key(keyfile_name)
            self.run_espsecure(
                f"digest-sdc-public-key --keyfile {keyfile_name} -o {digest_file}"
            )

            with open(keyfile_name, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
            nums = priv.public_key().public_numbers()
            pubkey_bytes = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
            expected = hashlib.sha256(pubkey_bytes).digest()[::-1]

            with open(digest_file, "rb") as f:
                assert f.read() == expected

    # --- chip-info file path (the link to esptool read-sdc-chip-info) ---

    def test_generate_sdc_cert_from_chip_info_file(self):
        """--chip-info accepts the 64-byte (chip_info||nonce) file that
        `esptool read-sdc-chip-info` produces; the cert's trailing nonce must
        equal the file's last 32 bytes."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            chip_info_file = os.path.join(keydir, "chip_info.bin")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)

            chip_info = bytes(range(32))
            nonce = bytes(range(32, 64))
            with open(chip_info_file, "wb") as f:
                f.write(chip_info + nonce)

            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} --output {output_file} "
                f"--chip-info {chip_info_file}"
            )
            with open(output_file, "rb") as f:
                fields = self._parse_sdc_cert(f.read())
            # The nonce trailing the cert is taken verbatim from the chip-info file
            assert fields["nonce"] == nonce

    def test_generate_sdc_cert_chip_info_wrong_size(self):
        """A chip-info file that isn't exactly 64 bytes must be rejected."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            chip_info_file = os.path.join(keydir, "chip_info.bin")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            with open(chip_info_file, "wb") as f:
                f.write(bytes(63))  # one byte short

            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} "
                    f"--chip-info {chip_info_file}"
                )
            assert "Invalid chip_info file size" in exc.value.output.decode()

    # --- MAC parsing corner cases ------------------------------------------

    @pytest.mark.parametrize(
        "mac",
        ["00:11:22:33:44:55", "00-11-22-33-44-55", "001122334455"],
    )
    def test_generate_sdc_cert_mac_formats(self, mac):
        """colon / dash / continuous MAC formats are all accepted."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} --output {output_file} --mac {mac}"
            )
            assert os.path.getsize(output_file) == 468

    def test_generate_sdc_cert_bad_mac_length(self):
        """A MAC that isn't 6 bytes must be rejected."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} "
                    "--mac 00:11:22:33:44"  # only 5 bytes
                )
            out = exc.value.output.decode()
            assert "MAC" in out and "hex characters" in out

    # SDC_SESSION_COUNTER is a 3-bit write-only eFuse whose bits burn 0->1, so it
    # can only ever hold 0, 1, 3 or 7. 2/4/5/6 are in the 3-bit range but are
    # unreachable under monotonic burning; 8+ is out of range entirely.
    @pytest.mark.parametrize("counter", [2, 4, 5, 6, 8, 256])
    def test_generate_sdc_cert_session_counter_invalid(self, counter):
        """Only 0, 1, 3, 7 are valid; everything else must be rejected."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} "
                    f"--mac 00:11:22:33:44:55 --sdc-session-counter {counter}"
                )
            assert "session counter" in exc.value.output.decode()

    @pytest.mark.parametrize("counter", [0, 1, 3, 7])
    def test_generate_sdc_cert_session_counter_valid(self, counter):
        """The 4 monotonic-reachable counter values all produce a valid cert."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} --output {output_file} "
                f"--mac 00:11:22:33:44:55 --sdc-session-counter {counter}"
            )
            assert os.path.getsize(output_file) == 468

    # --- Wrong key type / curve (negative) ---------------------------------

    def test_generate_sdc_cert_rejects_rsa_key(self):
        """RSA keys are not valid for SDC certificates."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "rsa_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name, scheme="rsa3072")
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} "
                    "--mac 00:11:22:33:44:55"
                )
            assert "ECDSA" in exc.value.output.decode()

    @pytest.mark.parametrize("scheme", ["ecdsa192", "ecdsa384"])
    def test_generate_sdc_cert_rejects_wrong_curve(self, scheme):
        """Only SECP256R1 (P-256) keys are valid; other curves must be rejected."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "ec_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name, scheme=scheme)
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} "
                    "--mac 00:11:22:33:44:55"
                )
            out = exc.value.output.decode()
            assert "SECP256R1" in out or "Unsupported curve" in out

    def test_generate_sdc_digest_rejects_rsa_key(self):
        """The digest command must also reject non-ECDSA keys."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "rsa_key.pem")
            digest_file = os.path.join(keydir, "digest.bin")
            self._gen_key(keyfile_name, scheme="rsa3072")
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    f"digest-sdc-public-key --keyfile {keyfile_name} -o {digest_file}"
                )
            assert "ECDSA" in exc.value.output.decode()

    # --- USC JSON config (positive + negative) -----------------------------

    def test_generate_sdc_cert_usc_json_overrides_flags(self):
        """A --usc JSON file drives the USC config bits."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            usc_file = os.path.join(keydir, "usc.json")
            self._gen_key(keyfile_name)
            with open(usc_file, "w") as f:
                json.dump(
                    {
                        "version": 1,
                        "groups": [
                            {
                                "group": "config_flags",
                                "entries": [
                                    {"key": "enable_jtag", "value": True},
                                    {
                                        "key": "enable_download_reuse",
                                        "value": True,
                                    },
                                    {
                                        "key": "enable_force_spi_boot",
                                        "value": False,
                                    },
                                ],
                            }
                        ],
                    },
                    f,
                )
            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} --output {output_file} "
                f"--mac 00:11:22:33:44:55 --usc {usc_file}"
            )
            with open(output_file, "rb") as f:
                fields = self._parse_sdc_cert(f.read())
            assert fields["usc_first_word"] & (1 << 0)  # JTAG
            assert fields["usc_first_word"] & (1 << 1)  # download reuse
            assert not fields["usc_first_word"] & (1 << 2)  # force SPI boot off

    def test_generate_sdc_cert_usc_json_invalid(self):
        """Malformed USC JSON must be reported, not silently ignored."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            usc_file = os.path.join(keydir, "usc.json")
            self._gen_key(keyfile_name)
            with open(usc_file, "w") as f:
                f.write("{ this is not valid json ")
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} "
                    f"--mac 00:11:22:33:44:55 --usc {usc_file}"
                )
            assert "JSON" in exc.value.output.decode()

    def test_generate_sdc_cert_usc_json_bad_boolean(self):
        """Non-boolean config flag values must be rejected."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            usc_file = os.path.join(keydir, "usc.json")
            self._gen_key(keyfile_name)
            with open(usc_file, "w") as f:
                json.dump(
                    {
                        "version": 1,
                        "groups": [
                            {
                                "group": "config_flags",
                                "entries": [{"key": "enable_jtag", "value": "yes"}],
                            }
                        ],
                    },
                    f,
                )
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} "
                    f"--mac 00:11:22:33:44:55 --usc {usc_file}"
                )
            assert "boolean" in exc.value.output.decode()

    def test_generate_sdc_cert_usc_json_wrong_version(self):
        """A USC JSON file without the supported version must be rejected."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            usc_file = os.path.join(keydir, "usc.json")
            self._gen_key(keyfile_name)
            with open(usc_file, "w") as f:
                # Old, unversioned layout is no longer accepted.
                json.dump({"config_flags": {"enable_jtag": True}}, f)
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} "
                    f"--mac 00:11:22:33:44:55 --usc {usc_file}"
                )
            assert "version" in exc.value.output.decode()

    # --- Mutually-exclusive / missing-input guards -------------------------

    def test_generate_sdc_digest_no_input(self):
        """The digest command requires at least one key source."""
        with tempfile.TemporaryDirectory() as keydir:
            digest_file = os.path.join(keydir, "digest.bin")
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(f"digest-sdc-public-key -o {digest_file}")
            # Assert the specific guard fired (not just any failure). The click
            # error is rendered in a Rich box and line-wrapped, so match only a
            # short contiguous fragment that survives wrapping at any width.
            assert "must be provided" in exc.value.output.decode()

    def test_generate_sdc_digest_multiple_inputs(self):
        """Supplying both --keyfile and --pub-key must be rejected."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            public_keyfile = os.path.join(keydir, "sdc_pub_key.pem")
            digest_file = os.path.join(keydir, "digest.bin")
            self._gen_key(keyfile_name)
            self.run_espsecure(
                f"extract-public-key --version 2 --keyfile {keyfile_name} "
                f"{public_keyfile}"
            )
            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "digest-sdc-public-key "
                    f"--keyfile {keyfile_name} --pub-key {public_keyfile} "
                    f"-o {digest_file}"
                )
            # Short fragment to survive Rich-box line wrapping (see no_input test).
            assert "can be provided" in exc.value.output.decode()

    # --- MAC supplied as a file (_parse_input_data file-path branch) --------

    def test_generate_sdc_cert_mac_from_bin_file(self):
        """--mac accepts a 6-byte binary (.bin) file (file-path branch of
        _parse_input_data), producing a valid 468-byte certificate."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            mac_file = os.path.join(keydir, "mac.bin")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            with open(mac_file, "wb") as f:
                f.write(bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))

            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} --output {output_file} --mac {mac_file}"
            )
            with open(output_file, "rb") as f:
                # Structurally valid cert (also asserts the 468-byte length)
                self._parse_sdc_cert(f.read())

    def test_generate_sdc_cert_mac_from_hex_file(self):
        """--mac accepts a hex-text (.hex) file (file-path branch of
        _parse_input_data), producing a valid 468-byte certificate."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            mac_file = os.path.join(keydir, "mac.hex")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            with open(mac_file, "w") as f:
                f.write("00:11:22:33:44:55\n")  # separators exercise normalization

            self.run_espsecure(
                "generate-sdc-certificate "
                f"--keyfile {keyfile_name} --output {output_file} --mac {mac_file}"
            )
            with open(output_file, "rb") as f:
                self._parse_sdc_cert(f.read())

    def test_generate_sdc_cert_mac_bin_file_wrong_size(self):
        """A binary MAC file that isn't exactly 6 bytes must be rejected."""
        with tempfile.TemporaryDirectory() as keydir:
            keyfile_name = os.path.join(keydir, "sdc_key.pem")
            mac_file = os.path.join(keydir, "mac.bin")
            output_file = os.path.join(keydir, "sdc_cert.bin")
            self._gen_key(keyfile_name)
            with open(mac_file, "wb") as f:
                f.write(bytes(5))  # one byte short

            with pytest.raises(subprocess.CalledProcessError) as exc:
                self.run_espsecure(
                    "generate-sdc-certificate "
                    f"--keyfile {keyfile_name} --output {output_file} --mac {mac_file}"
                )
            out = exc.value.output.decode()
            assert "MAC" in out and "file size" in out
