# Tests for espsecure using the pytest framework
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
