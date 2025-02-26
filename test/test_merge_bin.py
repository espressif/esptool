import filecmp
import hashlib
import itertools
import os
import os.path
import random
import struct
import subprocess
import sys
import tempfile
from functools import partial

IMAGES_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "images")

from conftest import need_to_install_package_err

import pytest

try:
    from esptool.util import byte
    from esptool.uf2_writer import UF2Writer
    from esptool.targets import CHIP_DEFS
except ImportError:
    need_to_install_package_err()


def read_image(filename):
    with open(os.path.join(IMAGES_DIR, filename), "rb") as f:
        return f.read()


@pytest.mark.host_test
class TestMergeBin:
    def run_merge_bin(self, chip, offsets_names, options=[], allow_warnings=False):
        """Run merge_bin on a list of (offset, filename) tuples
        with output to a named temporary file.

        Filenames are relative to the 'test/images' directory.

        Returns the contents of the merged file if successful.
        """
        output_file = tempfile.NamedTemporaryFile(delete=False)
        try:
            output_file.close()

            cmd = [
                sys.executable,
                "-m",
                "esptool",
                "--chip",
                chip,
                "merge_bin",
                "-o",
                output_file.name,
            ] + options
            for offset, name in offsets_names:
                cmd += [hex(offset), name]
            print("\nExecuting {}".format(" ".join(cmd)))

            output = subprocess.check_output(
                cmd, cwd=IMAGES_DIR, stderr=subprocess.STDOUT
            )
            output = output.decode("utf-8")
            print(output)
            if not allow_warnings:
                assert "warning" not in output.lower(), (
                    "merge_bin should not output warnings"
                )

            with open(output_file.name, "rb") as f:
                return f.read()
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise
        finally:
            os.unlink(output_file.name)

    def assertAllFF(self, some_bytes):
        # this may need some improving as the failed assert messages may be
        # very long and/or useless!
        assert b"\xff" * len(some_bytes) == some_bytes

    def test_simple_merge(self):
        merged = self.run_merge_bin(
            "esp8266",
            [(0x0, "one_kb.bin"), (0x1000, "one_kb.bin"), (0x10000, "one_kb.bin")],
        )
        one_kb = read_image("one_kb.bin")

        assert len(one_kb) == 0x400

        assert len(merged) == 0x10400
        assert merged[:0x400] == one_kb
        assert merged[0x1000:0x1400] == one_kb
        assert merged[0x10000:] == one_kb

        self.assertAllFF(merged[0x400:0x1000])
        self.assertAllFF(merged[0x1400:0x10000])

    def test_args_out_of_order(self):
        # no matter which order we supply arguments, the output should be the same
        args = [(0x0, "one_kb.bin"), (0x1000, "one_kb.bin"), (0x10000, "one_kb.bin")]
        merged_orders = [
            self.run_merge_bin("esp8266", perm_args)
            for perm_args in itertools.permutations(args)
        ]
        for m in merged_orders:
            assert m == merged_orders[0]

    def test_error_overlap(self, capsys):
        args = [(0x1000, "one_mb.bin"), (0x20000, "one_kb.bin")]
        for perm_args in itertools.permutations(args):
            with pytest.raises(subprocess.CalledProcessError):
                self.run_merge_bin("esp32", perm_args)
            output = capsys.readouterr().out
            assert "overlap" in output

    def test_leading_padding(self):
        merged = self.run_merge_bin("esp32c3", [(0x100000, "one_mb.bin")])
        self.assertAllFF(merged[:0x100000])
        assert read_image("one_mb.bin") == merged[0x100000:]

    def test_update_bootloader_params(self):
        merged = self.run_merge_bin(
            "esp32",
            [
                (0x1000, "bootloader_esp32.bin"),
                (0x10000, "ram_helloworld/helloworld-esp32.bin"),
            ],
            ["--flash_size", "2MB", "--flash_mode", "dout"],
        )
        self.assertAllFF(merged[:0x1000])

        bootloader = read_image("bootloader_esp32.bin")
        helloworld = read_image("ram_helloworld/helloworld-esp32.bin")

        # test the bootloader is unchanged apart from the header
        # (updating the header doesn't change CRC,
        # and doesn't update the SHA although it will invalidate it!)
        assert merged[0x1010 : 0x1000 + len(bootloader)] == bootloader[0x10:]

        # check the individual bytes in the header are as expected
        merged_hdr = merged[0x1000:0x1010]
        bootloader_hdr = bootloader[:0x10]
        assert bootloader_hdr[:2] == merged_hdr[:2]
        assert byte(merged_hdr, 2) == 3  # flash mode dout
        assert byte(merged_hdr, 3) & 0xF0 == 0x10  # flash size 2MB (ESP32)
        # flash freq is unchanged
        assert byte(bootloader_hdr, 3) & 0x0F == byte(merged_hdr, 3) & 0x0F
        assert bootloader_hdr[4:] == merged_hdr[4:]  # remaining field are unchanged

        # check all the padding is as expected
        self.assertAllFF(merged[0x1000 + len(bootloader) : 0x10000])
        assert merged[0x10000 : 0x10000 + len(helloworld)], helloworld

    def test_target_offset(self):
        merged = self.run_merge_bin(
            "esp32",
            [
                (0x1000, "bootloader_esp32.bin"),
                (0x10000, "ram_helloworld/helloworld-esp32.bin"),
            ],
            ["--target-offset", "0x1000"],
        )

        bootloader = read_image("bootloader_esp32.bin")
        helloworld = read_image("ram_helloworld/helloworld-esp32.bin")
        assert bootloader == merged[: len(bootloader)]
        assert helloworld == merged[0xF000 : 0xF000 + len(helloworld)]
        self.assertAllFF(merged[0x1000 + len(bootloader) : 0xF000])

    def test_pad_to_size(self):
        merged = self.run_merge_bin(
            "esp32c3", [(0x0, "bootloader_esp32c3.bin")], ["--pad-to-size", "4MB"]
        )
        bootloader = read_image("bootloader_esp32c3.bin")

        assert len(merged) == 0x400000
        assert bootloader == merged[: len(bootloader)]
        self.assertAllFF(merged[len(bootloader) :])

    def test_pad_to_size_w_target_offset(self):
        merged = self.run_merge_bin(
            "esp32",
            [
                (0x1000, "bootloader_esp32.bin"),
                (0x10000, "ram_helloworld/helloworld-esp32.bin"),
            ],
            ["--target-offset", "0x1000", "--pad-to-size", "2MB"],
        )

        # full length is without target-offset arg
        assert len(merged) == 0x200000 - 0x1000

        bootloader = read_image("bootloader_esp32.bin")
        helloworld = read_image("ram_helloworld/helloworld-esp32.bin")
        assert bootloader == merged[: len(bootloader)]
        assert helloworld == merged[0xF000 : 0xF000 + len(helloworld)]
        self.assertAllFF(merged[0xF000 + len(helloworld) :])

    def test_merge_mixed(self):
        # convert bootloader to hex
        hex = self.run_merge_bin(
            "esp32",
            [(0x1000, "bootloader_esp32.bin")],
            options=["--format", "hex"],
            allow_warnings=True,
        )
        # create a temp file with hex content
        with tempfile.NamedTemporaryFile(suffix=".hex", delete=False) as f:
            f.write(hex)
        # merge hex file with bin file
        # output to bin file should be the same as in merge bin + bin
        try:
            merged = self.run_merge_bin(
                "esp32",
                [(0x1000, f.name), (0x10000, "ram_helloworld/helloworld-esp32.bin")],
                ["--target-offset", "0x1000", "--pad-to-size", "2MB"],
            )
        finally:
            os.unlink(f.name)
        # full length is without target-offset arg
        assert len(merged) == 0x200000 - 0x1000

        bootloader = read_image("bootloader_esp32.bin")
        helloworld = read_image("ram_helloworld/helloworld-esp32.bin")
        assert bootloader == merged[: len(bootloader)]
        assert helloworld == merged[0xF000 : 0xF000 + len(helloworld)]
        self.assertAllFF(merged[0xF000 + len(helloworld) :])

    def test_merge_bin2hex(self):
        merged = self.run_merge_bin(
            "esp32",
            [
                (0x1000, "bootloader_esp32.bin"),
            ],
            options=["--format", "hex"],
            allow_warnings=True,
        )
        lines = merged.splitlines()
        # hex format - :0300300002337A1E
        # :03          0030  00    02337A 1E
        #  ^data_cnt/2 ^addr ^type ^data  ^checksum

        # check for starting address - 0x1000 passed from arg
        assert lines[0][3:7] == b"1000"
        # pick a random line for testing the format
        line = lines[random.randrange(0, len(lines))]
        assert line[0] == ord(":")
        data_len = int(b"0x" + line[1:3], 16)
        # : + len + addr + type + data + checksum
        assert len(line) == 1 + 2 + 4 + 2 + data_len * 2 + 2
        # last line is always :00000001FF
        assert lines[-1] == b":00000001FF"
        # convert back and verify the result against the source bin file
        with tempfile.NamedTemporaryFile(suffix=".hex", delete=False) as hex:
            hex.write(merged)
        merged_bin = self.run_merge_bin(
            "esp32",
            [(0x1000, hex.name)],
            options=["--format", "raw"],
        )
        source = read_image("bootloader_esp32.bin")
        # verify that padding was done correctly
        assert b"\xff" * 0x1000 == merged_bin[:0x1000]
        # verify the file itself
        assert source == merged_bin[0x1000:]

    def test_hex_header_raw_file(self):
        # use raw binary file starting with colon
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b":")
        try:
            merged = self.run_merge_bin("esp32", [(0x0, f.name)])
            assert merged == b":"
        finally:
            os.unlink(f.name)


class UF2Block(object):
    def __init__(self, bs):
        self.length = len(bs)

        # See https://github.com/microsoft/uf2 for the format
        first_part = "<" + "I" * 8
        # payload is between
        last_part = "<I"

        first_part_len = struct.calcsize(first_part)
        last_part_len = struct.calcsize(last_part)

        (
            self.magicStart0,
            self.magicStart1,
            self.flags,
            self.targetAddr,
            self.payloadSize,
            self.blockNo,
            self.numBlocks,
            self.familyID,
        ) = struct.unpack(first_part, bs[:first_part_len])

        self.data = bs[first_part_len:-last_part_len]

        (self.magicEnd,) = struct.unpack(last_part, bs[-last_part_len:])

    def __len__(self):
        return self.length


class UF2BlockReader(object):
    def __init__(self, f_name):
        self.f_name = f_name

    def get(self):
        with open(self.f_name, "rb") as f:
            for chunk in iter(partial(f.read, UF2Writer.UF2_BLOCK_SIZE), b""):
                yield UF2Block(chunk)


class BinaryWriter(object):
    def __init__(self, f_name):
        self.f_name = f_name

    def append(self, data):
        # File is reopened several times in order to make sure that won't left open
        with open(self.f_name, "ab") as f:
            f.write(data)


@pytest.mark.host_test
class TestUF2:
    def generate_binary(self, size):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            for _ in range(size):
                f.write(struct.pack("B", random.randrange(0, 1 << 7)))
            return f.name

    @staticmethod
    def generate_chipID():
        chip, rom = random.choice(list(CHIP_DEFS.items()))
        family_id = rom.UF2_FAMILY_ID
        return chip, family_id

    def generate_uf2(
        self,
        of_name,
        chip_id,
        iter_addr_offset_tuples,
        chunk_size=None,
        md5_enable=True,
    ):
        com_args = [
            sys.executable,
            "-m",
            "esptool",
            "--chip",
            chip_id,
            "merge_bin",
            "--format",
            "uf2",
            "-o",
            of_name,
        ]
        if not md5_enable:
            com_args.append("--md5-disable")
        com_args += [] if chunk_size is None else ["--chunk-size", str(chunk_size)]
        file_args = list(
            itertools.chain(*[(hex(addr), f) for addr, f in iter_addr_offset_tuples])
        )

        output = subprocess.check_output(com_args + file_args, stderr=subprocess.STDOUT)
        output = output.decode("utf-8")
        print(output)
        assert "warning" not in output.lower(), "merge_bin should not output warnings"

        exp_list = [f"Adding {f} at {hex(addr)}" for addr, f in iter_addr_offset_tuples]
        exp_list += [
            f"bytes to file {of_name}, ready to be flashed with any ESP USB Bridge"
        ]
        for e in exp_list:
            assert e in output

        return of_name

    def process_blocks(self, uf2block, expected_chip_id, md5_enable=True):
        flags = UF2Writer.UF2_FLAG_FAMILYID_PRESENT
        if md5_enable:
            flags |= UF2Writer.UF2_FLAG_MD5_PRESENT

        parsed_binaries = []

        block_list = []  # collect block numbers here
        total_blocks = set()  # collect total block numbers here
        for block in UF2BlockReader(uf2block).get():
            if block.blockNo == 0:
                # new file has been detected
                base_addr = block.targetAddr
                current_addr = base_addr
                binary_writer = BinaryWriter(self.generate_binary(0))

            assert len(block) == UF2Writer.UF2_BLOCK_SIZE
            assert block.magicStart0 == UF2Writer.UF2_FIRST_MAGIC
            assert block.magicStart1 == UF2Writer.UF2_SECOND_MAGIC
            assert block.flags & flags == flags

            assert len(block.data) == UF2Writer.UF2_DATA_SIZE
            payload = block.data[: block.payloadSize]
            if md5_enable:
                md5_obj = hashlib.md5(payload)
                md5_part = block.data[
                    block.payloadSize : block.payloadSize + UF2Writer.UF2_MD5_PART_SIZE
                ]
                address, length = struct.unpack("<II", md5_part[: -md5_obj.digest_size])
                md5sum = md5_part[-md5_obj.digest_size :]
                assert address == block.targetAddr
                assert length == block.payloadSize
                assert md5sum == md5_obj.digest()

            assert block.familyID == expected_chip_id
            assert block.magicEnd == UF2Writer.UF2_FINAL_MAGIC

            assert current_addr == block.targetAddr
            binary_writer.append(payload)

            block_list.append(block.blockNo)
            total_blocks.add(block.numBlocks)
            if block.blockNo == block.numBlocks - 1:
                assert block_list == list(range(block.numBlocks))
                # we have found all blocks and in the right order
                assert total_blocks == {
                    block.numBlocks
                }  # numBlocks are the same in all the blocks
                del block_list[:]
                total_blocks.clear()

                parsed_binaries += [(base_addr, binary_writer.f_name)]

            current_addr += block.payloadSize
        return parsed_binaries

    def common(self, t, chunk_size=None, md5_enable=True):
        of_name = self.generate_binary(0)
        try:
            chip_name, chip_id = self.generate_chipID()
            self.generate_uf2(of_name, chip_name, t, chunk_size, md5_enable)
            parsed_t = self.process_blocks(of_name, chip_id, md5_enable)

            assert len(t) == len(parsed_t)
            for (orig_addr, orig_fname), (addr, fname) in zip(t, parsed_t):
                assert orig_addr == addr
                assert filecmp.cmp(orig_fname, fname)
        finally:
            os.unlink(of_name)
            for _, file_name in t:
                os.unlink(file_name)

    def test_simple(self):
        self.common([(0, self.generate_binary(1))])

    def test_more_files(self):
        self.common(
            [(0x100, self.generate_binary(1)), (0x1000, self.generate_binary(1))]
        )

    def test_larger_files(self):
        self.common(
            [(0x100, self.generate_binary(6)), (0x1000, self.generate_binary(8))]
        )

    def test_boundaries(self):
        self.common(
            [
                (0x100, self.generate_binary(UF2Writer.UF2_DATA_SIZE)),
                (0x2000, self.generate_binary(UF2Writer.UF2_DATA_SIZE + 1)),
                (0x3000, self.generate_binary(UF2Writer.UF2_DATA_SIZE - 1)),
            ]
        )

    def test_files_with_more_blocks(self):
        self.common(
            [
                (0x100, self.generate_binary(3 * UF2Writer.UF2_DATA_SIZE)),
                (0x2000, self.generate_binary(2 * UF2Writer.UF2_DATA_SIZE + 1)),
                (0x3000, self.generate_binary(2 * UF2Writer.UF2_DATA_SIZE - 1)),
            ]
        )

    def test_very_large_files(self):
        self.common(
            [
                (0x100, self.generate_binary(20 * UF2Writer.UF2_DATA_SIZE + 5)),
                (0x10000, self.generate_binary(50 * UF2Writer.UF2_DATA_SIZE + 100)),
                (0x100000, self.generate_binary(100 * UF2Writer.UF2_DATA_SIZE)),
            ]
        )

    def test_chunk_size(self):
        chunk_size = 256
        self.common(
            [
                (0x1000, self.generate_binary(chunk_size)),
                (0x2000, self.generate_binary(chunk_size + 1)),
                (0x3000, self.generate_binary(chunk_size - 1)),
            ],
            chunk_size,
        )

    def test_md5_disable(self):
        self.common(
            [(0x100, self.generate_binary(1)), (0x2000, self.generate_binary(1))],
            md5_enable=False,
        )
