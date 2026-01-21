# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Hardware tests for NAND flash (ESP32-S3 + W25N01GVZEIG).

Requires: ESPTOOL_TEST_NAND=1
Optional: ESPTOOL_TEST_NAND_PORT (default /dev/ttyACM0)
          ESPTOOL_TEST_SPI_CONN (default 12,13,11,9,10)
"""

import os
import re
import struct
import subprocess
import tempfile

import pytest

# ---------------------------------------------------------------------------
# CI gate: skip all tests unless NAND hardware is available.
# Enable in CI by setting ESPTOOL_TEST_NAND=1.
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.skipif(
    os.environ.get("ESPTOOL_TEST_NAND") != "1",
    reason="NAND hardware tests require ESP32-S3 + W25N01GV NAND chip. "
    "Set ESPTOOL_TEST_NAND=1 to enable.",
)

# ---------------------------------------------------------------------------
# Hardware configuration (override via env vars)
# ---------------------------------------------------------------------------

PORT = os.environ.get("ESPTOOL_TEST_NAND_PORT", "/dev/ttyACM0")
SPI_CONN = os.environ.get("ESPTOOL_TEST_SPI_CONN", "12,13,11,9,10")
CHIP = "esp32s3"

PAGE_SIZE = 2048
PAGES_PER_BLOCK = 64
BLOCK_SIZE = PAGE_SIZE * PAGES_PER_BLOCK  # 131 072 = 0x20000

# Block 1 (0x20000) — spare-area tests
SPARE_BLOCK = 1
SPARE_PAGE = SPARE_BLOCK * PAGES_PER_BLOCK  # page 64

# Blocks 2–9 (0x40000–0x13FFFF) — all read/write/erase tests
TEST_OFFSET = 2 * BLOCK_SIZE  # 0x40000

# Expected JEDEC ID: Winbond W25N01GVZEIG
JEDEC_MFR = 0xEF
JEDEC_DEV = 0xAA21

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _env():
    env = os.environ.copy()
    env["ESPTOOL_STUB_VERSION"] = "2"
    return env


def esptool(*args, check=True):
    """Run esptool and return CompletedProcess.

    Raises on non-zero exit if check=True.
    """
    cmd = ["esptool", "--chip", CHIP, "--port", PORT] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, env=_env())
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd, output=result.stdout, stderr=result.stderr
        )
    return result


def erase_region(offset, size=BLOCK_SIZE):
    esptool(
        "erase-region",
        "--flash-type",
        "nand",
        "--spi-connection",
        SPI_CONN,
        hex(offset),
        hex(size),
    )


def write_nand(offset, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(data)
        fname = f.name
    try:
        esptool(
            "write-flash",
            "--flash-type",
            "nand",
            "--spi-connection",
            SPI_CONN,
            hex(offset),
            fname,
        )
    finally:
        os.unlink(fname)


def read_nand(offset, size) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        fname = f.name
    try:
        esptool(
            "read-flash",
            "--flash-type",
            "nand",
            "--spi-connection",
            SPI_CONN,
            hex(offset),
            str(size),
            fname,
        )
        with open(fname, "rb") as f:
            return f.read()
    finally:
        os.unlink(fname)


def verify_nand(offset, data: bytes) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(data)
        fname = f.name
    try:
        return esptool(
            "verify-flash",
            "--flash-type",
            "nand",
            "--spi-connection",
            SPI_CONN,
            hex(offset),
            fname,
        )
    finally:
        os.unlink(fname)


def parse_spare_value(stdout: str) -> int:
    """Extract the integer spare value from a read-nand-spare output line.

    Matches: NAND spare for page N: first word 0xXXXXXXXX ...
    Returns the first word as an integer.
    """
    m = re.search(r"NAND spare for page \d+: first word (0x[0-9a-fA-F]+)", stdout)
    assert m, f"Could not find spare data in output:\n{stdout}"
    return int(m.group(1), 16)


def first_diff(a: bytes, b: bytes) -> int:
    """Return index of first differing byte, or -1 if equal."""
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return -1 if len(a) == len(b) else min(len(a), len(b))


def xorshift_bytes(n: int, seed: int = 0xDEADBEEF) -> bytes:
    """Generate n pseudo-random bytes via xorshift32 (deterministic)."""
    state = seed & 0xFFFFFFFF
    out = bytearray(n)
    i = 0
    while i < n:
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= (state >> 17) & 0xFFFFFFFF
        state ^= (state << 5) & 0xFFFFFFFF
        word = struct.pack("<I", state)
        chunk = min(4, n - i)
        out[i : i + chunk] = word[:chunk]
        i += chunk
    return bytes(out)


# ---------------------------------------------------------------------------
# Attach / JEDEC ID
# ---------------------------------------------------------------------------


class TestAttach:
    """Verify the NAND chip initialises correctly."""

    def test_jedec_manufacturer_id(self):
        """Manufacturer ID must be 0xEF (Winbond); visible at --trace level."""
        result = esptool(
            "--trace", "read-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE)
        )
        assert f"mfr={JEDEC_MFR:#04x}" in result.stdout, result.stdout

    def test_jedec_device_id(self):
        """Device ID must be 0xAA21 (W25N01GVZEIG); visible at --trace level."""
        result = esptool(
            "--trace", "read-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE)
        )
        assert f"dev={JEDEC_DEV:#06x}" in result.stdout, result.stdout

    def test_status_register_clear_after_attach(self):
        """Status register must be 0x00 after attach (no pending errors).

        The debug line is only emitted at trace level; verify by running with
        --trace and checking the trace output contains status=0x00.
        """
        result = esptool(
            "--trace", "read-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE)
        )
        assert "status=0x00" in result.stdout, result.stdout

    def test_protect_register_cleared(self):
        """Protection-register readback must be 0x00 (all blocks unlocked).

        When prot=0x00 the warning is absent; when non-zero a warning is printed.
        Verify no protection-register warning appears.
        """
        result = esptool(
            "read-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE)
        )
        assert "NAND protection register" not in result.stdout, result.stdout


# ---------------------------------------------------------------------------
# Spare area (OOB)
# ---------------------------------------------------------------------------


class TestSpareArea:
    """Read and write the spare (OOB) byte of NAND pages."""

    def test_read_spare_after_erase_is_ff(self):
        """Fresh-erased page spare must read 0xFFFF."""
        erase_region(SPARE_BLOCK * BLOCK_SIZE)
        result = esptool(
            "read-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE)
        )
        assert "0xffff" in result.stdout.lower(), result.stdout

    def test_mark_good_reads_ff(self):
        """Writing is_bad=0 (good marker 0xFF) → spare reads 0xFFFF."""
        erase_region(SPARE_BLOCK * BLOCK_SIZE)
        esptool("write-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE), "0")
        result = esptool(
            "read-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE)
        )
        assert "0xffff" in result.stdout.lower(), result.stdout

    def test_mark_bad_reads_zero(self):
        """Writing is_bad=1 (bad marker 0x00) → spare reads 0x0000."""
        erase_region(SPARE_BLOCK * BLOCK_SIZE)
        esptool("write-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE), "1")
        result = esptool(
            "read-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE)
        )
        assert parse_spare_value(result.stdout) == 0, result.stdout

    def test_erase_resets_bad_marker(self):
        """Block erase restores a bad-marked page's spare to 0xFFFF."""
        erase_region(SPARE_BLOCK * BLOCK_SIZE)
        esptool("write-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE), "1")
        erase_region(SPARE_BLOCK * BLOCK_SIZE)
        result = esptool(
            "read-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE)
        )
        assert "0xffff" in result.stdout.lower(), result.stdout

    def test_multiple_pages_in_block_independent(self):
        """Spare areas of different pages in the same block are independent."""
        erase_region(SPARE_BLOCK * BLOCK_SIZE)
        page_a = SPARE_PAGE
        page_b = SPARE_PAGE + 1
        # Mark page_a bad, leave page_b untouched
        esptool("write-nand-spare", "--spi-connection", SPI_CONN, str(page_a), "1")
        ra = esptool("read-nand-spare", "--spi-connection", SPI_CONN, str(page_a))
        rb = esptool("read-nand-spare", "--spi-connection", SPI_CONN, str(page_b))
        assert parse_spare_value(ra.stdout) == 0, ra.stdout
        assert parse_spare_value(rb.stdout) == 0xFFFFFFFF, rb.stdout

    def test_last_page_of_block_spare(self):
        """Spare area of the last page of a block can be read correctly."""
        erase_region(SPARE_BLOCK * BLOCK_SIZE)
        last_page = SPARE_PAGE + PAGES_PER_BLOCK - 1  # page 127
        result = esptool(
            "read-nand-spare", "--spi-connection", SPI_CONN, str(last_page)
        )
        assert "NAND spare for page" in result.stdout, result.stdout
        assert "0xffffffff" in result.stdout.lower(), result.stdout


# ---------------------------------------------------------------------------
# Erase
# ---------------------------------------------------------------------------


class TestErase:
    """Block and region erase operations."""

    def test_erase_single_block_reads_ff(self):
        """After erasing one block, a full block read-back is all 0xFF."""
        write_nand(TEST_OFFSET, bytes([0xAA] * BLOCK_SIZE))
        erase_region(TEST_OFFSET)
        data = read_nand(TEST_OFFSET, BLOCK_SIZE)
        ff = bytes([0xFF] * BLOCK_SIZE)
        assert data == ff, (
            f"Not fully erased: first non-FF at byte {first_diff(data, ff)}"
        )

    def test_erase_two_blocks(self):
        """Erasing two blocks clears both completely."""
        size = 2 * BLOCK_SIZE
        write_nand(TEST_OFFSET, bytes([0x55] * size))
        erase_region(TEST_OFFSET, size)
        data = read_nand(TEST_OFFSET, size)
        assert data == bytes([0xFF] * size)

    def test_erase_does_not_affect_adjacent_block(self):
        """Erasing block N does not corrupt block N+1."""
        two = 2 * BLOCK_SIZE
        pattern = xorshift_bytes(two, seed=0xBEEFBEEF)
        write_nand(TEST_OFFSET, pattern)
        # Now erase only the first block
        erase_region(TEST_OFFSET, BLOCK_SIZE)
        # Second block should still have its data
        block1_data = read_nand(TEST_OFFSET + BLOCK_SIZE, BLOCK_SIZE)
        expected = pattern[BLOCK_SIZE:]
        diff_pos = first_diff(block1_data, expected)
        assert block1_data == expected, (
            f"Adjacent block corrupted: first diff at {diff_pos}"
        )


# ---------------------------------------------------------------------------
# Single-page read/write
# ---------------------------------------------------------------------------


class TestSinglePage:
    """Write and read back one page (2048 bytes)."""

    def setup_method(self):
        erase_region(TEST_OFFSET)

    def test_incrementing_pattern(self):
        """Write bytes 0x00–0xFF repeated, read back exactly."""
        data = bytes(i % 256 for i in range(PAGE_SIZE))
        write_nand(TEST_OFFSET, data)
        assert read_nand(TEST_OFFSET, PAGE_SIZE) == data

    def test_all_zeros(self):
        """Write all-zero page, read back zero."""
        data = bytes(PAGE_SIZE)
        write_nand(TEST_OFFSET, data)
        assert read_nand(TEST_OFFSET, PAGE_SIZE) == data

    def test_all_ones(self):
        """Write all-0xFF page (same as erased state), read back 0xFF."""
        data = bytes([0xFF] * PAGE_SIZE)
        write_nand(TEST_OFFSET, data)
        assert read_nand(TEST_OFFSET, PAGE_SIZE) == data

    def test_alternating_aa55(self):
        """Write 0xAA/0x55 alternating pattern, read back."""
        data = bytes([0xAA, 0x55] * (PAGE_SIZE // 2))
        write_nand(TEST_OFFSET, data)
        assert read_nand(TEST_OFFSET, PAGE_SIZE) == data

    def test_pseudo_random(self):
        """Write xorshift pseudo-random page, read back."""
        data = xorshift_bytes(PAGE_SIZE, seed=0x13579BDF)
        write_nand(TEST_OFFSET, data)
        readback = read_nand(TEST_OFFSET, PAGE_SIZE)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"

    def test_verify_flash_passes(self):
        """verify-flash succeeds (exit 0) for a single written page."""
        data = xorshift_bytes(PAGE_SIZE, seed=0xFEDCBA98)
        write_nand(TEST_OFFSET, data)
        verify_nand(TEST_OFFSET, data)  # raises CalledProcessError on failure


# ---------------------------------------------------------------------------
# Multi-page (within one block)
# ---------------------------------------------------------------------------


class TestMultiPage:
    """Write and read back multiple pages within a single block."""

    def setup_method(self):
        erase_region(TEST_OFFSET)

    def test_ten_pages(self):
        """Write 10 pages (20 480 bytes), read back."""
        size = 10 * PAGE_SIZE
        data = xorshift_bytes(size, seed=0x11223344)
        write_nand(TEST_OFFSET, data)
        readback = read_nand(TEST_OFFSET, size)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"

    def test_half_block(self):
        """Write half a block (32 pages = 65 536 bytes), read back."""
        size = BLOCK_SIZE // 2
        data = xorshift_bytes(size, seed=0xAABBCCDD)
        write_nand(TEST_OFFSET, data)
        readback = read_nand(TEST_OFFSET, size)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"

    def test_full_block(self):
        """Write a full 128 KB block, read back."""
        data = xorshift_bytes(BLOCK_SIZE, seed=0xDEADBEEF)
        write_nand(TEST_OFFSET, data)
        readback = read_nand(TEST_OFFSET, BLOCK_SIZE)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"

    def test_verify_full_block(self):
        """verify-flash over a full block succeeds."""
        data = xorshift_bytes(BLOCK_SIZE, seed=0xCAFEBABE)
        write_nand(TEST_OFFSET, data)
        verify_nand(TEST_OFFSET, data)

    def test_non_page_aligned_size(self):
        """Write a size that is not a multiple of PAGE_SIZE.

        Read back exactly that size.
        """
        size = PAGE_SIZE + 512  # 2560 bytes — one full page + partial
        data = xorshift_bytes(size, seed=0x76543210)
        write_nand(TEST_OFFSET, data)
        readback = read_nand(TEST_OFFSET, size)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"


# ---------------------------------------------------------------------------
# Multi-block read/write
# ---------------------------------------------------------------------------


class TestMultiBlock:
    """Write and read back data spanning multiple blocks."""

    REGION_SIZE = 8 * BLOCK_SIZE  # 1 MB — blocks 2–9

    def setup_method(self):
        erase_region(TEST_OFFSET, self.REGION_SIZE)

    def test_two_blocks(self):
        """Write 256 KB (2 blocks), read back."""
        size = 2 * BLOCK_SIZE
        data = xorshift_bytes(size, seed=0xABCD1234)
        write_nand(TEST_OFFSET, data)
        readback = read_nand(TEST_OFFSET, size)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"

    def test_four_blocks(self):
        """Write 512 KB (4 blocks), read back."""
        size = 4 * BLOCK_SIZE
        data = xorshift_bytes(size, seed=0xFEEDFACE)
        write_nand(TEST_OFFSET, data)
        readback = read_nand(TEST_OFFSET, size)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"

    def test_verify_two_blocks(self):
        """verify-flash over two blocks succeeds."""
        size = 2 * BLOCK_SIZE
        data = xorshift_bytes(size, seed=0x5678ABCD)
        write_nand(TEST_OFFSET, data)
        verify_nand(TEST_OFFSET, data)

    def test_block_boundary_data_integrity(self):
        """Data written across a block boundary reads back correctly on both sides.

        write-flash requires block-aligned offsets, so we write 2 full blocks
        and then read back just the 2 pages straddling the boundary to verify
        there is no corruption at the block transition.
        """
        size = 2 * BLOCK_SIZE
        data = xorshift_bytes(size, seed=0x12345678)
        write_nand(TEST_OFFSET, data)
        # Read the last page of block 2 and first page of block 3
        boundary_offset = TEST_OFFSET + BLOCK_SIZE - PAGE_SIZE
        boundary_size = 2 * PAGE_SIZE
        readback = read_nand(boundary_offset, boundary_size)
        expected = data[BLOCK_SIZE - PAGE_SIZE : BLOCK_SIZE + PAGE_SIZE]
        assert readback == expected, (
            f"Boundary mismatch at byte {first_diff(readback, expected)}"
        )

    def test_write_second_block_independent(self):
        """Writing to block 3 does not corrupt block 2 contents."""
        data_b2 = xorshift_bytes(BLOCK_SIZE, seed=0x11111111)
        data_b3 = xorshift_bytes(BLOCK_SIZE, seed=0x22222222)
        write_nand(TEST_OFFSET, data_b2)
        write_nand(TEST_OFFSET + BLOCK_SIZE, data_b3)
        readback_b2 = read_nand(TEST_OFFSET, BLOCK_SIZE)
        assert readback_b2 == data_b2, (
            f"Block 2 corrupted after writing block 3: "
            f"first diff at {first_diff(readback_b2, data_b2)}"
        )

    def test_eight_blocks_verify(self):
        """Write 1 MB (8 blocks), verify-flash succeeds."""
        data = xorshift_bytes(self.REGION_SIZE, seed=0x0FACADE0)
        write_nand(TEST_OFFSET, data)
        verify_nand(TEST_OFFSET, data)


# ---------------------------------------------------------------------------
# Data-pattern stress
# ---------------------------------------------------------------------------


class TestDataPatterns:
    """Stress tests with specific bit patterns that challenge NAND reliability."""

    def setup_method(self):
        erase_region(TEST_OFFSET)

    def test_checkerboard_pages(self):
        """Even pages 0xAA, odd pages 0x55; read back both correctly."""
        page0 = bytes([0xAA] * PAGE_SIZE)
        page1 = bytes([0x55] * PAGE_SIZE)
        write_nand(TEST_OFFSET, page0 + page1)
        readback = read_nand(TEST_OFFSET, 2 * PAGE_SIZE)
        assert readback[:PAGE_SIZE] == page0
        assert readback[PAGE_SIZE:] == page1

    def test_walking_ones(self):
        """Walking-ones pattern (bit 0→7 set in successive bytes)."""
        pattern = bytes(1 << (i % 8) for i in range(PAGE_SIZE))
        write_nand(TEST_OFFSET, pattern)
        assert read_nand(TEST_OFFSET, PAGE_SIZE) == pattern

    def test_walking_zeros(self):
        """Walking-zeros pattern (one bit clear in successive bytes)."""
        pattern = bytes(0xFF ^ (1 << (i % 8)) for i in range(PAGE_SIZE))
        write_nand(TEST_OFFSET, pattern)
        assert read_nand(TEST_OFFSET, PAGE_SIZE) == pattern

    def test_repeated_write_erase_cycles(self):
        """Write→erase→write→verify three times to the same block."""
        for cycle, seed in enumerate([0xAAAA1111, 0x55552222, 0xFFFF3333]):
            erase_region(TEST_OFFSET)
            data = xorshift_bytes(BLOCK_SIZE, seed=seed)
            write_nand(TEST_OFFSET, data)
            readback = read_nand(TEST_OFFSET, BLOCK_SIZE)
            assert readback == data, (
                f"Cycle {cycle}: mismatch at byte {first_diff(readback, data)}"
            )


# ---------------------------------------------------------------------------
# High-address block (end of device)
# ---------------------------------------------------------------------------


class TestHighAddress:
    """Access near the end of the 128 MB device."""

    # W25N01GV: 1024 blocks total; last reliable block = 1023
    LAST_SAFE_BLOCK = 1020  # leave a few blocks of margin
    LAST_OFFSET = LAST_SAFE_BLOCK * BLOCK_SIZE

    def test_write_read_near_end_of_device(self):
        """Write and read back a single page near the end of the device."""
        erase_region(self.LAST_OFFSET)
        data = xorshift_bytes(PAGE_SIZE, seed=0xDEADC0DE)
        write_nand(self.LAST_OFFSET, data)
        readback = read_nand(self.LAST_OFFSET, PAGE_SIZE)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"

    def test_spare_read_near_end_of_device(self):
        """Spare area of a page near end of device can be read."""
        erase_region(self.LAST_OFFSET)
        last_page = self.LAST_SAFE_BLOCK * PAGES_PER_BLOCK
        result = esptool(
            "read-nand-spare", "--spi-connection", SPI_CONN, str(last_page)
        )
        assert "0xffff" in result.stdout.lower(), result.stdout


# ---------------------------------------------------------------------------
# Full chip erase
# ---------------------------------------------------------------------------


class TestFullErase:
    """Full chip erase. Takes ~10 seconds."""

    def test_erase_flash_clears_chip(self):
        """erase-flash clears all blocks; spot-check blocks 2, 64, 512, 1020."""
        esptool(
            "erase-flash",
            "--flash-type",
            "nand",
            "--spi-connection",
            SPI_CONN,
        )
        for block in [2, 64, 512, 1020]:
            offset = block * BLOCK_SIZE
            data = read_nand(offset, PAGE_SIZE)
            assert data == bytes([0xFF] * PAGE_SIZE), (
                f"Block {block} not erased: byte 0 = {data[0]:#04x}"
            )

    def test_write_verify_after_full_erase(self):
        """After full chip erase, write+verify a block works correctly."""
        esptool(
            "erase-flash",
            "--flash-type",
            "nand",
            "--spi-connection",
            SPI_CONN,
        )
        data = xorshift_bytes(BLOCK_SIZE, seed=0xC001C0DE)
        write_nand(TEST_OFFSET, data)
        verify_nand(TEST_OFFSET, data)


# ---------------------------------------------------------------------------
# dump-bbm command
# ---------------------------------------------------------------------------


def write_nand_with_end(offset, data: bytes, end_addr: str) -> None:
    """Write NAND data with a --nand-end-address constraint."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(data)
        fname = f.name
    try:
        esptool(
            "write-flash",
            "--flash-type",
            "nand",
            "--spi-connection",
            SPI_CONN,
            "--nand-end-address",
            end_addr,
            hex(offset),
            fname,
        )
    finally:
        os.unlink(fname)


class TestDumpBBM:
    """Tests for the dump-bbm command."""

    def test_dump_bbm_creates_file(self, tmp_path):
        """dump-bbm creates a file of exactly NAND_BLOCK_COUNT bytes."""
        out = str(tmp_path / "bbm.bin")
        esptool("dump-bbm", "--spi-connection", SPI_CONN, out)
        data = open(out, "rb").read()
        assert len(data) == 1024  # W25N01GV has 1024 blocks

    def test_dump_bbm_values_are_0_or_1(self, tmp_path):
        """Every byte in the dump is 0x00 (good) or 0x01 (bad)."""
        out = str(tmp_path / "bbm.bin")
        esptool("dump-bbm", "--spi-connection", SPI_CONN, out)
        data = open(out, "rb").read()
        assert all(b in (0, 1) for b in data)

    def test_dump_bbm_erased_block_is_good(self, tmp_path):
        """A freshly-erased block reports as good (0x00) in the dump."""
        erase_region(SPARE_BLOCK * BLOCK_SIZE)  # ensure block 1 is good
        out = str(tmp_path / "bbm.bin")
        esptool("dump-bbm", "--spi-connection", SPI_CONN, out)
        data = open(out, "rb").read()
        assert data[SPARE_BLOCK] == 0x00  # block 1 should be good

    def test_dump_bbm_marked_bad_block_shows_bad(self, tmp_path):
        """A block marked bad via write-nand-spare shows as 0x01 in the dump."""
        erase_region(SPARE_BLOCK * BLOCK_SIZE)
        esptool("write-nand-spare", "--spi-connection", SPI_CONN, str(SPARE_PAGE), "1")
        out = str(tmp_path / "bbm.bin")
        esptool("dump-bbm", "--spi-connection", SPI_CONN, out)
        data = open(out, "rb").read()
        assert data[SPARE_BLOCK] == 0x01  # block 1 marked bad
        # Restore
        erase_region(SPARE_BLOCK * BLOCK_SIZE)


# ---------------------------------------------------------------------------
# Bad-block skip on write
# ---------------------------------------------------------------------------


class TestBadBlockSkipWrite:
    """write-flash skips pre-marked bad blocks."""

    def setup_method(self):
        # Erase two blocks at TEST_OFFSET and TEST_OFFSET+BLOCK_SIZE
        erase_region(TEST_OFFSET, 2 * BLOCK_SIZE)

    def teardown_method(self):
        erase_region(TEST_OFFSET, 2 * BLOCK_SIZE)

    def test_write_skips_bad_block_and_uses_next(self):
        """If the target block is bad, write uses the next physical block."""
        # Mark the first block (TEST_OFFSET) as bad
        first_page = TEST_OFFSET // BLOCK_SIZE * PAGES_PER_BLOCK
        esptool("write-nand-spare", "--spi-connection", SPI_CONN, str(first_page), "1")

        # Write one block of data — should land in TEST_OFFSET+BLOCK_SIZE
        data = xorshift_bytes(PAGE_SIZE, seed=0xBAADF00D)
        write_nand(TEST_OFFSET, data)

        # Read from the next physical block (where data actually landed)
        readback = read_nand(TEST_OFFSET + BLOCK_SIZE, PAGE_SIZE)
        assert readback == data, f"Mismatch at byte {first_diff(readback, data)}"

        # Restore: erase both blocks
        erase_region(TEST_OFFSET, 2 * BLOCK_SIZE)


# ---------------------------------------------------------------------------
# --nand-end-address
# ---------------------------------------------------------------------------


class TestNandEndAddress:
    """write-flash respects --nand-end-address."""

    def setup_method(self):
        erase_region(TEST_OFFSET, 2 * BLOCK_SIZE)

    def teardown_method(self):
        erase_region(TEST_OFFSET, 2 * BLOCK_SIZE)

    def test_end_address_too_small_fails(self):
        """write-flash fails when end address leaves no room for the image."""
        data = xorshift_bytes(BLOCK_SIZE, seed=0x12345678)
        # End address = TEST_OFFSET means zero blocks available → must fail
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(data)
            fname = f.name
        try:
            result = esptool(
                "write-flash",
                "--flash-type",
                "nand",
                "--spi-connection",
                SPI_CONN,
                "--nand-end-address",
                hex(TEST_OFFSET),
                hex(TEST_OFFSET),
                fname,
                check=False,
            )
            assert result.returncode != 0, "Expected failure but got success"
        finally:
            os.unlink(fname)

    def test_end_address_sufficient_succeeds(self):
        """write-flash succeeds when end address covers the required blocks."""
        data = xorshift_bytes(PAGE_SIZE, seed=0xDEADBEEF)
        end = TEST_OFFSET + 2 * BLOCK_SIZE  # 2 blocks available for 1 needed
        write_nand_with_end(TEST_OFFSET, data, hex(end))
        readback = read_nand(TEST_OFFSET, PAGE_SIZE)
        assert readback == data


# ---------------------------------------------------------------------------
# Experimental warning
# ---------------------------------------------------------------------------


class TestExperimentalWarning:
    """Every NAND command prints the experimental warning."""

    def test_write_flash_warns_experimental(self):
        result = esptool(
            "write-flash",
            "--flash-type",
            "nand",
            "--spi-connection",
            SPI_CONN,
            hex(TEST_OFFSET),
            "/dev/null",
            check=False,
        )
        assert "experimental" in (result.stdout + result.stderr).lower()
