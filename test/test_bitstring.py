# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""Host tests for espefuse.efuse.bitstring, the subset of bitstring 4.3.1 used by
espefuse. The expected values were produced by upstream bitstring 4.3.1.
"""

import io
import os
import subprocess
import sys
import textwrap

import pytest

from espefuse.efuse.bitstring import (
    BitArray,
    Bits,
    BitStream,
    CreationError,
    InterpretError,
    ReadError,
)

pytestmark = pytest.mark.host_test

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_classes_and_exceptions():
    assert issubclass(BitStream, BitArray)
    assert issubclass(BitArray, Bits)
    # espefuse catches token parse errors with "except CreationError"
    assert CreationError is ValueError
    assert InterpretError is ValueError
    assert issubclass(ReadError, IndexError)
    # Annotations such as "BitStream | Bits" are evaluated when espefuse loads
    assert BitStream | Bits is not None


@pytest.mark.parametrize(
    "token, expected",
    [
        ("uint:8=5", "BitArray('0x05')"),
        ("uint8=5", "BitArray('0x05')"),
        (" uint : 8 = 5 ", "BitArray('0x05')"),
        ("uint:8=1 0", "BitArray('0x0a')"),
        ("uint:8=+5", "BitArray('0x05')"),
        ("uint:8=-0", "BitArray('0x00')"),
        ("uint:5=31", "BitArray('0b11111')"),
        ("uint:32=4294967295", "BitArray('0xffffffff')"),
        ("uint:33=5", "BitArray('0x00000002, 0b1')"),
        ("bool=1", "BitArray('0b1')"),
        ("bool=True", "BitArray('0b1')"),
        ("bool=0", "BitArray('0b0')"),
        ("bool=False", "BitArray('0b0')"),
        ("bool:1=1", "BitArray('0b1')"),
        ("uint:8=5, uint:8=6", "BitArray('0x0506')"),
        ("2*uint:4=3", "BitArray('0x33')"),
        ("0x0f,uint:4=1,bool=1", "BitArray('0b0000111100011')"),
        ("0x00", "BitArray('0x00')"),
        ("0X0A", "BitArray('0x0a')"),
        ("0x_1_2", "BitArray('0x12')"),
        ("0b101", "BitArray('0b101')"),
        ("", "BitArray('')"),
    ],
)
def test_token_creation(token, expected):
    assert repr(BitArray(token)) == expected


@pytest.mark.parametrize(
    "token, message",
    [
        (
            "uint:6=200",
            "200 is too large an unsigned integer for a bitstring of length 6. "
            "The allowed range is [0, 63].",
        ),
        (
            "uint:32=4294967296",
            "4294967296 is too large an unsigned integer for a bitstring of length "
            "32. The allowed range is [0, 4294967295].",
        ),
        ("uint:8=-1", "uint cannot be initialised with a negative number."),
        ("uint:8=abc", "invalid literal for int() with base 10: 'abc'"),
        ("uint:8=0x1f", "invalid literal for int() with base 10: '0x1f'"),
        ("uint:8=True", "invalid literal for int() with base 10: 'True'"),
        ("uint=5", "A non-zero length must be specified with a uint initialiser."),
        ("uint:8", "Token uint requires a value."),
        ("uint:4=1,2", "Token bits requires a value."),
        ("uint:8:=5", "Don't understand length 'uint:8:' of token."),
        ("bool=2", "Cannot initialise boolean with 2."),
        ("bool=true", "Cannot initialise boolean with true."),
        ("bool", "Token bool requires a value."),
        (
            "bool:2=1",
            "Can't parse token: A length of 2 was supplied for the 'bool' dtype, "
            "but its only allowed length is 1.",
        ),
        ("0xg", "Invalid symbol in hex initialiser."),
        # Every token is parsed before any is built
        ("uint:6=64,0x", "Don't understand length '0x' of token."),
        ("bool=2,uint:x=1", "Don't understand length 'x' of token."),
    ],
)
def test_token_errors(token, message):
    with pytest.raises(CreationError) as e:
        BitArray(token)
    assert str(e.value) == message


def test_unknown_dtype_name_raises():
    with pytest.raises(CreationError):
        BitArray("foo:8=1")
    with pytest.raises(ValueError):
        BitStream("0x00").read("foo:8")


def test_construction():
    assert repr(BitStream(5)) == "BitStream('0b00000')"
    assert repr(BitStream(length=12)) == "BitStream('0x000')"
    assert repr(BitArray()) == "BitArray('')"
    assert repr(Bits(3)) == "Bits('0b000')"
    with pytest.raises(CreationError):
        BitStream(-1)

    # Data beyond length is dropped; too little data raises
    assert repr(BitStream(bytes=b"\x12\x34", length=12)) == "BitStream('0x123')"
    assert repr(BitArray(bytes=b"\x12\x34\x56", length=8)) == "BitArray('0x12')"
    with pytest.raises(CreationError) as e:
        BitStream(bytes=b"\x12\x34", length=24)
    assert str(e.value) == "Not enough data present. Need 24 bits, have 16."
    with pytest.raises(CreationError):
        BitStream(bytes=b"", length=8)

    # Copy construction gives an independent object of the new class at pos 0
    src = BitStream("0xf0f0")
    src.pos = 5
    copy = BitStream(src)
    copy.set(0)
    assert repr(copy) == "BitStream('0x0000')"
    assert repr(src) == "BitStream('0xf0f0', pos=5)"
    assert repr(Bits(src)) == "Bits('0xf0f0')"


def test_file_object(tmp_path):
    path = tmp_path / "blk.bin"
    path.write_bytes(bytes(range(1, 9)))
    with open(path, "rb") as f:
        f.read(3)  # The whole file is used whatever the handle position
        data = BitStream("0x00") * 2 + BitStream(f)
    assert data.readlist(f"{data.len // 8}*uint:8") == [0, 0, 1, 2, 3, 4, 5, 6, 7, 8]


@pytest.mark.parametrize(
    "length, expected",
    [
        (0, ""),
        (1, "0b1"),
        (3, "0b101"),
        (4, "0x9"),
        (8, "0x81"),
        (31, "0b1000000000000000000000000000001"),
        (32, "0x80000001"),
        (33, "0x80000000, 0b1"),
        (35, "0x80000000, 0b001"),
        (36, "0x800000001"),
        (65, "0x8000000000000000, 0b1"),
        (1000, "0x8" + "0" * 248 + "1"),
        (1001, "0x8" + "0" * 249 + "..."),
    ],
)
def test_str(length, expected):
    bits = BitArray(length)
    bits.set(1, {0, length - 1} if length else ())
    assert str(bits) == expected


def test_repr():
    stream = BitStream(16)
    assert repr(stream) == "BitStream('0x0000')"
    stream.pos = 4
    assert repr(stream) == "BitStream('0x0000', pos=4)"
    assert repr(BitArray("0b101")) == "BitArray('0b101')"
    long_stream = BitStream(1004)
    long_stream.pos = 8
    assert repr(long_stream) == (
        "BitStream('0x" + "0" * 250 + "...', pos=8)  # length=1004"
    )
    assert repr({"WR_DIS": BitStream(16)}) == "{'WR_DIS': BitStream('0x0000')}"


def test_properties():
    bits = BitStream("0x0102")
    assert (bits.len, bits.length, len(bits)) == (16, 16, 16)
    assert bits.bytes == b"\x01\x02"
    assert bits.hex == "0102"
    assert bits.uint == 258
    assert BitStream("0xABCDEF").hex == "abcdef"
    assert bytes(BitStream("0b1")) == b"\x80"
    assert (BitStream().bytes, BitStream().hex) == (b"", "")
    for prop in ("bytes", "hex"):
        with pytest.raises(InterpretError):
            getattr(BitStream("0b1"), prop)
    with pytest.raises(InterpretError):
        BitStream().uint


def test_pos():
    stream = BitStream(16)
    stream.pos = 16
    for bad in (-1, 17):
        with pytest.raises(ValueError):
            stream.pos = bad
    assert stream.pos == 16


def test_read():
    stream = BitStream("0xa5c3ff00")
    value = stream.read("bool")
    assert (type(value), value, stream.pos) == (bool, True, 1)
    value = stream.read(" uint : 7 ")
    assert (type(value), value, stream.pos) == (int, 37, 8)
    value = stream.read("bytes:2")
    assert (type(value), value, stream.pos) == (bytes, b"\xc3\xff", 24)
    chunk = stream.read(4)
    assert (repr(chunk), stream.pos) == ("BitStream('0x0')", 28)
    chunk.set(1)
    assert repr(stream) == "BitStream('0xa5c3ff00', pos=28)"

    with pytest.raises(ReadError) as e:
        stream.read("uint:8")
    assert str(e.value) == (
        "Needed a length of at least 8 bits, but only 4 bits were available."
    )
    with pytest.raises(ReadError):
        stream.read(8)
    with pytest.raises(ValueError):
        stream.read(-1)
    assert stream.pos == 28


def test_readlist():
    stream = BitStream("0x0102030405060708")
    values = stream.readlist("2*uint:32")
    assert (values, stream.pos) == ([16909060, 84281096], 64)
    stream.pos = 0
    assert stream.readlist(" 8 * uint : 8 ") == [1, 2, 3, 4, 5, 6, 7, 8]
    stream.pos = 0
    assert stream.readlist("uint:8, bool, bytes:1") == [1, False, b"\x04"]
    assert stream.pos == 17

    stream.pos = 0
    with pytest.raises(ReadError):
        stream.readlist("3*uint:32")
    assert stream.pos == 0


@pytest.mark.parametrize(
    "start, data, pos, expected",
    [
        (0, "0xffff", 56, "BitStream('0x00000000000000ffff', pos=72)"),
        (0, "0xffff", -16, "BitStream('0x000000000000ffff', pos=64)"),
        (0, "0xffff", -8, "BitStream('0x00000000000000ffff', pos=72)"),
        (0, "0xffff", 0, "BitStream('0xffff000000000000', pos=16)"),
        (36, "0b11", None, "BitStream('0x000000000c000000', pos=38)"),
        (48, "uint:32=5", None, "BitStream('0x00000000000000000005', pos=80)"),
        (5, "", 99, "BitStream('0x0000000000000000', pos=5)"),
    ],
)
def test_overwrite(start, data, pos, expected):
    stream = BitStream(64)
    stream.pos = start
    stream.overwrite(data, pos=pos)
    assert repr(stream) == expected


def test_overwrite_errors_and_stream_pos():
    for pos in (65, -65):
        with pytest.raises(ValueError):
            BitStream(64).overwrite("0xffff", pos=pos)

    # Consecutive writes without pos continue where the last one stopped
    stream = BitStream(64)
    stream.pos = 0
    for word in (0x55555555, 0xAAAAAAAA):
        stream.overwrite(BitArray(f"uint:32={word}"))
    assert repr(stream) == "BitStream('0x55555555aaaaaaaa', pos=64)"
    assert stream.count(True) == 32


def test_set():
    stream = BitStream(8)
    stream.pos = 3
    same = stream
    stream.set(1)
    assert repr(stream) == "BitStream('0xff', pos=3)"
    stream.set(0)
    assert stream is same and repr(stream) == "BitStream('0x00', pos=3)"

    for positions, expected in [
        ((0, 7), "0x81"),
        ([-1], "0x01"),
        (3, "0x10"),
        ([], "0x00"),
    ]:
        bits = BitArray(8)
        bits.set(True, positions)
        assert str(bits) == expected

    # Positions before the bad one stay set
    bits = BitArray(8)
    with pytest.raises(IndexError):
        bits.set(True, (1, 9, 2))
    assert str(bits) == "0x40"


@pytest.mark.parametrize(
    "token, expected",
    [
        ("0x00", (True, False, 0, False, True)),
        ("0xff", (False, True, 8, True, False)),
        ("0x10", (False, True, 1, False, True)),
        ("", (True, False, 0, True, False)),
    ],
)
def test_all_any_count(token, expected):
    bits = BitStream(token)
    bits.pos = len(bits)  # These look at the whole bitstring, not from pos
    actual = (
        bits.all(False),
        bits.any(True),
        bits.count(True),
        bits.all(True),
        bits.any(False),
    )
    assert actual == expected


def test_index_and_slice():
    bits = BitStream("0b10000001")
    bits.pos = 5
    assert (bits[0], bits[-1], bits[1]) == (True, True, False)
    with pytest.raises(IndexError):
        bits[8]
    assert repr(bits[1:]) == "BitStream('0b0000001')"
    assert repr(bits[2:100]) == "BitStream('0b000001')"
    assert repr(bits[-3:]) == "BitStream('0b001')"
    assert repr(bits[5:2]) == "BitStream('')"
    assert repr(bits[::2]) == "BitStream('0x8')"
    assert repr(bits[1:7:3]) == "BitStream('0b00')"
    assert repr(BitArray("0xf0")[0:4]) == "BitArray('0xf')"

    # A slice is a copy: changing it leaves the source alone
    assert bits[:] is not bits
    bits[0:4:].set(1)
    assert repr(bits) == "BitStream('0x81', pos=5)"


def test_and_or():
    a = BitStream("0x0f")
    a.pos = 4
    b = BitStream("0x3c")
    b.pos = 2
    assert repr(a & b) == "BitStream('0x0c')"
    assert repr(a | b) == "BitStream('0x3f')"
    assert (repr(a), repr(b)) == (
        "BitStream('0x0f', pos=4)",
        "BitStream('0x3c', pos=2)",
    )
    assert repr(BitArray("0x0f") & Bits("0x3c")) == "BitArray('0x0c')"

    same = a
    a |= BitArray("0xf0")
    assert a is same and repr(a) == "BitStream('0xff', pos=4)"

    with pytest.raises(ValueError):
        BitStream(8) & BitStream(16)
    with pytest.raises(ValueError):
        BitStream(8) | BitStream(16)
    with pytest.raises(ValueError):
        a |= BitStream(16)


def test_equality():
    assert BitStream(8) == BitArray(8)
    assert BitStream(8) == Bits(8)
    assert BitStream(8) != BitStream(9)
    assert BitStream(8) == "0x00"
    # Comparing with an int is never equal, whatever the length and value
    for bits in (BitStream(8), BitStream(), BitStream("0b1")):
        assert bits != 0
        assert not bits == 0
    assert BitStream("0b1") != 1
    assert BitStream("0b1") != True  # noqa: E712
    assert BitStream(8) != None  # noqa: E711

    # Upstream compares these by content and searches with "in". Unsupported here,
    # so they raise instead of returning a different answer.
    for other in (b"\x00", [0] * 8):
        with pytest.raises(TypeError):
            BitStream(8) == other
    with pytest.raises(TypeError):
        "0b1" in BitStream("0x80")


def test_add_mul():
    assert repr(Bits(3) + BitStream(5)) == "BitStream('0x00')"
    assert repr(Bits(3) + BitStream(1)) == "Bits('0x0')"
    assert repr(Bits(1) + BitStream("0b101")) == "BitStream('0x5')"
    assert repr(BitStream("0x1") + Bits("0x22")) == "BitStream('0x122')"
    assert repr(BitStream("0x00") * 0) == "BitStream('')"
    assert repr(BitStream("0x01") * 3) == "BitStream('0x010101')"
    with pytest.raises(ValueError):
        BitStream("0x00") * -1


def test_mutating_methods():
    stream = BitStream("0x112233445566")
    stream.insert(BitStream("0xfffe"), 24)
    assert repr(stream) == "BitStream('0x112233fffe445566', pos=40)"
    with pytest.raises(ValueError):
        stream.insert("0b1", 65)

    stream.pos = 10
    del stream[0:0]
    assert stream.pos == 10
    del stream[0:16]
    assert repr(stream) == "BitStream('0x33fffe445566')"
    with pytest.raises(TypeError):
        del stream[::2]

    bits = BitArray()
    bits.append("uint:32=1")
    bits.append("uint:32=4294967295")
    assert repr(bits) == "BitArray('0x00000001ffffffff')"
    stream.append("0x7")
    assert stream.pos == len(stream) == 52

    # pos ends after the inserted copy of the original
    stream = BitStream("0b1111111")
    stream.insert(stream, 0)
    assert repr(stream) == "BitStream('0b11111111111111', pos=7)"

    stream = BitStream("0x0102030405060708")
    stream.pos = 32
    assert stream.byteswap() == 1
    assert repr(stream) == "BitStream('0x0807060504030201', pos=32)"
    stream = BitStream("0x01020")
    stream.byteswap()
    assert str(stream) == "0x02010"
    assert BitStream().byteswap() == 0

    stream = BitStream("0b1100000")
    stream.pos = 3
    stream.reverse()
    assert repr(stream) == "BitStream('0b0000011', pos=3)"
    stream.invert()
    assert repr(stream) == "BitStream('0b1111100', pos=3)"


def test_copy():
    stream = BitStream("0xab")
    stream.pos = 4
    copy = stream.copy()
    copy.set(0)
    assert (type(copy), copy.pos, repr(stream)) == (
        BitStream,
        0,
        "BitStream('0xab', pos=4)",
    )
    assert type(BitArray("0xab").copy()) is BitArray


def test_tofile():
    for token, expected in [("0x0102", b"\x01\x02"), ("0b1", b"\x80"), ("", b"")]:
        stream = BitStream(token)
        stream.pos = len(stream)
        f = io.BytesIO()
        stream.tofile(f)
        assert f.getvalue() == expected
        assert stream.pos == len(stream)


def test_upstream_bitstring_never_imported():
    # Old virtual environments still have the upstream package installed. Block it
    # and check that every espefuse module and a virtual burn work without it. The
    # finder also records lookups that an "except ImportError" fallback would hide.
    script = textwrap.dedent(
        """
        import importlib, pkgutil, sys

        class BlockUpstream:
            lookups = []

            @classmethod
            def find_spec(cls, name, path=None, target=None):
                if name == "bitstring" or name.startswith("bitstring."):
                    cls.lookups.append(name)
                    raise ImportError(f"upstream {name} is blocked")
                return None

        assert "bitstring" not in sys.modules
        sys.meta_path.insert(0, BlockUpstream)
        import espefuse
        for module in pkgutil.walk_packages(espefuse.__path__, "espefuse."):
            importlib.import_module(module.name)
        espefuse.main(["--chip", "esp32c3", "--virt", "--debug",
                       "--do-not-confirm", "burn-efuse", "WDT_DELAY_SEL", "1"])
        assert not BlockUpstream.lookups, BlockUpstream.lookups
        assert "bitstring" not in sys.modules
        print("upstream bitstring not imported")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Successful." in result.stdout
    assert "upstream bitstring not imported" in result.stdout
